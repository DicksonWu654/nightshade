import { createHash } from "node:crypto";
import type { AbstractValue } from "./index.js";
import { refineScalar, type ScalarConstraints } from "./transfers.js";

type Recipe =
  | { kind: "aggregate"; fields: boolean; children: readonly (readonly [string, string])[] }
  | { kind: "hash"; domain: readonly unknown[]; prefix: string; input: string }
  | { kind: "byte"; input: string; index: number }
  | { kind: "cast"; input: string; operation: string }
  | { kind: "expression"; operator: string; numericType?: string; inputs: string[]; commutative: boolean }
  | { kind: "choice"; selector: string; yes: string; no: string };
const digest = (value: unknown): string => createHash("sha256").update(JSON.stringify(value)).digest("hex");
interface Normalization {
  generation: number;
  selected: ReadonlyMap<string, boolean>;
  values: Map<string, string>;
}

/** Immutable identities for total hash choices, not alternative effect histories.
 * Only substitute Boolean facts already proved by the ordinary transfer domain.
 * Keys are content-addressed; no recursive recipe is serialized into a value.
 */
export class HashRecipes {
  private readonly nodes = new Map<string, Recipe>();
  private readonly normalized = new WeakMap<ScalarConstraints, Normalization>();
  private readonly selectors = new Set<string>();
  // Normalization depends only on Boolean selector facts, not on unrelated
  // current storage, guards, provenance or scalar constraints. Share these
  // immutable substitutions across states with exactly the same selector facts.
  private readonly contexts = new Map<string, Map<string, string>>();
  private readonly dependencyIds = new Map<string, number>();
  private readonly dependencyMasks = new Map<string, bigint>();
  private readonly contained = new WeakMap<AbstractValue, boolean>();
  private refused = false;
  constructor(private readonly allowance: (work: number, nodes: number) => boolean, private readonly depthExceeded: () => void,
    private readonly shareContexts = true) {}

  /** A caller composing domain queries must not publish a complete result after
   * an indirect refinement refused work or exceeded the normalization depth. */
  get exhausted(): boolean { return this.refused; }
  private charge(work: number, nodes: number): boolean {
    if (!this.allowance(work, nodes)) this.refused = true;
    return !this.refused;
  }

  private key(node: Recipe): string {
    if (node.kind === "choice") return node.yes === node.no ? node.yes : `id:hash-choice:${digest([node.selector, node.yes, node.no])}`;
    if (node.kind === "hash") return `id:${node.prefix}:${digest([...node.domain, node.input])}`;
    if (node.kind === "byte") return `${node.input}::byte:${node.index}`;
    if (node.kind === "cast") return `id:native:${digest([node.operation, [["value", node.input.slice(3)]]])}`;
    if (node.kind === "expression") return `expression:${digest([node.operator, node.numericType, node.commutative ? node.inputs.slice().sort() : node.inputs])}`;
    const hash = createHash("sha256").update(node.fields ? "fields" : "items");
    for (const child of node.children) hash.update(JSON.stringify(child));
    return `aggregate:${hash.digest("hex")}`;
  }

  private intern(node: Recipe): string | undefined {
    if (!this.charge(1, 0)) return;
    const key = this.key(node);
    // Only choices and containers that depend on them need retained recipes.
    const needed = node.kind === "choice" ? node.yes !== node.no : node.kind === "hash" || node.kind === "byte" || node.kind === "cast"
      ? this.nodes.has(node.input) : node.kind === "expression" ? node.inputs.some(input => this.nodes.has(input))
        : node.children.some(([, child]) => this.nodes.has(child));
    if (needed && !this.nodes.has(key)) {
      if (!this.charge(0, 1)) return;
      let dependencies = this.dependencyLeaf(key);
      const inputs = node.kind === "choice" ? [node.yes, node.no, `id:${node.selector}`]
        : node.kind === "hash" || node.kind === "byte" || node.kind === "cast" ? [node.input]
          : node.kind === "expression" ? node.inputs : node.children.map(([, child]) => child);
      for (const input of inputs) {
        const mask = this.dependencyMasks.get(input) ?? this.dependencyLeaf(input);
        if (!this.charge(Math.max(1, Math.ceil(this.dependencyIds.size / 64)), 0)) return;
        dependencies |= mask;
      }
      if (!this.charge(0, Math.max(1, Math.ceil(this.dependencyIds.size / 64)))) return;
      this.nodes.set(key, node);
      this.dependencyMasks.set(key, dependencies);
      if (node.kind === "choice") this.selectors.add(node.selector);
    }
    return key;
  }

  private dependencyLeaf(key: string): bigint {
    if (!key.startsWith("id:")) return 0n;
    const identity = key.slice(3);
    let id = this.dependencyIds.get(identity);
    if (id === undefined) {
      if (!this.charge(1, 1)) return 0n;
      id = this.dependencyIds.size;
      this.dependencyIds.set(identity, id);
    }
    return 1n << BigInt(id);
  }

  /** Exact liveness intersection over the immutable recipe DAG. Dense bitsets
   * share ancestor membership; callers query only retained constraint keys,
   * instead of expanding the same hash tree at every CFG join. Work and retained
   * 64-bit words use the ordinary allowance. No constraint or history is joined. */
  retainDependencies(roots: Iterable<string>, candidates: Iterable<string>, visit: (identity: string) => void): void {
    if (!this.nodes.size) return;
    let live = 0n;
    const words = Math.max(1, Math.ceil(this.dependencyIds.size / 64));
    for (const identity of roots) {
      const mask = this.dependencyMasks.get(`id:${identity}`);
      if (mask === undefined) continue;
      if (!this.charge(words, 0)) return;
      live |= mask;
    }
    if (live === 0n) return;
    for (const identity of candidates) {
      if (!this.charge(1, 0)) return;
      const index = this.dependencyIds.get(identity);
      if (index !== undefined && (live & (1n << BigInt(index))) !== 0n) visit(identity);
    }
  }

  has(identity: string | undefined): boolean { return identity !== undefined && this.nodes.has(`id:${identity}`); }

  contains(value: AbstractValue): boolean {
    if (!this.nodes.size) return false;
    const cached = this.contained.get(value);
    if (cached !== undefined) return cached;
    if (!this.charge(1, 0)) return true;
    const result = this.has(value.identity) || !!value.items?.some(part => this.contains(part))
      || !!value.fields && Object.values(value.fields).some(part => this.contains(part))
      || !!value.comparison && [value.comparison.left, value.comparison.right].some(part => this.contains(part))
      || !!value.ordering && [value.ordering.left, value.ordering.right, ...value.ordering.leftBytes ?? []].some(part => this.contains(part))
      || !!value.byteEncoding && this.contains(value.byteEncoding.scalar)
      || !!value.negated && this.contains(value.negated);
    this.contained.set(value, result); return result;
  }

  relationKey(left: AbstractValue, right: AbstractValue, equals: boolean): string | undefined {
    const memo = new Map<AbstractValue, string | undefined>();
    const first = this.operand(left, memo), second = this.operand(right, memo);
    return first && second ? `hash-relation:${equals}:${digest([first, second].sort())}` : undefined;
  }

  invalidate(state: ScalarConstraints, identity?: string): void {
    if (identity !== undefined) {
      if (!this.selectors.has(identity)) return;
      const previous = this.normalized.get(state);
      if (previous?.generation === this.selectors.size && previous.selected.get(identity) === this.selectorTruth(state, identity)) return;
    }
    this.normalized.delete(state);
  }
  fork(from: ScalarConstraints, to: ScalarConstraints): void {
    if (!this.nodes.size) return;
    const memo = this.normalization(from);
    if (!this.refused) this.normalized.set(to, memo);
  }

  private selectorTruth(state: ScalarConstraints, selector: string): boolean | undefined {
    const constant = state.known.get(selector);
    return constant?.kind === "boolean" ? constant.value === "true" : state.truths.get(selector);
  }

  private normalization(state: ScalarConstraints): Normalization {
    const previous = this.normalized.get(state);
    if (previous?.generation === this.selectors.size) return previous;
    const selected: [string, boolean][] = [];
    for (const selector of this.selectors) {
      if (!this.charge(1, 0)) break;
      const truth = this.selectorTruth(state, selector);
      if (truth !== undefined) selected.push([selector, truth]);
    }
    // Unknown selectors need no entry: adding an unresolved choice cannot
    // change a previous substitution. Known facts use the selector identity.
    const key = JSON.stringify(selected);
    let values = this.shareContexts ? this.contexts.get(key) : undefined;
    if (!values) {
      values = new Map();
      if (this.shareContexts && this.charge(0, 1)) {
        // Eviction only costs recomputation; it never discards analysis facts.
        if (this.contexts.size >= 64) this.contexts.delete(this.contexts.keys().next().value!);
        this.contexts.set(key, values);
      }
    }
    const result = { generation: this.selectors.size, selected: new Map(selected), values };
    if (!this.refused && this.charge(0, 1 + selected.length)) this.normalized.set(state, result);
    return result;
  }

  /** Matches immutableOperandKey's scalar/aggregate encoding. Unknown operands
   * decline admission; they are never conflated by may-dependency membership. */
  private operand(value: AbstractValue, memo: Map<AbstractValue, string | undefined>, depth = 0): string | undefined {
    if (!this.charge(1, 0)) return;
    if (depth > 32) return;
    if (memo.has(value)) return memo.get(value);
    let key: string | undefined;
    if (value.negated || value.comparison || value.ordering) {
      const inputs = value.negated ? [value.negated] : value.comparison
        ? [value.comparison.left, value.comparison.right] : [value.ordering!.left, value.ordering!.right];
      const keys = inputs.map(input => this.operand(input, memo, depth + 1));
      if (keys.some(key => key === undefined)) return;
      key = this.intern({ kind: "expression", operator: value.negated ? "!" : value.comparison?.operator ?? value.ordering!.operator,
        numericType: value.ordering?.numericType, inputs: keys as string[], commutative: !!value.comparison });
    } else if (value.identity) { if (value.identity.length > 65536) return; key = `id:${value.identity}`; }
    else if (value.constantKind && value.constant !== undefined) { if (value.constant.length > 65536) return; key = `constant:${value.constantKind}:${value.constant}`; }
    else {
      const children = value.fields ? Object.entries(value.fields).sort(([a], [b]) => a.localeCompare(b))
        : value.items?.map((part, index) => [String(index), part] as const);
      if (!children) return;
      const keys: [string, string][] = [];
      for (const [name, child] of children) {
        const key = this.operand(child, memo, depth + 1);
        if (!key) return;
        keys.push([name, key]);
      }
      key = this.intern({ kind: "aggregate", fields: !!value.fields, children: keys });
    }
    memo.set(value, key); return key;
  }

  hash(values: AbstractValue[], domain: readonly unknown[], prefix: string): string | undefined {
    const input = this.operand({ flows: [], ledger: new Set(), items: values }, new Map());
    const key = input && this.intern({ kind: "hash", domain, prefix, input });
    return key?.slice(3);
  }

  choose(selector: string, yes: string, no: string): string | undefined {
    return this.intern({ kind: "choice", selector, yes: `id:${yes}`, no: `id:${no}` })?.slice(3);
  }

  byte(identity: string, index: number): string | undefined {
    return this.intern({ kind: "byte", input: `id:${identity}`, index })?.slice(3);
  }

  cast(identity: string, operation: string): string | undefined {
    return this.intern({ kind: "cast", input: `id:${identity}`, operation })?.slice(3);
  }

  /** Clones can share normalization while their scalar constraints agree. Every
   * assumption/forget invalidates the changed state's cache before further use. */
  private resolver(state: ScalarConstraints): (key: string) => string {
    const context = this.normalization(state), memo = context.values;
    const resolve = (key: string, depth = 0): string => {
      if (!this.charge(1, 0)) return key;
      const cached = memo.get(key);
      if (cached !== undefined) return cached;
      if (depth > 256) { this.refused = true; this.depthExceeded(); return key; }
      const node = this.nodes.get(key);
      if (!node) return key;
      let result: string | undefined;
      if (node.kind === "choice") {
        const truth = context.selected.get(node.selector);
        result = truth !== undefined ? resolve(truth ? node.yes : node.no, depth + 1)
          : this.intern({ ...node, yes: resolve(node.yes, depth + 1), no: resolve(node.no, depth + 1) });
      } else if (node.kind === "hash" || node.kind === "byte" || node.kind === "cast") result = this.intern({ ...node, input: resolve(node.input, depth + 1) });
      else if (node.kind === "expression") result = this.intern({ ...node, inputs: node.inputs.map(input => resolve(input, depth + 1)) });
      else result = this.intern({ ...node, children: node.children.map(([name, child]) => [name, resolve(child, depth + 1)] as const) });
      if (!this.refused && this.charge(0, 1)) memo.set(key, result ?? key);
      return result ?? key;
    };
    return resolve;
  }

  refine(value: AbstractValue, state: ScalarConstraints): AbstractValue {
    if (!this.contains(value)) return value;
    const identity = this.has(value.identity) ? this.resolver(state)(`id:${value.identity}`).slice(3) : value.identity;
    if (value.items) return { ...value, identity, items: value.items.map(part => refineScalar(part, state)) };
    if (value.fields) return { ...value, identity, fields: Object.fromEntries(Object.entries(value.fields).map(([name, part]) => [name, refineScalar(part, state)])) };
    return identity === value.identity ? value : { ...value, identity };
  }

  /** The domain substitutes known selectors; it does not solve disjunctions of
   * hash alternatives. A surviving restrictive check must resolve its selectors
   * before the entry can be called complete. Equality with an opaque input or
   * unchanged ledger digest imposes no decidable selector restriction in the
   * ordinary hash abstraction and remains supported.
   */
  pendingConstraints(state: ScalarConstraints): boolean {
    if (!this.nodes.size) return false;
    const resolve = this.resolver(state), seen = new Map<AbstractValue, boolean>();
    const unresolved = (value: AbstractValue): boolean => {
      if (seen.has(value)) return seen.get(value)!;
      if (!this.charge(1, 0)) return true;
      const result = !!value.identity && this.has(resolve(`id:${value.identity}`).slice(3))
        || !!value.items?.some(unresolved) || !!value.fields && Object.values(value.fields).some(unresolved)
        || !!value.comparison && [value.comparison.left, value.comparison.right].some(unresolved)
        || !!value.ordering && [value.ordering.left, value.ordering.right, ...value.ordering.leftBytes ?? []].some(unresolved)
        || !!value.negated && unresolved(value.negated);
      seen.set(value, result); return result;
    };
    const opaque = (value: AbstractValue): boolean => value.constant === undefined && !value.items && !value.fields
      && !value.comparison && !value.ordering && !value.negated && !!value.identity && !unresolved(value)
      && (Boolean(value.preexistingLedger?.size) || value.flows.some(flow => flow.form === "raw" && flow.source.id === value.identity));
    for (const { left, right } of state.scalarEqualities?.values() ?? []) {
      const first = unresolved(left), second = unresolved(right);
      if ((first || second) && !(first && opaque(refineScalar(right, state)) || second && opaque(refineScalar(left, state)))) return true;
    }
    for (const { predicate } of state.orderings?.values() ?? [])
      if ([predicate.left, predicate.right, ...predicate.leftBytes ?? []].some(unresolved)) return true;
    return false;
  }

  /** Earlier constant/exclusion constraints remain attached to the same value
   * after selecting an arm. Retain original aliases for future refinements. */
  consistent(state: ScalarConstraints): boolean {
    if (!this.nodes.size) return true;
    for (const [identity, value] of [...state.known]) {
      if (!this.has(identity)) continue;
      const selected = this.resolver(state)(`id:${identity}`).slice(3), previous = state.known.get(selected);
      if (previous && (previous.kind !== value.kind || previous.value !== value.value)) return false;
      if (state.excluded.get(selected)?.has(`${value.kind}:${value.value}`)) return false;
      state.known.set(selected, value);
      this.invalidate(state, selected);
    }
    for (const [identity, excluded] of [...state.excluded]) {
      if (!this.has(identity)) continue;
      const selected = this.resolver(state)(`id:${identity}`).slice(3), constant = state.known.get(selected);
      if (constant && excluded.has(`${constant.kind}:${constant.value}`)) return false;
      state.excluded.set(selected, new Set([...(state.excluded.get(selected) ?? []), ...excluded]));
    }
    for (const leaves of state.aggregateExclusions.values()) if (leaves.every(([identity, expected]) => {
      const actual = state.known.get(this.resolver(state)(`id:${identity}`).slice(3));
      return actual?.kind === expected.kind && actual.value === expected.value;
    })) return false;
    return true;
  }

  /** A live digest keeps the selector facts that determine its immutable value. */
  dependencies(identity: string, visit: (identity: string) => void, seen = new Set<string>()): void {
    if (!this.has(identity)) return;
    const pending = [`id:${identity}`];
    while (pending.length) {
      const key = pending.pop()!;
      if (seen.has(key)) continue;
      if (!this.charge(1, 0)) return;
      seen.add(key);
      if (key.startsWith("id:")) visit(key.slice(3));
      const node = this.nodes.get(key);
      if (node?.kind === "choice") { visit(node.selector); pending.push(node.yes, node.no); }
      else if (node?.kind === "hash" || node?.kind === "byte" || node?.kind === "cast") pending.push(node.input);
      else if (node?.kind === "expression") pending.push(...node.inputs);
      else if (node?.kind === "aggregate") for (const [, child] of node.children) pending.push(child);
    }
  }
}
