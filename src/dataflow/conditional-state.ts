/** Shared conditional current values. Choice keys come from the interpreter;
 * this graph does not solve source predicates or establish successful paths.
 * Transfers are the ordinary, trusted analysis kernels, not user callbacks. */
export interface ConditionalTerm<T> { readonly id: number; readonly valueType?: T }
type Node = { id: number; depth: number; eager: unknown; hasCommon: boolean } & (
  | { kind: "atom" }
  | { kind: "apply"; inputs: readonly Node[]; run: (inputs: readonly unknown[]) => unknown }
  | { kind: "choice"; selector: string; yes: Node; no: Node }
  | { kind: "decision"; selector: string; input: Node; known: (input: unknown) => boolean | undefined;
      run: (input: unknown, selected: boolean) => unknown }
);
type WithoutId<T> = T extends unknown ? Omit<T, "id"> : never;
export type ConditionalProjection<T> =
  | { status: "selected"; value: T; work: number }
  | { status: "incomplete"; reason: string; work: number };

export class ConditionalStateGraph {
  private readonly nodes = new WeakMap<ConditionalTerm<unknown>, Node>();
  private count = 0;
  private failure?: string;
  constructor(private readonly charge: (work: number, values: number) => boolean) {}

  get incompleteReason(): string | undefined { return this.failure; }
  get size(): number { return this.count; }
  refuse(reason: string): undefined { this.failure ??= reason; return undefined; }

  private get<T>(term: ConditionalTerm<T>): Node {
    const node = this.nodes.get(term);
    if (!node) throw new Error("Foreign conditional state term");
    return node;
  }

  private retain<T>(node: WithoutId<Node>): ConditionalTerm<T> | undefined {
    if (this.failure) return;
    if (node.depth > 512) return this.refuse("Conditional state depth exhausted");
    if (!this.charge(1, 1)) return this.refuse("Conditional state exhausted the shared analysis allowance");
    const stored = Object.freeze({ ...node, id: ++this.count }) as Node;
    const term = Object.freeze({ id: stored.id });
    this.nodes.set(term, stored);
    return term;
  }

  /** Inputs/eager results belong to the calling domain and must stay immutable.
   * Domains detach mutable external inputs before constructing an atom. */
  atom<T>(value: T): ConditionalTerm<T> | undefined {
    return this.retain({ kind: "atom", depth: 0, eager: value, hasCommon: true });
  }

  apply<T extends readonly unknown[], R>(inputs: { readonly [K in keyof T]: ConditionalTerm<T[K]> }, run: (...inputs: T) => R): ConditionalTerm<R> | undefined {
    const nodes = inputs.map(term => this.get(term));
    if (this.failure) return;
    const hasCommon = nodes.every(node => node.hasCommon);
    const eager = hasCommon ? run(...nodes.map(node => node.eager) as unknown as T) : undefined;
    return this.retain({ kind: "apply", inputs: Object.freeze(nodes), run: values => run(...values as T), eager,
      hasCommon, depth: 1 + Math.max(0, ...nodes.map(node => node.depth)) });
  }

  /** Source transfers mutate analysis counters and observations. Retain them
   * without running an eager approximation: only selected source histories may
   * create those observations. Inputs and returned values remain immutable. */
  defer<T extends readonly unknown[], R>(inputs: { readonly [K in keyof T]: ConditionalTerm<T[K]> }, run: (...inputs: T) => R): ConditionalTerm<R> | undefined {
    const nodes = inputs.map(term => this.get(term));
    return this.retain({ kind: "apply", inputs: Object.freeze(nodes), run: values => run(...values as T), eager: undefined,
      hasCommon: false, depth: 1 + Math.max(0, ...nodes.map(node => node.depth)) });
  }

  /** Unlike a value choice, a source decision must evaluate its prefix first.
   * Otherwise a rejected earlier lookup could request an unreachable choice,
   * or a later choice could be selected before the constraints on its operand. */
  decision<T, R>(selector: string, input: ConditionalTerm<T>, known: (input: T) => boolean | undefined,
    run: (input: T, selected: boolean) => R): ConditionalTerm<R> | undefined {
    if (!selector) throw new Error("Expected a stable conditional choice identity");
    const node = this.get(input);
    return this.retain({ kind: "decision", selector, input: node, known: value => known(value as T),
      run: (value, selected) => run(value as T, selected), eager: undefined, hasCommon: false, depth: node.depth + 1 });
  }

  choose<T>(selector: string, yes: ConditionalTerm<T>, no: ConditionalTerm<T>, common: (yes: T, no: T) => T): ConditionalTerm<T> | undefined {
    if (!selector) throw new Error("Expected a stable conditional choice identity");
    const left = this.get(yes), right = this.get(no);
    if (this.failure) return;
    if (left === right) return yes;
    const hasCommon = left.hasCommon && right.hasCommon;
    return this.retain({ kind: "choice", selector, yes: left, no: right,
      eager: hasCommon ? common(left.eager as T, right.eager as T) : undefined, hasCommon,
      depth: 1 + Math.max(left.depth, right.depth) });
  }

  /** Detached conservative view. Never a successful observation. Its allocation
   * uses the same entry allowance as construction and selected projections. */
  common<T>(term: ConditionalTerm<T>, detach: (value: T) => T):
    { status: "available"; value: T } | { status: "incomplete"; reason: string } {
    const node = this.get(term);
    if (!node.hasCommon) return { status: "incomplete", reason: this.failure ?? "Deferred source state has no conservative view" };
    if (!this.failure && !this.charge(1, node.eager === undefined ? 0 : 1)) this.refuse("Conditional state view exhausted the shared analysis allowance");
    if (this.failure) return { status: "incomplete", reason: this.failure };
    const value = detach(node.eager as T);
    return this.failure ? { status: "incomplete", reason: this.failure } : { status: "available", value };
  }

  select<T>(term: ConditionalTerm<T>, decisions: ReadonlyMap<string, boolean>, maxWork: number, detach: (value: T) => T): ConditionalProjection<T> {
    const root = this.get(term);
    if (!Number.isSafeInteger(maxWork) || maxWork < 1) throw new Error("Expected a positive conditional projection allowance");
    let work = 0;
    if (this.failure) return { status: "incomplete", reason: this.failure, work };
    const memo = new Map<number, unknown>();
    class Incomplete extends Error {}
    const visit = (node: Node): unknown => {
      if (++work > maxWork) throw new Incomplete("Conditional state projection work exhausted");
      if (!this.charge(1, (node.kind === "apply" || node.kind === "decision") && !memo.has(node.id) ? 1 : 0)) {
        this.refuse("Conditional state projection exhausted the shared analysis allowance");
        throw new Incomplete(this.failure);
      }
      if (memo.has(node.id)) return memo.get(node.id);
      let value: unknown;
      if (node.kind === "atom") value = node.eager;
      else if (node.kind === "choice") {
        const selected = decisions.get(node.selector);
        if (typeof selected !== "boolean") throw new Incomplete("Missing conditional state choice");
        value = visit(selected ? node.yes : node.no);
      } else if (node.kind === "decision") {
        const input = visit(node.input), known = node.known(input);
        const selected = decisions.get(node.selector) ?? known;
        if (typeof selected !== "boolean") throw new Incomplete("Missing conditional state choice");
        value = node.run(input, selected);
      } else value = node.run(node.inputs.map(visit));
      // A domain may discover exhausted selected facts even if its eager view
      // fit. Such a refusal must not escape as a selected result.
      if (this.failure) throw new Incomplete(this.failure);
      memo.set(node.id, value); return value;
    };
    try {
      const value = visit(root) as T;
      if (value !== undefined && !this.charge(0, 1)) {
        this.refuse("Conditional state projection exhausted the shared analysis allowance");
        throw new Incomplete(this.failure);
      }
      const detached = detach(value);
      if (this.failure) throw new Incomplete(this.failure);
      return { status: "selected", value: detached, work };
    } catch (error) {
      if (!(error instanceof Incomplete)) throw error;
      return { status: "incomplete", reason: error.message, work };
    }
  }
}
