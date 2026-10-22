import type { TerminalCounterRegion } from "../analysis/counter-regions.js";
import type { Diagnostic, Span } from "../model.js";

type Version = Readonly<
  | { kind: "incoming" }
  | { kind: "reset"; before: number }
  | { kind: "increment"; before: number; amount: bigint }
  | { kind: "choice"; decision: number; yes: number; no: number }
>;
type Operation = Readonly<{ kind: "reset" | "increment"; before: number; after: number; location: Readonly<Span>; amount?: bigint }>;
type History = Readonly<
  | { kind: "empty" }
  | { kind: "append"; prefix: number; operation: Operation }
  | { kind: "choice"; decision: number; yes: number; no: number }
>;

/** Deferred transfers only. This representation computes no Counter semantics. */
export interface CounterHistoryGraph {
  readonly kind: "counter-choice-history-1";
  readonly entry: string;
  readonly ledger: string;
  readonly location: Readonly<Span>;
  readonly decisions: readonly string[];
  readonly versions: readonly Version[];
  readonly histories: readonly History[];
  readonly finalVersion: number;
  readonly finalHistory: number;
  readonly representedAssignments: bigint;
}
export interface CounterHistoryProjection {
  readonly decisions: readonly boolean[];
  readonly operations: readonly Operation[];
  /** Every selected version includes its selected predecessor, never a union. */
  readonly versions: readonly Readonly<{ id: number; kind: "incoming" | "reset" | "increment"; before?: number; amount?: bigint }>[];
  readonly finalVersion: number;
}
type Incomplete = { status: "incomplete"; diagnostics: Diagnostic[]; work: number };
type Complete<T> = { status: "complete"; value: T; work: number };
const limit = (value: number, name: string): number => {
  if (!Number.isSafeInteger(value) || value < 1 || value > 1000000) throw new Error(`Invalid ${name}: expected integer in 1..1000000`);
  return value;
};
const gap = (code: string, location: Readonly<Span>, work: number): Incomplete => ({ status: "incomplete", diagnostics: [{ code, message: "Correlated Counter history budget exhausted; results are incomplete", location: { ...location } }], work });
const span = (value: Readonly<Span>): Readonly<Span> => Object.freeze({ ...value });

/**
 * Caller must obtain the region from the owned semantic/CFG eligibility check.
 * Each diamond shares one decision ID across its history and storage version.
 * No paths, dependencies, guards or successful-execution facts are fabricated.
 */
export function buildCounterHistoryGraph(region: TerminalCounterRegion, maxNodes = 4096): Complete<CounterHistoryGraph> | Incomplete {
  limit(maxNodes, "graph node budget");
  if (region.kind !== "terminal-root-counter-increments" || !region.diamonds.length
    || new Set(region.diamonds.map(item => item.parameter)).size !== region.diamonds.length
    || region.diamonds.some(item => typeof item.amount !== "bigint" || item.amount < 0n || item.amount > 65535n)) throw new Error("Unqualified Counter region");
  const required = 2 + Number(Boolean(region.resetLocation)) * 2 + region.diamonds.length * 4;
  if (required > maxNodes) return gap("correlated-graph-budget", region.location, 0);
  const versions: Version[] = [Object.freeze({ kind: "incoming" })];
  const histories: History[] = [Object.freeze({ kind: "empty" })];
  let currentVersion = 0, currentHistory = 0;
  const append = (operation: Operation): number => {
    histories.push(Object.freeze({ kind: "append", prefix: currentHistory, operation: Object.freeze(operation) }));
    return histories.length - 1;
  };
  if (region.resetLocation) {
    versions.push(Object.freeze({ kind: "reset", before: currentVersion }));
    currentHistory = append({ kind: "reset", before: currentVersion, after: 1, location: span(region.resetLocation) });
    currentVersion = 1;
  }
  region.diamonds.forEach((diamond, decision) => {
    const increment = versions.length;
    versions.push(Object.freeze({ kind: "increment", before: currentVersion, amount: diamond.amount }));
    const yes = append({ kind: "increment", before: currentVersion, after: increment, amount: diamond.amount, location: span(diamond.incrementLocation) });
    versions.push(Object.freeze({ kind: "choice", decision, yes: increment, no: currentVersion }));
    histories.push(Object.freeze({ kind: "choice", decision, yes, no: currentHistory }));
    currentVersion = versions.length - 1;
    currentHistory = histories.length - 1;
  });
  return { status: "complete", work: required, value: Object.freeze({ kind: "counter-choice-history-1", entry: region.entry, ledger: region.ledger,
    location: span(region.location), decisions: Object.freeze(region.diamonds.map(item => item.parameter)), versions: Object.freeze(versions), histories: Object.freeze(histories),
    finalVersion: currentVersion, finalHistory: currentHistory, representedAssignments: 1n << BigInt(region.diamonds.length) }) };
}

/** Select one shared assignment; projecting versions independently is forbidden. */
export function projectCounterHistory(graph: CounterHistoryGraph, assignment: readonly boolean[], maxWork = 20000): Complete<CounterHistoryProjection> | Incomplete {
  limit(maxWork, "projection work budget");
  if (!Array.isArray(assignment) || Object.getPrototypeOf(assignment) !== Array.prototype || assignment.length !== graph.decisions.length
    || Reflect.ownKeys(assignment).length !== assignment.length + 1) throw new Error("Expected one Boolean for every Counter decision");
  const decisions: boolean[] = [];
  for (let index = 0; index < assignment.length; index++) {
    const field = Object.getOwnPropertyDescriptor(assignment, index);
    if (!field || !("value" in field) || !field.enumerable || typeof field.value !== "boolean") throw new Error("Counter decisions must be enumerable Boolean data");
    decisions.push(field.value);
  }
  let work = 0;
  const exhausted = Symbol("projection budget");
  const tick = () => { if (work === maxWork) throw exhausted; work++; };
  const selected = new Map<number, number>();
  const versions: { id: number; kind: "incoming" | "reset" | "increment"; before?: number; amount?: bigint }[] = [];
  const resolveVersion = (root: number): number => {
    // Backward-only construction guarantees a DAG. The stack avoids JS recursion.
    const pending = [root];
    while (pending.length) {
      tick();
      const id = pending.at(-1)!;
      if (selected.has(id)) { pending.pop(); continue; }
      const node = graph.versions[id];
      if (node.kind === "incoming") { selected.set(id, id); versions.push({ id, kind: "incoming" }); pending.pop(); continue; }
      const previous = node.kind === "choice" ? decisions[node.decision] ? node.yes : node.no : node.before;
      if (!selected.has(previous)) { pending.push(previous); continue; }
      if (node.kind === "choice") selected.set(id, selected.get(previous)!);
      else { selected.set(id, id); versions.push({ id, kind: node.kind, before: selected.get(previous), ...(node.kind === "increment" ? { amount: node.amount } : {}) }); }
      pending.pop();
    }
    return selected.get(root)!;
  };
  const operations: Operation[] = [];
  const pending: ({ history: number } | { operation: Operation })[] = [{ history: graph.finalHistory }];
  try {
    while (pending.length) {
      tick();
      const item = pending.pop()!;
      if ("operation" in item) {
        const op = item.operation;
        operations.push(Object.freeze({ ...op, before: resolveVersion(op.before), after: resolveVersion(op.after) }));
        continue;
      }
      const node = graph.histories[item.history];
      if (node.kind === "append") pending.push({ operation: node.operation }, { history: node.prefix });
      else if (node.kind === "choice") pending.push({ history: decisions[node.decision] ? node.yes : node.no });
    }
    const finalVersion = resolveVersion(graph.finalVersion);
    return { status: "complete", work, value: Object.freeze({ decisions: Object.freeze(decisions), operations: Object.freeze(operations),
      versions: Object.freeze(versions.map(version => Object.freeze(version))), finalVersion }) };
  } catch (error) {
    if (error !== exhausted) throw error;
    return gap("correlated-projection-budget", graph.location, work);
  }
}

/** Bounded testing adapter. Exhaustion never returns a supposedly complete prefix. */
export function expandCounterHistories(graph: CounterHistoryGraph, maxHistories = 256, maxWork = 20000): Complete<readonly CounterHistoryProjection[]> | Incomplete {
  limit(maxHistories, "expansion history budget");
  limit(maxWork, "expansion work budget");
  if (graph.representedAssignments > BigInt(maxHistories)) return gap("correlated-expansion-budget", graph.location, 0);
  const results: CounterHistoryProjection[] = [];
  let work = 0;
  for (let bits = 0n; bits < graph.representedAssignments; bits++) {
    if (work === maxWork) return gap("correlated-expansion-budget", graph.location, work);
    const assignment = graph.decisions.map((_, index) => Boolean(bits & (1n << BigInt(index))));
    const projected = projectCounterHistory(graph, assignment, maxWork - work);
    work += projected.work;
    if (projected.status === "incomplete") return gap("correlated-expansion-budget", graph.location, work);
    results.push(projected.value);
  }
  return { status: "complete", work, value: Object.freeze(results) };
}
