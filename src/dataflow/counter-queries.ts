import { extractTerminalCounterRegion } from "../analysis/counter-regions.js";
import type { Diagnostic, Span } from "../model.js";
import { Dataflow, type CounterWitnessLimits, type SuccessfulPath } from "./index.js";

/** Canonical semantic IDs only; these are predicates, not detector policies. */
export type CounterQuery =
  | { kind: "public-flow"; source: string }
  | { kind: "missing-guard-write"; root: string; guard: string };
export interface CounterQueryLimits extends CounterWitnessLimits {
  maxQueryWork?: number;
  maxWitnesses?: number;
  maxTransferSteps?: number;
  maxTransferValues?: number;
}
export interface CounterQueryWork { query: number; witnesses: number; transferSteps: number; transferValues: number }
export interface CounterQueryWitness { decisions: readonly boolean[]; path: SuccessfulPath }
export type CounterQueryEvidence =
  | { kind: "public-flow"; witness: number; sink: number; flow: number }
  | { kind: "missing-guard-write"; witness: number; write: number };
export type CounterQueryResult =
  | { status: "ineligible"; reason: string; location: Span; work: CounterQueryWork }
  | { status: "incomplete"; diagnostics: Diagnostic[]; work: CounterQueryWork }
  | { status: "complete"; entry: string; query: CounterQuery;
      coverage: { contract: "terminal-counter-query-1"; scope: "requested-existential-observations"; assignments: bigint };
      witnesses: CounterQueryWitness[]; evidence: CounterQueryEvidence[]; work: CounterQueryWork };

const defaults = { maxQueryWork: 20000, maxWitnesses: 256, maxTransferSteps: 20000, maxTransferValues: 50000 } as const;
const positive = (value: number, name: string): number => {
  if (!Number.isSafeInteger(value) || value < 1 || value > 1000000) throw new Error(`Invalid ${name}: expected integer in 1..1000000`);
  return value;
};
const fields = (value: unknown, allowed: readonly string[]): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("Expected plain query data");
  const result: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (typeof key !== "string" || !allowed.includes(key) || !("value" in descriptor) || !descriptor.enumerable) throw new Error("Unexpected query field");
    result[key] = descriptor.value;
  }
  return result;
};
const sameSpan = (a: Span, b: Span): boolean => a.file === b.file && a.start === b.start && a.end === b.end
  && a.line === b.line && a.column === b.column && a.endLine === b.endLine && a.endColumn === b.endColumn;
class Refusal extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}

/**
 * Query-specific coverage for the qualified terminal region only. One-hot
 * histories witness sites; the restricted transfer contract proves coverage of
 * this predicate. No witness is promoted into whole-entry AnalysisFacts.
 */
export function queryCounterRegion(flow: Dataflow, entry: string, query: CounterQuery, limits: CounterQueryLimits = {}): CounterQueryResult {
  const input = fields(query, ["kind", "source", "root", "guard"]);
  if (input.kind === "public-flow" && Object.keys(input).length === 2 && typeof input.source === "string" && input.source.length) {
    query = { kind: "public-flow", source: input.source };
  } else if (input.kind === "missing-guard-write" && Object.keys(input).length === 3 && typeof input.root === "string" && input.root.length && typeof input.guard === "string" && input.guard.length) {
    query = { kind: "missing-guard-write", root: input.root, guard: input.guard };
  } else throw new Error("Invalid Counter query");
  const options = fields(limits, [...Object.keys(defaults), "region", "maxGraphNodes", "maxProjectionWork"]);
  const bounds = { ...defaults } as Record<keyof typeof defaults, number>;
  for (const name of Object.keys(defaults) as (keyof typeof defaults)[]) if (options[name] !== undefined) bounds[name] = positive(options[name] as number, name);
  const maxGraphNodes = positive(options.maxGraphNodes as number ?? 4096, "graph node budget");
  const maxProjectionWork = positive(options.maxProjectionWork as number ?? 20000, "projection work budget");
  // Detach and validate nested limits before any extraction or witness calls.
  const regionLimits = options.region === undefined ? undefined : fields(options.region, ["maxSyntaxNodes", "maxCFGNodes", "maxBranches"]);
  if (regionLimits) for (const [name, value] of Object.entries(regionLimits)) positive(value as number, name);
  const work: CounterQueryWork = { query: 0, witnesses: 0, transferSteps: 0, transferValues: 0 };
  const tick = (amount = 1): void => {
    if (amount > bounds.maxQueryWork - work.query) throw new Refusal("counter-query-budget", "Counter query work budget exhausted; results are incomplete");
    work.query += amount;
  };
  const program = flow.program;
  const extracted = extractTerminalCounterRegion(program, entry, regionLimits);
  if (extracted.status !== "eligible") return extracted.status === "ineligible"
    ? { status: "ineligible", reason: extracted.reason, location: extracted.location, work }
    : { status: "incomplete", diagnostics: extracted.diagnostics, work };
  const region = extracted.region;
  const refuse = (reason: string): CounterQueryResult => ({ status: "ineligible", reason, location: { ...region.location }, work });
  const mismatch = (): never => { throw new Refusal("counter-query-contract", "Selected Counter evidence differs from the qualified query contract; results are incomplete"); };
  try {
    const qualification = extracted.work.syntaxNodes + extracted.work.cfgNodes + extracted.work.branches;
    tick(qualification);
    for (const graph of [region.graphs.statements, region.graphs.instructions]) for (const diamond of graph.diamonds) {
      tick();
      if (diamond.controlJoin !== -1) return refuse("Query requires Counter control dependencies to survive to the virtual exit");
    }
    const fn = program.functions.get(entry)!;
    let sourceIndex = -1;
    if (query.kind === "public-flow") {
      const source = program.symbols.get(query.source);
      let belongs = false;
      for (const parameter of fn.declaration.parameters) { tick(); if (parameter.symbol === query.source) belongs = true; }
      if (source?.kind !== "parameter" || !belongs) return refuse("Public-flow query requires a canonical parameter of the selected entry");
      for (const [index, diamond] of region.diamonds.entries()) { tick(); if (diamond.parameter === query.source) sourceIndex = index; }
    } else {
      const root = program.symbols.get(query.root);
      const guard = program.symbols.get(query.guard);
      if (root?.kind !== "ledger" || guard?.kind !== "circuit" || program.representationOf(guard.type) !== "[]") return refuse("Write query requires a canonical ledger and void circuit guard");
    }
    const witnesses: CounterQueryWitness[] = [];
    const evidence: CounterQueryEvidence[] = [];
    const applicable = query.kind === "public-flow" ? sourceIndex >= 0 : query.root === region.ledger;
    if (applicable) for (let chosen = query.kind === "public-flow" ? sourceIndex : 0; chosen < region.diamonds.length; chosen++) {
      tick();
      if (work.witnesses === bounds.maxWitnesses) throw new Refusal("counter-query-witness-budget", "Counter query witness budget exhausted; results are incomplete");
      const remainingSteps = bounds.maxTransferSteps - work.transferSteps;
      const remainingValues = bounds.maxTransferValues - work.transferValues;
      if (!remainingSteps || !remainingValues) throw new Refusal("counter-query-transfer-budget", "Aggregate Counter query transfer budget exhausted; results are incomplete");
      const decisions = region.diamonds.map((_, index) => { tick(); return index === chosen; });
      // Reserve repeated qualification, graph construction and a conservative
      // one-hot projection upper bound before materialization. Lower explicit
      // graph/projection caps still fail in the owned selector.
      const graphNodes = 2 + Number(Boolean(region.resetLocation)) * 2 + region.diamonds.length * 4;
      const projectionBound = Math.min(maxProjectionWork, 8 * region.diamonds.length + 32);
      tick(qualification + graphNodes + projectionBound);
      const evaluator = new Dataflow(program, Math.min(flow.maxSteps, remainingSteps), flow.maxPaths,
        Math.min(flow.maxValues, remainingValues), flow.engine, flow.useSummaries, flow.useStatefulSummaries, flow.pathSemantics);
      work.witnesses++;
      const result = evaluator.selectCounterWitness(entry, decisions, { region: regionLimits, maxGraphNodes, maxProjectionWork: projectionBound });
      if (result.status === "incomplete") {
        // The selector intentionally exposes no partial transfer metrics. Charge
        // its reserved allowances conservatively on an incomplete invocation.
        work.transferSteps += Math.min(flow.maxSteps, remainingSteps);
        work.transferValues += Math.min(flow.maxValues, remainingValues);
        return { status: "incomplete", diagnostics: structuredClone(result.diagnostics), work };
      }
      if (result.status !== "selected") return mismatch();
      work.transferSteps += result.metrics.steps;
      work.transferValues += result.metrics.abstractValues;
      const path = result.path;
      const witness = witnesses.length;
      if (path.entry !== entry || result.decisions.length !== decisions.length || path.path.length !== decisions.length) mismatch();
      for (let index = 0; index < decisions.length; index++) {
        tick();
        const branch = path.path[index];
        if (result.decisions[index] !== decisions[index] || branch.kind !== "branch" || branch.label !== `condition may be ${decisions[index]}`
          || !sameSpan(branch.location, region.diamonds[index].location)) mismatch();
      }
      // Charge every retained observation, including provenance trace records;
      // returned paths are detached snapshots owned by this query result.
      const pending: Iterator<unknown>[] = [[path][Symbol.iterator]()];
      while (pending.length) {
        const next = pending.at(-1)!.next();
        if (next.done) { pending.pop(); continue; }
        tick();
        const value = next.value;
        if (value instanceof Set || Array.isArray(value)) pending.push(value[Symbol.iterator]());
        else if (value && typeof value === "object") pending.push(Object.values(value)[Symbol.iterator]());
      }
      const expectedLocations = [...(region.resetLocation ? [region.resetLocation] : []), region.diamonds[chosen].incrementLocation];
      if (path.writes.length !== expectedLocations.length || path.bindings.length) mismatch();
      for (const [index, write] of path.writes.entries()) {
        tick();
        if (write.ledger !== region.ledger || write.region.length || !sameSpan(write.location, expectedLocations[index])
          || write.callPath.length !== 1 || write.callPath[0] !== entry || write.guards.length) mismatch();
        if (query.kind === "missing-guard-write" && (index === expectedLocations.length - 1 || chosen === 0)) evidence.push({ kind: query.kind, witness, write: index });
      }
      if (path.sinks.length !== 1 + Number(Boolean(region.returnLocation))) mismatch();
      const sink = path.sinks[0];
      if (sink.kind !== "ledger-operation" || sink.name !== `${program.symbols.get(region.ledger)!.name}.increment`
        || !sameSpan(sink.location, region.diamonds[chosen].incrementLocation) || sink.callPath.length !== 1 || sink.callPath[0] !== entry
        || sink.value.flows.length !== chosen + 1) mismatch();
      for (const [index, observed] of sink.value.flows.entries()) {
        tick();
        if (observed.source.symbol !== region.diamonds[index].parameter || observed.source.kind !== "entry-parameter" || observed.form !== "derived") mismatch();
        if (query.kind === "public-flow" && observed.source.symbol === query.source) evidence.push({ kind: query.kind, witness, sink: 0, flow: index });
      }
      if (region.returnLocation) {
        const returned = path.sinks[1];
        if (returned.kind !== "exported-return" || !sameSpan(returned.location, region.returnLocation)
          || returned.value.flows.length || returned.value.items?.length !== 0) mismatch();
      }
      witnesses.push({ decisions: result.decisions, path });
    }
    return { status: "complete", entry, query, coverage: { contract: "terminal-counter-query-1", scope: "requested-existential-observations", assignments: 1n << BigInt(region.diamonds.length) }, witnesses, evidence, work };
  } catch (error) {
    if (!(error instanceof Refusal)) throw error;
    return { status: "incomplete", diagnostics: [{ code: error.code, message: error.message, location: { ...region.location } }], work };
  }
}
