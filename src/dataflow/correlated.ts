import { CFG, type CFGNode } from "../cfg/index.js";
import { AnalysisError, type Diagnostic, type Expr, type Span } from "../model.js";
import type { FunctionInfo, Program } from "../semantic/index.js";
import type { AbstractValue, PublicSink, SuccessfulPath } from "./index.js";
import { castConstant, literalConstant } from "./constants.js";
import { combine, constantOf, controlled, counterMutation, step, binaryValue, logicalValue, negateValue, refineScalar, assumeScalar, type ScalarConstraints } from "./transfers.js";

/** Internal instruction-only coverage. Construction is not a scanner result. */
export interface CorrelatedLimits { maxSteps: number; maxFrontier: number; maxValues: number }
export interface CorrelatedWork { steps: number; values: number; frames: number; frontier: number }
export type CorrelatedTerm<T> = Readonly<{ id: number; depth: number; eager: T; choiceFree: boolean; parameter?: string } & (
  | { kind: "atom"; value: T }
  | { kind: "apply"; inputs: readonly CorrelatedTerm<unknown>[]; transfer: (inputs: readonly unknown[]) => T }
  | { kind: "choice"; choice: number; yes: CorrelatedTerm<T>; no: CorrelatedTerm<T>; merge: (a: unknown, b: unknown) => T }
)>;
type Value = CorrelatedTerm<AbstractValue | undefined>;
type Facts = CorrelatedTerm<ScalarConstraints | undefined>;
type Guards = Readonly<Record<string, CorrelatedTerm<boolean>>>;
export type CorrelatedEvent = Readonly<
  | { kind: "require"; value: Value }
  | { kind: "branch"; choice: number; value: boolean; location: Span }
  | { kind: "write"; before: Value; after: Value; excludedBefore: CorrelatedTerm<readonly string[]>; guards: Guards; ledger: string; location: Span; callPath: readonly string[]; callSites: readonly Span[] }
  | { kind: "sink"; value: Value; sinkKind: PublicSink["kind"]; name: string; location: Span; callPath: readonly string[]; onlyPrivate: boolean }
>;
export type CorrelatedHistory = Readonly<{ id: number } & (
  | { kind: "empty" }
  | { kind: "append"; prefix: CorrelatedHistory; event: CorrelatedEvent }
  | { kind: "choice"; choice: number; yes: CorrelatedHistory; no: CorrelatedHistory }
)>;
export interface CorrelatedGraph {
  readonly scope: "correlated-instructions-5";
  readonly entry: string;
  readonly location: Span;
  readonly choices: readonly Readonly<{ parameter?: string; name: string; location: Span }>[];
  readonly roots: Readonly<Record<string, Value>>;
  readonly guards: Guards;
  readonly history: CorrelatedHistory;
  /** No admitted transfer introduces any of these facts. Broader scope must requalify this list. */
  readonly structuralAbsence: readonly ("hash-bindings" | "commitments" | "failed-assertions")[];
  readonly work: Readonly<CorrelatedWork>;
}
export type CorrelatedResult = { status: "complete"; graph: CorrelatedGraph }
  | { status: "incomplete"; diagnostics: Diagnostic[]; work: Readonly<CorrelatedWork> };
export type CorrelatedObservation = { status: "selected"; path: SuccessfulPath; roots: Record<string, AbstractValue>; guards: string[]; sites: { site: number; kind: "write" | "sink"; index: number }[]; work: number; values: number }
  | { status: "rejected"; work: number; values: number }
  | { status: "incomplete"; diagnostics: Diagnostic[]; work: number; values: number };
interface Control { value: Value; active: CorrelatedTerm<boolean>; site: string; until: number; owner: string }
interface Current {
  roots: Record<string, Value>; versions: Record<string, CorrelatedTerm<number>>; clock: CorrelatedTerm<number>;
  env: Record<string, Value>; facts: Facts; constraintParameters: ReadonlySet<string>;
  guards: Guards; control: readonly Control[]; history: CorrelatedHistory;
}
const newFacts = (): ScalarConstraints => ({ known: new Map(), truths: new Map(), excluded: new Map(), aggregateExclusions: new Map(), aggregateExclusionLeaves: 0, aggregateExclusionsExhausted: false });
const cloneFacts = (facts: ScalarConstraints): ScalarConstraints => ({ ...(facts.scalarEqualities ? { scalarEqualities: new Map(facts.scalarEqualities), scalarEqualitiesExhausted: facts.scalarEqualitiesExhausted } : {}), ...(facts.orderings ? { orderings: new Map(facts.orderings), orderingsExhausted: facts.orderingsExhausted } : {}), known: new Map(facts.known), truths: new Map(facts.truths), excluded: new Map([...facts.excluded].map(([key, values]) => [key, new Set(values)])), aggregateExclusions: new Map(facts.aggregateExclusions), aggregateExclusionLeaves: facts.aggregateExclusionLeaves, aggregateExclusionsExhausted: facts.aggregateExclusionsExhausted });
function mustFacts(a: ScalarConstraints | undefined, b: ScalarConstraints | undefined): ScalarConstraints | undefined {
  if (!a) return b; if (!b) return a;
  const result = newFacts();
  for (const [key, value] of a.known) if (b.known.get(key)?.kind === value.kind && b.known.get(key)?.value === value.value) result.known.set(key, value);
  for (const [key, value] of a.truths) if (b.truths.get(key) === value) result.truths.set(key, value);
  for (const [key, values] of a.excluded) { const common = new Set([...values].filter(value => b.excluded.get(key)?.has(value))); if (common.size) result.excluded.set(key, common); }
  for (const [key, leaves] of a.aggregateExclusions) if (b.aggregateExclusions.has(key)) { result.aggregateExclusions.set(key, leaves); result.aggregateExclusionLeaves += leaves.length; }
  result.aggregateExclusionsExhausted = a.aggregateExclusionsExhausted || b.aggregateExclusionsExhausted;
  for (const [key, relation] of a.scalarEqualities ?? []) if (b.scalarEqualities?.get(key)?.equals === relation.equals) (result.scalarEqualities ??= new Map()).set(key, relation);
  if (a.scalarEqualitiesExhausted || b.scalarEqualitiesExhausted) result.scalarEqualitiesExhausted = true;
  for (const [key, ordering] of a.orderings ?? []) if (b.orderings?.get(key)?.truth === ordering.truth) (result.orderings ??= new Map()).set(key, ordering);
  if (a.orderingsExhausted || b.orderingsExhausted) result.orderingsExhausted = true;
  return result;
}
const defaults: CorrelatedLimits = { maxSteps: 20000, maxFrontier: 256, maxValues: 50000 };
const empty = (): AbstractValue => ({ flows: [], ledger: new Set() });
const freezeSpan = (span: Span): Span => Object.freeze({ ...span });
class Refusal extends Error {
  constructor(readonly code: string, message: string, readonly location: Span) { super(message); }
}
const validLimit = (value: number): boolean => Number.isSafeInteger(value) && value > 0 && value <= 1000000;

/** Saturated syntactic estimate, including repeated resolved call sites. It only
 * selects an analysis engine; recursion/depth still require explicit refusal.
 */
export function correlatedBranchCount(program: Program, entry: string, limit: number): number {
  const memo = new Map<string, number>(), active = new Set<string>();
  const visit = (id: string): number => {
    if (active.has(id) || active.size >= 32) return limit;
    if (memo.has(id)) return memo.get(id)!;
    active.add(id);
    let count = 0;
    for (const node of program.instructionCFG(id).nodes) {
      if (node.kind === "branch") count++;
      const expression = node.instruction?.kind === "evaluate" ? node.instruction.expression : undefined;
      if (expression?.kind === "call" && expression.symbol && program.functions.has(expression.symbol)) count += visit(expression.symbol);
      if (count >= limit) { count = limit; break; }
    }
    active.delete(id); memo.set(id, count); return count;
  };
  return visit(entry);
}

/** Only conservative eager facts are joined. Exact metadata stays in the terms. */
function mayValue(first: AbstractValue | undefined, second: AbstractValue | undefined): AbstractValue | undefined {
  if (!first) return second;
  if (!second) return first;
  const same = first.constant !== undefined && first.constant === second.constant && first.constantKind === second.constantKind;
  return { ...combine([first, second]), type: first.type === second.type ? first.type : undefined,
    constant: same ? first.constant : undefined, constantKind: same ? first.constantKind : undefined,
    items: first.items && second.items?.length === first.items.length ? first.items.map((item, index) => mayValue(item, second.items![index])!) : undefined,
    fields: first.fields && second.fields && Object.keys(first.fields).every(name => Object.hasOwn(second.fields!, name)) ? Object.fromEntries(Object.entries(first.fields).map(([name, item]) => [name, mayValue(item, second.fields![name])!])) : undefined };
}

/**
 * Traverse owned instructions once per syntactic arm. Normal reconvergence and
 * actual abort-sensitive control expiry are distinct. No cached State, summaries,
 * constraints or callable closures from source are replayed during projection.
 */
export function analyzeCorrelatedEntry(program: Program, entry: string, options: Partial<CorrelatedLimits> = {}, sourceOffset = 0): CorrelatedResult {
  const limits = { ...defaults, ...options };
  if (!options || Object.keys(options).some(key => !Object.hasOwn(defaults, key)) || !Object.values(limits).every(validLimit) || !Number.isSafeInteger(sourceOffset) || sourceOffset < 0) throw new Error("Invalid correlated construction limits");
  const work: CorrelatedWork = { steps: 0, values: 0, frames: 0, frontier: 0 };
  const location = program.functions.get(entry)?.declaration.span ?? program.rootSource.ast.span;
  const refuse = (message: string, at = location, code = "correlated-unsupported"): never => { throw new Refusal(code, message, at); };
  const tick = (at = location): void => { if (++work.steps > limits.maxSteps) refuse("Correlated construction work exhausted", at, "correlated-step-budget"); };
  const id = (): number => { tick(); if (++work.values > limits.maxValues) refuse("Correlated graph/value budget exhausted", location, "correlated-value-budget"); return work.values; };
  const atom = <T>(value: T, parameter?: string): CorrelatedTerm<T> => Object.freeze({ id: id(), depth: 0, kind: "atom", choiceFree: true, value, eager: value, parameter });
  const apply = <T>(inputs: readonly CorrelatedTerm<unknown>[], transfer: (values: readonly unknown[]) => T, parameter?: string): CorrelatedTerm<T> => {
    const depth = 1 + Math.max(0, ...inputs.map(term => term.depth));
    if (depth > 512) refuse("Correlated value depth exhausted", location, "correlated-depth-budget");
    return Object.freeze({ id: id(), depth, kind: "apply", choiceFree: inputs.every(term => term.choiceFree), inputs: Object.freeze([...inputs]), transfer, eager: transfer(inputs.map(term => term.eager)), parameter });
  };
  const choose = <T>(choice: number, yes: CorrelatedTerm<T>, no: CorrelatedTerm<T>, merge: (a: T, b: T) => T): CorrelatedTerm<T> => {
    if (yes === no) return yes;
    const depth = 1 + Math.max(yes.depth, no.depth); if (depth > 512) refuse("Correlated value depth exhausted", location, "correlated-depth-budget");
    return Object.freeze({ id: id(), depth, kind: "choice", choiceFree: false, choice, yes, no, merge: (a: unknown, b: unknown) => merge(a as T, b as T), eager: merge(yes.eager, no.eager) });
  };
  const lift = (values: readonly Value[], transfer: (values: AbstractValue[]) => AbstractValue | undefined, parameter?: string): Value => apply(values, items => items.some(item => item === undefined) ? undefined : transfer(items as AbstractValue[]), parameter);
  const scalar = (type: string): boolean => /^(Boolean|Field|Uint<[^>]+>)$/.test(program.representationOf(type));
  const storage = (type: string): boolean => scalar(type) || program.representationOf(type) === "Counter";
  const choices: { parameter?: string; name: string; location: Span }[] = [];
  const append = (state: Current, event: CorrelatedEvent): void => {
    // Pure terms without a choice have an exact eager value. Keep known failures;
    // only a requirement that succeeds for every assignment can be omitted.
    if (event.kind === "require" && event.value.choiceFree && event.value.eager !== undefined) return;
    state.history = Object.freeze({ id: id(), kind: "append", prefix: state.history, event: Object.freeze(event) });
  };
  const clone = (state: Current): Current => { work.frames++; return { ...state, roots: { ...state.roots }, versions: { ...state.versions }, env: { ...state.env } }; };
  let frontier = 0;
  const enter = (): void => { if (++frontier > limits.maxFrontier) refuse("Correlated joined frontier exhausted", location, "correlated-frontier-budget"); work.frontier = Math.max(frontier, work.frontier); };
  const control = (value: Value, state: Current, at: Span, force = false): Value => state.control.length ? apply([value, ...state.control.flatMap(item => [item.active, item.value])], values => {
    const current = values[0] as AbstractValue | undefined; if (!current) return undefined;
    const controls: AbstractValue[] = [];
    for (let index = 1; index < values.length; index += 2) if (values[index]) {
      if (!values[index + 1]) return undefined;
      controls.push(values[index + 1] as AbstractValue);
    }
    return controlled(current, controls, at, force);
  }, value.parameter) : value;
  const support = (...groups: Iterable<string>[]): ReadonlySet<string> => {
    const result = new Set<string>();
    for (const group of groups) for (const name of group) { tick(); if (!result.has(name)) { id(); result.add(name); } }
    return result;
  };
  const refine = (value: Value, state: Current): Value => {
    if (state.facts.kind === "atom" && state.facts.value && !state.facts.value.known.size && !state.facts.value.truths.size && !state.facts.value.excluded.size && !state.facts.value.aggregateExclusions.size) return value;
    if (value.kind === "atom" && !value.value?.identity) return value;
    // A carried original-parameter identity is stable through argument/disclose
    // decoration. May-source support overapproximates all assumptions that can
    // refine that identity. Required histories still check rejected prefixes.
    if (value.parameter && !state.constraintParameters.has(value.parameter)) return value;
    return apply([value, state.facts], ([current, facts]) => current && facts ? refineScalar(current as AbstractValue, facts as ScalarConstraints) : undefined, value.parameter);
  };
  const read = (state: Current, root: string): Value => {
    const symbol = program.symbols.get(root)!;
    if (!state.roots[root]) refuse("Only scalar and Counter whole-root storage is admitted", symbol.span);
    return refine(apply([state.roots[root], state.versions[root]], ([stored, revision]) => stored === undefined ? undefined : {
      ...(stored as AbstractValue), identity: (stored as AbstractValue).identity ?? `ledger:${JSON.stringify([root])}:${revision}`,
      region: { root, path: [], type: symbol.type, revision: revision as number },
    }), state);
  };
  const graphs = new Map<string, { graph: CFG; normalJoins: Map<number, number> }>();
  const prepare = (fn: FunctionInfo): { graph: CFG; normalJoins: Map<number, number> } => {
    if (graphs.has(fn.symbol.id)) return graphs.get(fn.symbol.id)!;
    const graph = program.instructionCFG(fn.symbol.id), normal = new CFG();
    normal.entry = graph.entry; normal.exit = graph.exit; normal.abort = graph.abort;
    for (const node of graph.nodes) { tick(node.span); normal.nodes.push({ ...node, edges: node.edges.filter(edge => edge.target !== graph.abort) }); }
    const result = { graph, normalJoins: normal.immediatePostdominators() }; graphs.set(fn.symbol.id, result); return result;
  };
  try {
    const fn = program.functions.get(entry);
    if (!fn || !program.entries.includes(entry) || fn.symbol.kind !== "circuit") refuse("Requires a circuit entrypoint");
    const yes = atom(true), no = atom(false), zero = atom(0);
    const voidValue = (): Value => atom({ ...empty(), items: [], type: "[]" });
    let callSites: readonly Span[] = [];
    const initial: Current = { roots: {}, versions: {}, clock: zero, env: {}, facts: atom<ScalarConstraints | undefined>(newFacts()), constraintParameters: new Set(), guards: Object.freeze({}), control: [], history: Object.freeze({ id: id(), kind: "empty" }) };
    for (const symbol of program.activeSymbols()) if (symbol.kind === "ledger" && storage(symbol.type)) {
      initial.roots[symbol.id] = atom({ ...empty(), ledger: new Set([symbol.id]), preexistingLedger: new Set([symbol.id]), type: symbol.type }); initial.versions[symbol.id] = zero;
    }
    const write = (state: Current, root: string, assigned: Value, at: Span, stack: readonly string[]): void => {
      const before = read(state, root), after = control(assigned, state, at);
      append(state, { kind: "require", value: after });
      const excludedBefore = apply([before, state.facts], ([value, facts]) => {
        const identity = (value as AbstractValue | undefined)?.identity;
        return identity && facts ? [...((facts as ScalarConstraints).excluded.get(identity) ?? [])] : [];
      });
      append(state, { kind: "write", ledger: root, before, after, excludedBefore, guards: state.guards, location: at, callPath: Object.freeze([...stack]), callSites });
      state.guards = Object.freeze(Object.fromEntries(Object.entries(state.guards).map(([guard, term]) => [guard, program.functions.get(guard)!.readsState.has(root) ? no : term])));
      state.roots[root] = apply([after, state.clock], ([value, clock]) => value === undefined ? undefined : { ...(value as AbstractValue), identity: (value as AbstractValue).identity ?? `write:${clock}` });
      state.clock = apply([state.clock, after], ([clock, value]) => (clock as number) + Number(value !== undefined && !(value as AbstractValue).identity));
      state.versions[root] = apply([state.versions[root]], ([version]) => (version as number) + 1);
    };
    const sink = (state: Current, value: Value, sinkKind: PublicSink["kind"], name: string, at: Span, stack: readonly string[], onlyPrivate = false): void => append(state, { kind: "sink", value, sinkKind, name, location: at, callPath: Object.freeze([...stack]), onlyPrivate });
    const evaluate = (expr: Expr, values: Value[], state: Current, stack: readonly string[]): Value => {
      tick(expr.span);
      const at = freezeSpan(expr.span), type = expr.inferredType;
      if (expr.kind === "literal") {
        const constant = literalConstant(expr); if (!constant) refuse("Unsupported correlated literal", at);
        return atom({ ...empty(), type, constant: constant!.value, constantKind: constant!.kind });
      }
      if (expr.kind === "default") {
        if (!storage(expr.type!)) refuse("Unsupported correlated default", at);
        return atom({ ...empty(), type: expr.type, constant: program.representationOf(expr.type!) === "Boolean" ? "false" : "0", constantKind: program.representationOf(expr.type!) === "Boolean" ? "boolean" : "integer" });
      }
      if (expr.kind === "ref") {
        const symbol = program.symbols.get(expr.symbol!)!;
        if (symbol.kind === "ledger") return read(state, symbol.id);
        if (!state.env[symbol.id]) refuse("Unsupported captured or unavailable value", at);
        return refine(state.env[symbol.id], state);
      }
      if (expr.kind === "disclose") return lift(values, items => ({ ...step(items[0], "disclose", "explicit disclosure permission", at), type }), values[0].parameter);
      if (expr.kind === "tuple" && expr.args.every(arg => arg.kind !== "spread") && values.length <= 256) return lift(values, items => ({ ...combine(items), items, type }));
      if (expr.kind === "cast" && ["numeric", "identity"].includes(expr.castKind ?? "") && scalar(expr.type!) && scalar(expr.args[0].inferredType!)) {
        const kind = expr.castKind, target = program.representationOf(expr.type!), label = expr.type!;
        return lift(values, items => {
          const converted = castConstant(constantOf(items[0]), target); if (converted === null) return undefined;
          const value = step(items[0], "cast", label, at);
          return kind === "identity" ? { ...value, type } : { ...value, type, equalities: undefined, constant: converted?.value, constantKind: converted?.kind, identity: value.identity, comparison: undefined, ordering: undefined, negated: undefined, collectionPredicate: undefined, listPredicate: undefined };
        });
      }
      if (expr.kind === "binary" && ["==", "!=", "+", "-", "*", "<", "<=", ">", ">="].includes(expr.name!) && expr.args.every(argument => scalar(argument.inferredType!))) {
        return lift(values, items => { const value = binaryValue(items, expr.name!, at, expr.numericType ?? type ?? "unknown", expr.checkedArithmetic); return value && { ...value, type }; });
      }
      if (expr.kind === "unary" && expr.name === "!" && program.representationOf(expr.args[0].inferredType!) === "Boolean") {
        return lift(values, ([value]) => ({ ...negateValue(value, at), type }));
      }
      if (expr.kind === "assign" && expr.name === "=" && expr.args[0].kind === "ref" && program.symbols.get(expr.args[0].symbol!)?.kind === "ledger") {
        const root = expr.args[0].symbol!; if (!scalar(program.symbols.get(root)!.type)) refuse("Only scalar assignment is admitted", at);
        const assigned = control(values[1], state, at, true); write(state, root, assigned, at, stack); sink(state, assigned, "ledger-write", program.symbols.get(root)!.name, at, stack);
        return atom(empty());
      }
      if (expr.kind === "member" && expr.value === "call" && expr.args[0].kind === "ref" && program.symbols.get(expr.args[0].symbol!)?.kind === "ledger") {
        const root = expr.args[0].symbol!, symbol = program.symbols.get(root)!;
        if (program.representationOf(symbol.type) !== "Counter" || !["read", "resetToDefault", "increment", "decrement"].includes(expr.name!)) refuse("Unsupported correlated ledger operation", at);
        const argument = control(lift(values.slice(1), items => combine(items)), state, at, true);
        sink(state, argument, "ledger-operation", `${symbol.name}.${expr.name}`, at, stack, true);
        if (expr.name === "read") return lift([read(state, root)], ([value]) => ({ ...value, type }));
        const operator = expr.name === "increment" ? "+" : "-";
        const assigned = expr.name === "resetToDefault" ? atom({ ...empty(), type: symbol.type, constant: "0", constantKind: "integer" as const }) : lift([read(state, root), values[1]], items => counterMutation(items[0], items[1], operator, at));
        write(state, root, assigned, at, stack); return voidValue();
      }
      if (expr.kind === "call") {
        const callee = program.functions.get(expr.symbol!);
        if (!callee || callee.symbol.kind !== "circuit") refuse("Only resolved circuit helpers are admitted", at);
        const returned = invoke(callee!, values, state, stack, expr.span);
        return lift([returned], ([value]) => ({ ...step(value, "call", callee!.symbol.name, at), type }));
      }
      return refuse(`Unsupported correlated expression ${expr.kind}`, at);
    };
    const instruction = (node: CFGNode, previous: number, state: Current, stack: readonly string[]): Value => {
      const operation = node.instruction;
      if (!operation) return atom(empty());
      let inputs = operation.inputs;
      if (operation.kind === "merge") {
        if (previous === -2) return state.env[operation.result];
        const index = operation.predecessors.indexOf(previous); if (index < 0) refuse("Unknown correlated merge predecessor", node.span);
        inputs = [operation.inputs[index]];
      }
      const values = inputs.map(name => { const value = state.env[name]; if (!value) refuse("Unavailable correlated instruction operand", node.span); return refine(value, state); });
      if (operation.kind === "evaluate") {
        const value = evaluate(operation.expression, values, state, stack);
        // Reference evaluation already refines the loaded value with these facts.
        return operation.expression.kind === "ref" ? value : refine(value, state);
      }
      if (operation.kind === "copy" || operation.kind === "merge") return values[0];
      const expr = operation.expression;
      return lift(values, items => logicalValue(items, expr.name!, operation.selected, expr.span));
    };
    const join = (choice: number, left: Current, right: Current): Current => {
      const merged = clone(left);
      const records = <T>(a: Record<string, CorrelatedTerm<T>>, b: Record<string, CorrelatedTerm<T>>, merge: (a: T, b: T) => T) => Object.fromEntries(Object.keys(a).filter(name => Object.hasOwn(b, name)).map(name => [name, choose(choice, a[name], b[name], merge)]));
      merged.roots = records(left.roots, right.roots, mayValue);
      merged.versions = records(left.versions, right.versions, Math.max);
      merged.clock = choose(choice, left.clock, right.clock, Math.max);
      merged.env = records(left.env, right.env, mayValue);
      merged.facts = choose(choice, left.facts, right.facts, mustFacts);
      merged.constraintParameters = support(left.constraintParameters, right.constraintParameters);
      merged.guards = Object.freeze(Object.fromEntries([...new Set([...Object.keys(left.guards), ...Object.keys(right.guards)])].map(name => [name, choose(choice, left.guards[name] ?? no, right.guards[name] ?? no, (a, b) => a && b)])));
      merged.control = [...new Set([...left.control, ...right.control].map(item => item.site))].map(site => {
        const a = left.control.find(item => item.site === site), b = right.control.find(item => item.site === site);
        return { ...(a ?? b)!, value: a && b ? choose(choice, a.value, b.value, mayValue) : (a ?? b)!.value,
          active: choose(choice, a?.active ?? no, b?.active ?? no, (a, b) => a || b) };
      });
      merged.history = Object.freeze({ id: id(), kind: "choice", choice, yes: left.history, no: right.history }); return merged;
    };
    const invoke = (callee: FunctionInfo, args: Value[], state: Current, parents: readonly string[], invocation = callee.declaration.span): Value => {
      tick(callee.declaration.span);
      if (parents.includes(callee.symbol.id) || parents.length >= 32) refuse("Correlated call depth exhausted", callee.declaration.span, "correlated-call-depth");
      const stack = Object.freeze([...parents, callee.symbol.id]), { graph, normalJoins } = prepare(callee);
      if (args.length !== callee.declaration.parameters.length) refuse("Correlated helper arity mismatch", callee.declaration.span);
      for (const [index, parameter] of callee.declaration.parameters.entries()) {
        if (parameter.pattern && (parameter.pattern.kind !== "name" || parameter.pattern.symbol !== parameter.symbol) || !scalar(parameter.type)) refuse("Only scalar named parameters are admitted", parameter.span);
        const at = freezeSpan(parameter.span), name = parameter.name, type = parameter.type;
        state.env[parameter.symbol!] = lift([args[index]], ([value]) => ({ ...step(value, "argument", name, at), type }), args[index].parameter);
      }
      const walk = (input: Current, start: number, stop: number | undefined, predecessor: number): { state: Current; previous: number; value?: Value } => {
        enter();
        try {
          let current = input, nodeId = start, previous = predecessor;
          while (nodeId !== stop) {
            const node = graph.nodes[nodeId]; tick(node.span);
            current.control = current.control.filter(control => control.owner !== callee.symbol.id || control.until !== node.id);
            if (node.pattern && (node.pattern.kind !== "name" || node.pattern.symbol !== node.binding)) refuse("Destructuring is outside correlated scope", node.span);
            if (node.kind === "exit") {
              if (stop !== undefined) refuse("Branch terminates before normal reconvergence", node.span);
              current.control = current.control.filter(control => control.owner !== callee.symbol.id);
              current.guards = Object.freeze({ ...current.guards, [callee.symbol.id]: yes }); return { state: current, previous, value: voidValue() };
            }
            const value = instruction(node, previous, current, stack);
            // A reference load is total: any undefined operand/facts originated
            // at a producer, write or assumption whose required event remains in
            // the same ordered history. Do not recheck it at each subsequent load.
            if (node.instruction?.kind !== "evaluate" || node.instruction.expression.kind !== "ref") append(current, { kind: "require", value });
            if (node.instruction?.result) current.env[node.instruction.result] = node.instruction.kind === "copy" ? control(value, current, freezeSpan(node.span)) : value;
            if (node.binding) {
              const at = freezeSpan(node.span), name = program.symbols.get(node.binding)!.name;
              const bound = control(value, current, at);
              // Ordinary name-pattern binding overwrites the decorated binding
              // slot with the bound value. Preserve that final provenance.
              current.env[node.binding] = node.pattern ? bound : lift([bound], ([value]) => step(value, "binding", name, at));
            }
            if (node.kind === "return") {
              const at = freezeSpan(node.span), name = callee.symbol.name, type = callee.declaration.type;
              const result = lift([control(lift([value], ([value]) => step(value, "return", name, at)), current, at)], ([value]) => ({ ...value, type }));
              if (!parents.length) sink(current, result, "exported-return", name, at, stack);
              current.control = current.control.filter(control => control.owner !== callee.symbol.id);
              current.guards = Object.freeze({ ...current.guards, [callee.symbol.id]: yes }); return { state: current, previous, value: result };
            }
            if (node.kind === "branch") {
              const parameter = value.parameter && program.symbols.get(value.parameter)?.type === "Boolean" ? value.parameter : undefined;
              let choice = parameter ? choices.findIndex(item => item.parameter === parameter) : -1;
              if (choice < 0) { choice = choices.length; choices.push({ parameter, name: parameter ? program.symbols.get(parameter)!.name : "condition", location: freezeSpan(node.span) }); }
              const constraintParameters = support(current.constraintParameters, value.eager?.flows.flatMap(flow => flow.source.symbol ? [flow.source.symbol] : []) ?? []);
              const convergence = normalJoins.get(node.id);
              if (convergence === undefined || convergence < 0) refuse("Missing normal branch reconvergence", node.span);
              const arms = [true, false].map(selected => {
                const next = clone(current), edge = node.edges.find(edge => edge.condition === selected);
                if (!edge) refuse("Missing branch successor", node.span);
                append(next, { kind: "branch", choice, value: selected, location: freezeSpan(node.span) });
                next.facts = apply([current.facts, value], ([facts, condition]) => {
                  if (!facts || !condition) return undefined;
                  const copied = cloneFacts(facts as ScalarConstraints);
                  const possible = assumeScalar(condition as AbstractValue, selected, copied);
                  if (copied.scalarEqualitiesExhausted) refuse("Scalar relation capacity exhausted; results are incomplete", node.span, "correlated-constraint-budget");
                  if (copied.orderingsExhausted) refuse("Ordered predicate capacity exhausted; results are incomplete", node.span, "correlated-constraint-budget");
                  if (copied.aggregateExclusionsExhausted) refuse("Aggregate exclusion capacity exhausted; results are incomplete", node.span, "correlated-constraint-budget");
                  return possible ? copied : undefined;
                });
                next.constraintParameters = constraintParameters;
                append(next, { kind: "require", value: apply([next.facts], ([facts]) => facts ? empty() : undefined) });
                next.control = [...next.control, { value, active: yes, site: `${callee.symbol.id}:${node.id}`, owner: callee.symbol.id, until: node.join! }];
                // If reconvergence is the function exit, finish each arm through
                // its own return/fallthrough. Caller continuation starts only
                // after the returned value and final current state are joined.
                const result = walk(next, edge!.target, convergence === graph.exit ? undefined : convergence, node.id);
                const merge = graph.nodes[convergence!];
                if (merge.instruction?.kind === "merge") result.state.env[merge.instruction.result] = instruction(merge, result.previous, result.state, stack);
                return result;
              });
              current = join(choice, arms[0].state, arms[1].state);
              if (convergence === graph.exit) {
                if (!arms[0].value || !arms[1].value) refuse("Missing conditional return", node.span);
                return { state: current, previous: node.id, value: choose(choice, arms[0].value!, arms[1].value!, mayValue) };
              }
              nodeId = convergence!; previous = graph.nodes[nodeId].instruction?.kind === "merge" ? -2 : node.id; continue;
            }
            const edges = node.edges.filter(edge => edge.target !== graph.abort);
            if (edges.length !== 1) refuse("Unexpected correlated instruction continuation", node.span);
            previous = nodeId; nodeId = edges[0].target;
          }
          return { state: current, previous };
        } finally { frontier--; }
      };
      const callerSites = callSites;
      callSites = Object.freeze([...callerSites, freezeSpan(invocation)]);
      try {
        const result = walk(state, graph.entry, undefined, -1);
        Object.assign(state, result.state); return result.value!;
      } finally { callSites = callerSites; }
    };
    const parameters = fn!.declaration.parameters.map((parameter, index) => {
      if (!scalar(parameter.type) || parameter.pattern && (parameter.pattern.kind !== "name" || parameter.pattern.symbol !== parameter.symbol)) refuse("Unsupported entry parameter", parameter.span);
      const at = freezeSpan(parameter.span), source = { id: `${at.file}:${at.start}:${sourceOffset + index}`, kind: "entry-parameter" as const, name: parameter.name, location: at, symbol: parameter.symbol };
      return atom<AbstractValue | undefined>({ flows: [{ source, form: "raw", trace: [{ kind: "source", label: source.name, location: at }] }], ledger: new Set(), identity: source.id, type: parameter.type }, parameter.symbol);
    });
    invoke(fn!, parameters, initial, []);
    const roots = Object.fromEntries(Object.keys(initial.roots).map(root => [root, read(initial, root)]));
    return { status: "complete", graph: Object.freeze({ scope: "correlated-instructions-5", entry, location: freezeSpan(location), choices: Object.freeze(choices.map(choice => Object.freeze(choice))), roots: Object.freeze(roots), guards: initial.guards, history: initial.history, structuralAbsence: Object.freeze(["hash-bindings", "commitments", "failed-assertions"] as const), work: Object.freeze({ ...work }) }) };
  } catch (error) {
    if (error instanceof AnalysisError) return { status: "incomplete", diagnostics: [error.diagnostic], work: Object.freeze({ ...work }) };
    if (!(error instanceof Refusal)) throw error;
    return { status: "incomplete", diagnostics: [{ code: error.code, message: `${error.message}; results are incomplete`, location: freezeSpan(error.location) }], work: Object.freeze({ ...work }) };
  }
}

/** Project full observations from shared terms, never replay a whole State. */
export function selectCorrelatedObservation(graph: CorrelatedGraph, decisions: readonly boolean[], maxWork = 20000, maxValues = 50000): CorrelatedObservation {
  if (!validLimit(maxWork) || !validLimit(maxValues) || !Array.isArray(decisions) || Object.getPrototypeOf(decisions) !== Array.prototype || decisions.length !== graph.choices.length || Reflect.ownKeys(decisions).length !== decisions.length + 1) throw new Error("Invalid correlated observation selection");
  const selected: boolean[] = [];
  for (let index = 0; index < decisions.length; index++) {
    const field = Object.getOwnPropertyDescriptor(decisions, index);
    if (!field || !("value" in field) || !field.enumerable || typeof field.value !== "boolean") throw new Error("Correlated selection requires enumerable Boolean data");
    selected.push(field.value);
  }
  const cache = new Map<number, unknown>(); let work = 0, values = 0;
  const tick = (): void => { if (++work > maxWork) throw new Refusal("correlated-projection-budget", "Correlated observation work exhausted; results are incomplete", graph.location); };
  const retain = (): void => { if (++values > maxValues) throw new Refusal("correlated-projection-value-budget", "Correlated observation capacity exhausted; results are incomplete", graph.location); };
  const term = <T>(input: CorrelatedTerm<T>): T => {
    tick(); if (cache.has(input.id)) return cache.get(input.id) as T;
    const value = input.choiceFree ? input.eager : input.kind === "atom" ? input.value : input.kind === "choice" ? term(selected[input.choice] ? input.yes : input.no) : input.transfer(input.inputs.map(item => term(item)));
    retain(); cache.set(input.id, value); return value;
  };
  try {
    const events: { site: number; event: CorrelatedEvent }[] = []; let history = graph.history;
    while (history.kind !== "empty") { tick(); if (history.kind === "choice") history = selected[history.choice] ? history.yes : history.no; else { retain(); events.push({ site: history.id, event: history.event }); history = history.prefix; } }
    const path: SuccessfulPath = { entry: graph.entry, predicates: [], bindings: [], sinks: [], path: [], writes: [] };
    const sites: { site: number; kind: "write" | "sink"; index: number }[] = [];
    const guards = (values: Guards): string[] => Object.keys(values).filter(name => term(values[name]));
    for (const { site, event } of events.reverse()) {
      tick();
      if (event.kind === "require") { if (!term(event.value)) return { status: "rejected", work, values }; }
      else if (event.kind === "branch") path.path.push({ kind: "branch", label: `condition may be ${event.value}`, location: event.location });
      else if (event.kind === "write") {
        const before = term(event.before), after = term(event.after); if (!before || !after) return { status: "rejected", work, values };
        sites.push({ site, kind: "write", index: path.writes.length });
        path.writes.push({ ledger: event.ledger, region: [], location: event.location, before, after, excludedBefore: [...term(event.excludedBefore)], guards: guards(event.guards), callPath: [...event.callPath], callSites: event.callSites.map(at => ({ ...at })) });
      } else {
        const value = term(event.value); if (!value) return { status: "rejected", work, values };
        if (!event.onlyPrivate || value.flows.length) { sites.push({ site, kind: "sink", index: path.sinks.length }); path.sinks.push({ kind: event.sinkKind, name: event.name, value, location: event.location, callPath: [...event.callPath] }); }
      }
    }
    const roots: Record<string, AbstractValue> = {};
    for (const [root, value] of Object.entries(graph.roots)) { const result = term(value); if (!result) return { status: "rejected", work, values }; roots[root] = result; }
    const completedGuards = guards(graph.guards);
    return { status: "selected", path: structuredClone(path), roots: structuredClone(roots), guards: completedGuards, sites, work, values };
  } catch (error) {
    if (!(error instanceof Refusal)) throw error;
    return { status: "incomplete", diagnostics: [{ code: error.code, message: error.message, location: freezeSpan(error.location) }], work, values };
  }
}
