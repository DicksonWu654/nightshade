import type { Constant } from "../../src/dataflow/constants.js";
import type { Span } from "../../src/model.js";

/** Manual, owned fixtures only. No source frontend, detector coverage or solver. */
export interface Value {
  constant?: Constant; identity?: string; dependencies: string[];
  comparison?: { operator: "==" | "!="; left: Value; right: Value }; negated?: Value;
}
export type Input = { ref: string } | { constant: Constant } | { operator: "==" | "!="; left: Input; right: Input } | { not: Input };
export type Op = { kind: "bind"; name: string; value: Input }
  | { kind: "write"; root: string; value: Input; location: Span }
  | { kind: "increment"; root: string; location: Span }
  | { kind: "branch"; name: string; condition: Input; yes: Op[]; no: Op[] };
interface Constraints { known: Record<string, Constant>; excluded: Record<string, string[]>; truths: Record<string, boolean> }
type Term<T> = { id: number; eager: T; depth: number } & (
  { kind: "atom"; value: T } | { kind: "apply"; inputs: Term<unknown>[]; run: (values: unknown[]) => T }
  | { kind: "choice"; name: string; yes: Term<T>; no: Term<T> });
type Scalar = Term<Value | undefined>;
type Facts = Term<Constraints | undefined>;
interface Write { root: string; before: Scalar; after: Scalar; constraints: Facts; location: Span }
type History = { kind: "empty" } | { kind: "write"; previous: History; write: Write }
  | { kind: "require"; previous: History; constraints: Facts }
  | { kind: "choice"; name: string; yes: History; no: History };
interface State { env: Record<string, Scalar>; roots: Record<string, Scalar>; constraints: Facts; constraintParameters: ReadonlySet<string>; control: Scalar; history: History }
export interface Work { steps: number; nodes: number; frames: number }
export interface Graph { history: History; roots: Record<string, Scalar>; constraints: Facts; conditions: Record<string, Scalar>; choices: string[]; work: Work }
export interface Observation { root: string; before?: string; after?: string; excludedBefore: string[]; dependencies: string[]; location: Span }
const union = (...values: string[][]): string[] => [...new Set(values.flat())].sort();
const key = (value: Constant): string => `${value.kind}:${value.value}`;
const same = (a: Constant | undefined, b: Constant | undefined): boolean => a !== undefined && b !== undefined && key(a) === key(b);
const refine = (value: Value, constraints: Constraints): Value => !value.identity ? value : constraints.known[value.identity]
  ? { ...value, constant: constraints.known[value.identity] } : Object.hasOwn(constraints.truths, value.identity)
    ? { ...value, constant: { kind: "boolean", value: String(constraints.truths[value.identity]) } } : value;
const common = <T>(a: Record<string, T>, b: Record<string, T>, equal: (a: T, b: T) => boolean): Record<string, T> => Object.fromEntries(Object.entries(a).filter(([name, value]) => Object.hasOwn(b, name) && equal(value, b[name])));
function must(a: Constraints | undefined, b: Constraints | undefined): Constraints | undefined {
  if (!a) return b; if (!b) return a;
  return { known: common(a.known, b.known, same), truths: common(a.truths, b.truths, (a, b) => a === b),
    excluded: Object.fromEntries(Object.entries(a.excluded).map(([name, values]) => [name, values.filter(value => b.excluded[name]?.includes(value))]).filter(([, values]) => values.length)) };
}
function may(a: Value | undefined, b: Value | undefined): Value | undefined {
  if (!a) return b; if (!b) return a;
  return { dependencies: union(a.dependencies, b.dependencies), constant: same(a.constant, b.constant) ? a.constant : undefined, identity: a.identity === b.identity ? a.identity : undefined };
}
function assume(value: Value, truth: boolean, input: Constraints): Constraints | undefined {
  const state = { known: { ...input.known }, excluded: Object.fromEntries(Object.entries(input.excluded).map(([name, items]) => [name, [...items]])), truths: { ...input.truths } };
  const visit = (value: Value, truth: boolean): boolean => {
    const current = refine(value, state);
    if (current.constant?.kind === "boolean" && current.constant.value !== String(truth)) return false;
    if (value.negated && !visit(value.negated, !truth)) return false;
    if (value.identity) {
      if (Object.hasOwn(state.truths, value.identity) && state.truths[value.identity] !== truth) return false;
      state.truths[value.identity] = truth; state.known[value.identity] = { kind: "boolean", value: String(truth) };
    }
    if (value.comparison) {
      const { left, right, operator } = value.comparison, equal = operator === "==" ? truth : !truth;
      const a = refine(left, state), b = refine(right, state);
      const known = a.constant && b.constant ? same(a.constant, b.constant) : a.identity && a.identity === b.identity ? true : undefined;
      if (known !== undefined && known !== equal) return false;
      for (const [subject, counterpart] of [[left, right], [right, left]]) {
        const constant = refine(counterpart, state).constant; if (!subject.identity || !constant) continue;
        const excluded = state.excluded[subject.identity] ?? [];
        if (equal) { if (excluded.includes(key(constant))) return false; state.known[subject.identity] = constant; }
        else state.excluded[subject.identity] = union(excluded, [key(constant)]);
      }
    }
    return true;
  };
  return visit(value, truth) ? state : undefined;
}
class Incomplete extends Error {}

/** Whole constraint maps are one shared term; eager maps retain only common must-facts. */
export function construct(parameters: string[], roots: string[], operations: Op[], options: Partial<{ maxSteps: number; maxFrames: number; maxNodes: number }> = {}, indexed = false): { status: "complete"; graph: Graph } | { status: "incomplete"; diagnostic: string; work: Work } {
  const limits = { maxSteps: 20000, maxFrames: 256, maxNodes: 50000, ...options }, work: Work = { steps: 0, nodes: 0, frames: 0 };
  const tick = (): void => { if (++work.steps > limits.maxSteps) throw new Incomplete("predicate-experiment-step-budget"); };
  const node = (): number => { tick(); if (++work.nodes > limits.maxNodes) throw new Incomplete("predicate-experiment-value-budget"); return work.nodes; };
  const atom = <T>(value: T): Term<T> => ({ id: node(), depth: 0, kind: "atom", value, eager: value });
  const apply = <T>(inputs: Term<unknown>[], run: (values: unknown[]) => T): Term<T> => {
    const depth = Math.max(0, ...inputs.map(input => input.depth)) + 1;
    if (depth > 512) throw new Incomplete("predicate-experiment-depth-budget");
    return { id: node(), depth, kind: "apply", inputs, run, eager: run(inputs.map(input => input.eager)) };
  };
  const choose = <T>(name: string, yes: Term<T>, no: Term<T>, merge: (a: T, b: T) => T): Term<T> => yes === no ? yes : ({ id: node(), depth: Math.max(yes.depth, no.depth) + 1, kind: "choice", name, yes, no, eager: merge(yes.eager, no.eager) });
  const conditions: Record<string, Scalar> = {}, choices: string[] = [];
  try {
    const parameterValues = Object.fromEntries(parameters.map(name => [name, atom<Value | undefined>({ dependencies: [name], identity: `parameter:${name}` })]));
    const support = (...groups: Iterable<string>[]): ReadonlySet<string> => {
      const result = new Set<string>();
      if (indexed) for (const group of groups) for (const name of group) {
        tick(); if (!result.has(name)) { node(); result.add(name); }
      }
      return result;
    };
    const blank = atom<Value | undefined>({ dependencies: [] });
    const controlled = (value: Scalar, control: Scalar): Scalar => apply([value, control], ([v, c]) => v && c ? { ...(v as Value), dependencies: union((v as Value).dependencies, (c as Value).dependencies) } : undefined);
    const read = (state: State, name: string): Scalar => {
      const value = state.roots[name] ?? state.env[name]; if (!value) throw new Incomplete("predicate-experiment-unknown-value");
      // In this owned grammar, an assumption can constrain an original input
      // only if that input occurs in its may-dependencies. Skip map lookup for
      // a provably untouched original atom. Aliases and changed bindings keep
      // ordinary map refinement. Required-history checks still reject prefixes;
      // demanding a condition alone never proves a successful history.
      if (indexed && value === parameterValues[name] && !state.constraintParameters.has(name)) {
        tick(); return state.constraints.eager === undefined ? atom<Value | undefined>(undefined) : value;
      }
      return apply([value, state.constraints], ([value, constraints]) => value && constraints ? refine(value as Value, constraints as Constraints) : undefined);
    };
    const evaluate = (state: State, expression: Input): Scalar => {
      tick();
      if ("ref" in expression) return read(state, expression.ref);
      if ("constant" in expression) return atom<Value | undefined>({ dependencies: [], constant: expression.constant });
      if ("not" in expression) return apply([evaluate(state, expression.not)], ([value]) => {
        if (!value) return undefined; const v = value as Value;
        return { dependencies: v.dependencies, negated: v, identity: v.identity ? `!${v.identity}` : undefined,
          constant: v.constant?.kind === "boolean" ? { kind: "boolean" as const, value: String(v.constant.value !== "true") } : undefined };
      });
      return apply([evaluate(state, expression.left), evaluate(state, expression.right)], ([left, right]) => {
        if (!left || !right) return undefined; const a = left as Value, b = right as Value;
        const identities = [a.constant ? key(a.constant) : a.identity, b.constant ? key(b.constant) : b.identity];
        const equal = a.constant && b.constant ? same(a.constant, b.constant) : a.identity && a.identity === b.identity ? true : undefined;
        return { dependencies: union(a.dependencies, b.dependencies), identity: identities.every(Boolean) ? `${expression.operator}:${JSON.stringify(identities.sort())}` : undefined,
          comparison: { operator: expression.operator, left: a, right: b }, constant: equal === undefined ? undefined : { kind: "boolean" as const, value: String(expression.operator === "==" ? equal : !equal) } };
      });
    };
    const execute = (state: State, ops: Op[]): State => {
      if (++work.frames > limits.maxFrames) throw new Incomplete("predicate-experiment-frame-budget");
      for (const op of ops) {
        tick();
        if (op.kind === "bind") state.env[op.name] = controlled(evaluate(state, op.value), state.control);
        else if (op.kind === "write" || op.kind === "increment") {
          const before = read(state, op.root);
          const assigned = op.kind === "write" ? evaluate(state, op.value) : apply([before], ([value]) => {
            if (!value) return undefined; const current = value as Value;
            if (current.constant && BigInt(current.constant.value) + 1n >= 1n << 64n) return undefined;
            return { dependencies: current.dependencies, constant: current.constant ? { kind: "integer" as const, value: String(BigInt(current.constant.value) + 1n) } : undefined };
          });
          const after = controlled(assigned, state.control);
          state.history = { kind: "write", previous: state.history, write: { root: op.root, before, after, constraints: state.constraints, location: op.location } };
          // A site identity suffices only for this acyclic, once-per-site grammar.
          state.roots[op.root] = apply([after], ([value]) => value ? { ...(value as Value), identity: (value as Value).identity ?? `write:${op.location.start}` } : undefined);
        } else {
          if (choices.includes(op.name)) throw new Incomplete("predicate-experiment-repeated-site");
          choices.push(op.name); const condition = evaluate(state, op.condition); conditions[op.name] = condition;
          const constraintParameters = support(state.constraintParameters, condition.eager?.dependencies ?? []);
          const arm = (truth: boolean, body: Op[]): State => {
            const constraints = apply([state.constraints, condition], ([facts, value]) => facts && value ? assume(value as Value, truth, facts as Constraints) : undefined);
            return execute({ ...state, roots: { ...state.roots }, env: { ...state.env }, constraints, constraintParameters, control: controlled(condition, state.control), history: { kind: "require", previous: state.history, constraints } }, body);
          };
          const yes = arm(true, op.yes), no = arm(false, op.no);
          state.roots = Object.fromEntries(Object.keys(state.roots).map(root => [root, choose(op.name, yes.roots[root], no.roots[root], may)]));
          state.env = Object.fromEntries(Object.keys(state.env).map(name => [name, choose(op.name, yes.env[name], no.env[name], may)]));
          state.constraints = choose(op.name, yes.constraints, no.constraints, must);
          state.constraintParameters = support(yes.constraintParameters, no.constraintParameters);
          state.control = choose(op.name, yes.control, no.control, may);
          state.history = { kind: "choice", name: op.name, yes: yes.history, no: no.history };
        }
      }
      return state;
    };
    const state = execute({ env: parameterValues,
      roots: Object.fromEntries(roots.map(root => [root, atom<Value | undefined>({ dependencies: [], identity: `ledger:${root}:0` })])),
      constraints: atom<Constraints | undefined>({ known: {}, excluded: {}, truths: {} }), constraintParameters: new Set(), control: blank, history: { kind: "empty" } }, operations);
    return { status: "complete", graph: { ...state, conditions, choices, work: { ...work } } };
  } catch (error) {
    if (!(error instanceof Incomplete)) throw error;
    return { status: "incomplete", diagnostic: error.message, work: { ...work } };
  }
}

/** A condition-only projection measures demand; it does not attest a successful history. */
export function project(graph: Graph, decisions: Record<string, boolean>, condition?: string, maximum = 20000): { status: "selected"; writes: Observation[]; value?: Value; work: number; terms: number; choices: string[] } | { status: "rejected" | "incomplete"; work: number; terms: number; choices: string[] } {
  let work = 0; const cache = new Map<number, unknown>(), demanded = new Set<string>();
  const tick = (): void => { if (++work > maximum) throw new Incomplete("predicate-experiment-projection-budget"); };
  const term = <T>(input: Term<T>): T => {
    tick(); if (cache.has(input.id)) return cache.get(input.id) as T;
    if (input.kind === "choice") { if (typeof decisions[input.name] !== "boolean") throw new Error("Missing choice"); demanded.add(input.name); }
    const value = input.kind === "atom" ? input.value : input.kind === "choice" ? term(decisions[input.name] ? input.yes : input.no) : input.run(input.inputs.map(term));
    cache.set(input.id, value); return value;
  };
  const stats = () => ({ work, terms: cache.size, choices: [...demanded].sort() });
  try {
    if (condition) { const value = term(graph.conditions[condition]); return value ? { status: "selected", writes: [], value, ...stats() } : { status: "rejected", ...stats() }; }
    const events: Exclude<History, { kind: "choice" | "empty" }>[] = []; let history = graph.history;
    while (history.kind !== "empty") { tick(); if (history.kind === "choice") history = decisions[history.name] ? history.yes : history.no; else { events.push(history); history = history.previous; } }
    const writes: Observation[] = [];
    for (const event of events.reverse()) {
      tick();
      if (event.kind === "require") { if (!term(event.constraints)) return { status: "rejected", ...stats() }; }
      else {
        const before = term(event.write.before), after = term(event.write.after), constraints = term(event.write.constraints);
        if (!before || !after || !constraints) return { status: "rejected", ...stats() };
        writes.push({ root: event.write.root, before: before.constant ? key(before.constant) : undefined, after: after.constant ? key(after.constant) : undefined,
          excludedBefore: before.identity ? [...(constraints.excluded[before.identity] ?? [])].sort() : [], dependencies: after.dependencies, location: event.write.location });
      }
    }
    if (!term(graph.constraints)) return { status: "rejected", ...stats() };
    return { status: "selected", writes, ...stats() };
  } catch (error) {
    if (!(error instanceof Incomplete)) throw error;
    return { status: "incomplete", ...stats() };
  }
}
