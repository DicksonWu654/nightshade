import type { Span } from "../../src/model.js";

/** Trusted owned grammar only: this experiment is neither a source analyzer nor a solver. */
export interface Value { readonly constant?: string; readonly dependencies: readonly string[] }
export type Input = { root: string } | Value;
export type Op =
  | { kind: "write"; root: string; value: Input; location: Span }
  | { kind: "increment"; root: string; amount: number; location: Span }
  | { kind: "guard"; name: string; reads: readonly string[] }
  | { kind: "publish"; values: readonly Input[]; location: Span }
  | { kind: "reject"; location: Span }
  | { kind: "branch"; choice: string; yes: readonly Op[]; no: readonly Op[]; retainControl: boolean };
type Term<T> = Readonly<{ id: number; eager: T } & (
  | { kind: "atom"; value: T }
  | { kind: "apply"; args: readonly Term<unknown>[]; run: (args: readonly unknown[]) => T }
  | { kind: "choice"; choice: string; yes: Term<T>; no: Term<T> }
)>;
type Guards = Readonly<Record<string, Term<boolean>>>;
type Event = Readonly<
  | { kind: "write"; root: string; before: Term<Value>; after: Term<Value>; guards: Guards; location: Readonly<Span> }
  | { kind: "publish"; values: readonly Term<Value>[]; location: Readonly<Span> }
  | { kind: "reject"; location: Readonly<Span> }
>;
type History = Readonly<{ id: number } & (
  | { kind: "empty" }
  | { kind: "append"; prefix: History; event: Event }
  | { kind: "choice"; choice: string; yes: History; no: History }
)>;
interface State { roots: Record<string, Term<Value>>; guards: Guards; control: Term<Value>; history: History }
export interface Work { steps: number; nodes: number; frames: number; transfers: number }
export interface Limits { maxSteps: number; maxFrames: number; maxNodes: number }
export const LIMITS: Readonly<Limits> = Object.freeze({ maxSteps: 20000, maxFrames: 256, maxNodes: 50000 });
export interface Graph {
  readonly roots: Readonly<Record<string, Term<Value>>>;
  readonly guards: Guards;
  readonly history: History;
  readonly writes: readonly Extract<Event, { kind: "write" }>[];
  readonly choices: readonly string[];
  readonly work: Readonly<Work>;
}
export type SelectedEvent =
  | { kind: "write"; root: string; before: Value; after: Value; guards: string[]; location: Readonly<Span> }
  | { kind: "publish"; values: Value[]; location: Readonly<Span> }
  | { kind: "reject"; location: Readonly<Span> };
type Incomplete = { status: "incomplete"; diagnostic: string; work: Readonly<Work> };
class Exhausted extends Error {}
const validLimit = (n: number): boolean => Number.isSafeInteger(n) && n > 0 && n <= 1000000;
const union = (...groups: readonly (readonly string[])[]): readonly string[] => Object.freeze([...new Set(groups.flat())].sort());
export const value = (constant?: string, dependencies: readonly string[] = []): Value => Object.freeze({ constant, dependencies: union(dependencies) });
const join = (a: Value, b: Value): Value => value(a.constant === b.constant ? a.constant : undefined, union(a.dependencies, b.dependencies));

/**
 * Values, guard membership and histories share choice IDs. An arm sees already
 * joined values: transfer construction never maps over earlier assignments.
 * apply computes eager may-dependencies now and exact scalar facts at selection.
 * Only whole-root assignment, small Counter addition and declared completion are
 * modeled; unsupported input and exhaustion return no usable graph. "complete"
 * means construction completed, not all selections succeed: overflow hidden by
 * a join is explicitly incomplete when selected. Eager views may include rejected
 * suffixes and overapproximate dependencies; they never attest successful paths.
 */
export function construct(initial: Readonly<Record<string, Value>>, operations: readonly Op[], options: Partial<Limits> = {}): { status: "complete"; graph: Graph } | Incomplete {
  const limits = { ...LIMITS, ...options };
  if (Object.keys(options).some(key => !Object.hasOwn(LIMITS, key)) || !Object.values(limits).every(validLimit)) throw new Error("Invalid experiment limits");
  const work: Work = { steps: 0, nodes: 0, frames: 0, transfers: 0 };
  const tick = (): void => { if (++work.steps > limits.maxSteps) throw new Exhausted("experiment-construction-steps"); };
  const node = (): number => { tick(); if (++work.nodes > limits.maxNodes) throw new Exhausted("experiment-construction-nodes"); return work.nodes; };
  const atom = <T>(item: T): Term<T> => Object.freeze({ id: node(), kind: "atom", value: item, eager: item });
  const apply = <T>(args: readonly Term<unknown>[], eager: T, run: (items: readonly unknown[]) => T): Term<T> => Object.freeze({ id: node(), kind: "apply", args: Object.freeze([...args]), eager, run });
  const choose = <T>(choice: string, yes: Term<T>, no: Term<T>, merge: (a: T, b: T) => T): Term<T> => yes === no ? yes : Object.freeze({ id: node(), kind: "choice", choice, yes, no, eager: merge(yes.eager, no.eager) });
  const control = (item: Term<Value>, ambient: Term<Value>): Term<Value> => {
    const add = (a: Value, b: Value): Value => value(a.constant, union(a.dependencies, b.dependencies));
    return apply([item, ambient], add(item.eager, ambient.eager), ([a, b]) => add(a as Value, b as Value));
  };
  const reads = new Map<string, readonly string[]>(), choices = new Set<string>();
  const writes: Extract<Event, { kind: "write" }>[] = [];
  try {
    const yes = atom(true), no = atom(false), empty = atom(value());
    const root = (state: State, name: string): Term<Value> => {
      if (!Object.hasOwn(state.roots, name)) throw new Exhausted("experiment-unsupported-root");
      return state.roots[name];
    };
    const input = (state: State, item: Input): Term<Value> => "root" in item ? root(state, item.root) : atom(value(item.constant, item.dependencies));
    const append = (state: State, event: Event): void => { state.history = Object.freeze({ id: node(), kind: "append", prefix: state.history, event: Object.freeze(event) }); };
    const execute = (state: State, ops: readonly Op[]): State => {
      tick(); if (++work.frames > limits.maxFrames) throw new Exhausted("experiment-construction-frames");
      for (const op of ops) {
        tick(); work.transfers++;
        if (op.kind === "branch") {
          if (!op.choice) throw new Exhausted("experiment-unsupported-choice");
          choices.add(op.choice);
          const ambient = control(state.control, atom(value(undefined, [op.choice])));
          const arm = (body: readonly Op[]): State => execute({ roots: { ...state.roots }, guards: state.guards, control: ambient, history: state.history }, body);
          const left = arm(op.yes), right = arm(op.no);
          state.roots = Object.fromEntries(Object.keys(state.roots).map(name => [name, choose(op.choice, left.roots[name], right.roots[name], join)]));
          state.guards = Object.freeze(Object.fromEntries(union(Object.keys(left.guards), Object.keys(right.guards)).map(name => [name, choose(op.choice, left.guards[name] ?? no, right.guards[name] ?? no, (a, b) => a && b)])));
          state.history = Object.freeze({ id: node(), kind: "choice", choice: op.choice, yes: left.history, no: right.history });
          if (op.retainControl) state.control = choose(op.choice, left.control, right.control, join);
        } else if (op.kind === "guard") {
          if (reads.has(op.name) && JSON.stringify(reads.get(op.name)) !== JSON.stringify(op.reads)) throw new Exhausted("experiment-unsupported-guard-shape");
          op.reads.forEach(name => root(state, name)); reads.set(op.name, Object.freeze([...op.reads]));
          state.guards = Object.freeze({ ...state.guards, [op.name]: yes });
        } else if (op.kind === "write" || op.kind === "increment") {
          const before = root(state, op.root);
          let assigned: Term<Value>;
          if (op.kind === "write") assigned = input(state, op.value);
          else {
            if (!Number.isInteger(op.amount) || op.amount < 0 || op.amount > 65535) throw new Exhausted("experiment-unsupported-counter-amount");
            const amount = BigInt(op.amount);
            const increment = (v: Value): Value => {
              const next = v.constant === undefined ? undefined : BigInt(v.constant) + amount;
              if (next !== undefined && (next < 0n || next >= 1n << 64n)) throw new Exhausted("experiment-unmodeled-counter-overflow");
              return value(next?.toString(), v.dependencies);
            };
            assigned = apply([before], increment(before.eager), ([v]) => increment(v as Value));
          }
          const after = control(assigned, state.control);
          const event = Object.freeze({ kind: "write" as const, root: op.root, before, after, guards: state.guards, location: Object.freeze({ ...op.location }) });
          writes.push(event); append(state, event); state.roots[op.root] = after;
          state.guards = Object.freeze(Object.fromEntries(Object.entries(state.guards).map(([name, membership]) => [name, reads.get(name)!.includes(op.root) ? no : membership])));
        } else if (op.kind === "publish") append(state, { kind: "publish", values: Object.freeze(op.values.map(item => control(input(state, item), state.control))), location: Object.freeze({ ...op.location }) });
        else if (op.kind === "reject") append(state, { kind: "reject", location: Object.freeze({ ...op.location }) });
        else throw new Exhausted("experiment-unsupported-operation");
      }
      return state;
    };
    const state = execute({ roots: Object.fromEntries(Object.entries(initial).map(([name, item]) => [name, atom(value(item.constant, item.dependencies))])), guards: Object.freeze({}), control: empty, history: Object.freeze({ id: node(), kind: "empty" }) }, operations);
    return { status: "complete", graph: Object.freeze({ roots: Object.freeze(state.roots), guards: state.guards, history: state.history, writes: Object.freeze(writes), choices: Object.freeze([...choices]), work: Object.freeze({ ...work }) }) };
  } catch (error) {
    if (!(error instanceof Exhausted)) throw error;
    return { status: "incomplete", diagnostic: error.message, work: { ...work } };
  }
}

/** Conservative views need no enumeration; false must-membership means unproved. */
export function eager(graph: Graph) {
  const guards = (items: Guards): string[] => Object.keys(items).filter(name => items[name].eager).sort();
  return { roots: Object.fromEntries(Object.entries(graph.roots).map(([name, term]) => [name, term.eager])), guards: guards(graph.guards),
    writes: graph.writes.map(write => ({ root: write.root, before: write.before.eager, after: write.after.eager, guards: guards(write.guards), location: write.location })) };
}

/** One assignment selects every component together. This is test oracle work. */
export function select(graph: Graph, decisions: Readonly<Record<string, boolean>>, maximum = 20000):
  | { status: "selected" | "rejected"; events: SelectedEvent[]; roots?: Record<string, Value>; guards?: string[]; work: number }
  | { status: "incomplete"; diagnostic: string; work: number } {
  if (!validLimit(maximum) || Object.keys(decisions).length !== graph.choices.length || graph.choices.some(name => typeof decisions[name] !== "boolean")) throw new Error("Invalid experiment selection");
  let work = 0;
  const tick = (): void => { if (++work > maximum) throw new Exhausted("experiment-projection-budget"); };
  const cache = new Map<number, unknown>();
  const term = <T>(item: Term<T>): T => {
    tick(); if (cache.has(item.id)) return cache.get(item.id) as T;
    const result = item.kind === "atom" ? item.value : item.kind === "choice" ? term(decisions[item.choice] ? item.yes : item.no) : item.run(item.args.map(argument => term(argument)));
    cache.set(item.id, result); return result;
  };
  const guards = (items: Guards): string[] => Object.keys(items).filter(name => term(items[name])).sort();
  const events: SelectedEvent[] = [];
  let rejected = false;
  const history = (item: History): void => {
    tick();
    if (item.kind === "choice") history(decisions[item.choice] ? item.yes : item.no);
    else if (item.kind === "append") {
      history(item.prefix); if (rejected) return;
      const event = item.event;
      if (event.kind === "write") events.push({ kind: "write", root: event.root, before: term(event.before), after: term(event.after), guards: guards(event.guards), location: event.location });
      else if (event.kind === "publish") events.push({ kind: "publish", values: event.values.map(item => term(item)), location: event.location });
      else { events.push(event); rejected = true; }
    }
  };
  try {
    history(graph.history);
    if (rejected) return { status: "rejected", events, work };
    const roots = Object.fromEntries(Object.entries(graph.roots).map(([name, item]) => [name, term(item)]));
    const selectedGuards = guards(graph.guards);
    return { status: "selected", events, roots, guards: selectedGuards, work };
  } catch (error) {
    if (!(error instanceof Exhausted)) throw error;
    return { status: "incomplete", diagnostic: error.message, work };
  }
}
