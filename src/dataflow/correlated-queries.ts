import type { Diagnostic } from "../model.js";
import type { AbstractValue, Flow, SuccessfulPath } from "./index.js";
import { selectCorrelatedObservation, type CorrelatedEvent, type CorrelatedGraph, type CorrelatedHistory, type CorrelatedObservation, type CorrelatedTerm } from "./correlated.js";

export type CorrelatedPredicate =
  | { kind: "public-flow"; source: string; forms: readonly Flow["form"][] }
  | { kind: "missing-guard"; ledger: string; guard: string }
  | { kind: "transition"; ledger: string; from: string; to: string };
export interface CorrelatedQueryLimits { maxWork: number; maxWitnesses: number; maxProjectionWork: number; maxValues: number }
export interface CorrelatedQueryWork { query: number; projections: number; witnesses: number; values: number }
export interface CorrelatedEvidence { predicate: number; site: number; eventIndex: number; witness: number }
export type CorrelatedQueryResult =
  | { status: "complete"; evidence: CorrelatedEvidence[]; absent: number[]; witnesses: { decisions: boolean[]; path: SuccessfulPath }[]; structuralAbsence: CorrelatedGraph["structuralAbsence"]; work: CorrelatedQueryWork }
  | { status: "incomplete"; diagnostics: Diagnostic[]; work: CorrelatedQueryWork };
type Observable = Extract<CorrelatedEvent, { kind: "sink" | "write" }>;
type Presence = boolean | { choice: number; yes: Presence; no: Presence };
const defaults: CorrelatedQueryLimits = { maxWork: 20000, maxWitnesses: 256, maxProjectionWork: 20000, maxValues: 50000 };
const key = (value: AbstractValue): string | undefined => value.constant !== undefined && value.constantKind ? `${value.constantKind}:${value.constant}` : undefined;

/**
 * Finite event predicates over a trusted internal graph. Eager facts only rule
 * out candidates; every positive uses one full successful selected history.
 * Bounded choice cofactoring is not a feasibility solver. Construction costs are
 * separate and the caller must subtract them from its aggregate scan allowance.
 */
export function queryCorrelatedGraph(graph: CorrelatedGraph, predicates: readonly CorrelatedPredicate[], options: Partial<CorrelatedQueryLimits> = {}): CorrelatedQueryResult {
  const limits = { ...defaults, ...options };
  if (!options || Object.keys(options).some(name => !Object.hasOwn(defaults, name)) || !Object.values(limits).every(value => Number.isSafeInteger(value) && value > 0 && value <= 1000000)) throw new Error("Invalid correlated query limits");
  if (!Array.isArray(predicates) || predicates.some(predicate => predicate.kind === "public-flow" ? !predicate.source || !Array.isArray(predicate.forms) || predicate.forms.some((form: unknown) => typeof form !== "string" || !["raw", "derived", "hash", "commitment"].includes(form)) : predicate.kind === "missing-guard" ? !predicate.ledger || !predicate.guard : predicate.kind === "transition" ? !predicate.ledger || !predicate.from || !predicate.to : true)) throw new Error("Invalid correlated predicate");
  const work: CorrelatedQueryWork = { query: 0, projections: 0, witnesses: 0, values: 0 };
  const diagnostics: Diagnostic[] = [];
  const stop = (code: string, message: string): never => { diagnostics.push({ code, message: `${message}; correlated query results are incomplete`, location: { ...graph.location } }); throw exhausted; };
  const exhausted = Symbol("correlated-query-exhausted");
  const tick = (amount = 1): void => { work.query += amount; if (work.query + work.projections > limits.maxWork) stop("correlated-query-budget", "Aggregate query work exhausted"); };
  const retain = (): void => { if (++work.values > limits.maxValues) stop("correlated-query-value-budget", "Query graph capacity exhausted"); };
  const history = new Map<number, CorrelatedHistory>(), sites: { site: number; event: Observable }[] = [];
  const evidence: CorrelatedEvidence[] = [], absent: number[] = [], witnesses: { decisions: boolean[]; path: SuccessfulPath }[] = [];
  const projections = new Map<string, { result: CorrelatedObservation; witness?: number }>();
  try {
    if (graph.scope !== "correlated-instructions-5" || ["hash-bindings", "commitments", "failed-assertions"].some(fact => !graph.structuralAbsence.includes(fact as CorrelatedGraph["structuralAbsence"][number]))) stop("correlated-query-scope", "Unqualified correlated transfer scope");
    const pending = [graph.history];
    while (pending.length) {
      const node = pending.pop()!; tick(); if (history.has(node.id)) continue;
      retain(); history.set(node.id, node);
      if (node.kind === "choice") pending.push(node.yes, node.no);
      if (node.kind === "append") { pending.push(node.prefix); if (node.event.kind === "write" || node.event.kind === "sink") sites.push({ site: node.id, event: node.event }); }
    }
    const ordered = [...history.values()].sort((a, b) => a.id - b.id); sites.sort((a, b) => a.site - b.site);
    const presenceCache = new Map<number, Presence>();
    const presenceOf = (target: number): Presence => {
      if (presenceCache.has(target)) return presenceCache.get(target)!;
      const results = new Map<number, Presence>();
      // History IDs follow allocation order: older nodes cannot contain target.
      let low = 0, high = ordered.length;
      while (low < high) { tick(); const middle = (low + high) >>> 1; if (ordered[middle].id < target) low = middle + 1; else high = middle; }
      for (let index = low; index < ordered.length; index++) {
        const node = ordered[index];
        tick();
        let result: Presence;
        if (node.kind === "empty") result = false;
        else if (node.kind === "append") result = node.id === target ? true : results.get(node.prefix.id) ?? false;
        else {
          const yes = results.get(node.yes.id) ?? false, no = results.get(node.no.id) ?? false;
          if (yes === no) result = yes;
          else { retain(); result = { choice: node.choice, yes, no }; }
        }
        results.set(node.id, result);
      }
      const result = results.get(graph.history.id)!; retain(); presenceCache.set(target, result); return result;
    };
    const present = (formula: Presence, decisions: readonly (boolean | undefined)[], depth = 0): boolean | undefined => {
      tick(); if (depth > 512) stop("correlated-query-depth-budget", "Event presence depth exhausted");
      if (typeof formula === "boolean") return formula;
      const selected = decisions[formula.choice];
      if (selected !== undefined) return present(selected ? formula.yes : formula.no, decisions, depth + 1);
      const yes = present(formula.yes, decisions, depth + 1), no = present(formula.no, decisions, depth + 1);
      return yes === no ? yes : undefined;
    };
    const overlaps = (predicate: CorrelatedPredicate, event: Observable): boolean => predicate.kind === "public-flow" ? event.kind === "sink" : event.kind === "write" && event.ledger === predicate.ledger;
    const possible = (predicate: CorrelatedPredicate, event: Observable, cofactor: <T>(term: CorrelatedTerm<T>) => T): boolean => {
      tick();
      if (predicate.kind === "public-flow" && event.kind === "sink") return Boolean(cofactor(event.value)?.flows.some(flow => flow.source.symbol === predicate.source && predicate.forms.includes(flow.form)));
      if (event.kind !== "write") return false;
      if (predicate.kind === "missing-guard") return !event.guards[predicate.guard] || !cofactor(event.guards[predicate.guard]);
      if (predicate.kind !== "transition") return false;
      const before = cofactor(event.before), after = cofactor(event.after); if (!before || !after) return false;
      return (predicate.from === "*" || !cofactor(event.excludedBefore).includes(predicate.from) && (key(before) === undefined || key(before) === predicate.from)) && (predicate.to === "*" || key(after) === undefined || key(after) === predicate.to);
    };
    const observe = (decisions: boolean[]) => {
      const identity = decisions.map(value => value ? "1" : "0").join("");
      if (projections.has(identity)) return projections.get(identity)!;
      if (++work.witnesses > limits.maxWitnesses) stop("correlated-query-witness-budget", "Selected observation allowance exhausted");
      const remaining = Math.min(limits.maxProjectionWork - work.projections, limits.maxWork - work.query - work.projections);
      if (remaining <= 0) stop("correlated-query-projection-budget", "Aggregate selected observation work exhausted");
      const remainingValues = limits.maxValues - work.values;
      if (remainingValues <= 0) stop("correlated-query-value-budget", "Selected observation capacity exhausted");
      const result = selectCorrelatedObservation(graph, decisions, remaining, remainingValues); work.projections += result.work; work.values += result.values;
      if (result.status === "incomplete") { diagnostics.push(...result.diagnostics); throw exhausted; }
      const value: { result: CorrelatedObservation; witness?: number } = { result };
      if (result.status === "selected") { retain(); value.witness = witnesses.length; witnesses.push({ decisions: [...decisions], path: result.path }); }
      retain(); projections.set(identity, value); return value;
    };
    for (const [predicateIndex, predicate] of predicates.entries()) {
      tick(); let found = false;
      for (const { site, event } of sites) {
        tick(); if (!overlaps(predicate, event) || !possible(predicate, event, term => term.eager)) continue;
        const presence = presenceOf(site);
        const search = (decisions: (boolean | undefined)[], depth = 0): { witness: number; index: number } | undefined => {
          tick(); if (depth > 512) stop("correlated-query-depth-budget", "Candidate choice depth exhausted");
          if (present(presence, decisions) === false) return undefined;
          const cache = new Map<number, unknown>();
          const dependencies = new Set<number>();
          const cofactor = <T>(term: CorrelatedTerm<T>): T => {
            tick(); if (cache.has(term.id)) return cache.get(term.id) as T;
            let result: T;
            if (term.choiceFree) result = term.eager;
            else if (term.kind === "atom") result = term.value;
            else if (term.kind === "apply") result = term.transfer(term.inputs.map(input => cofactor(input)));
            else if (decisions[term.choice] === undefined) { dependencies.add(term.choice); result = term.merge(cofactor(term.yes), cofactor(term.no)); }
            else result = cofactor(decisions[term.choice] ? term.yes : term.no);
            retain(); cache.set(term.id, result); return result;
          };
          // The outer eager check already covers the empty assignment. Delay
          // dependency traversal unless this candidate needs choice refinement.
          if (depth > 0 && !possible(predicate, event, cofactor)) return undefined;
          const complete = decisions.map(value => value ?? false);
          // Choose a compatible presence arm before projecting. All components
          // subsequently use this same assignment, including required suffixes.
          const fill = (formula: Presence, depth = 0): boolean => {
            tick(); if (depth > 512) stop("correlated-query-depth-budget", "Candidate presence depth exhausted");
            if (typeof formula === "boolean") return formula;
            if (decisions[formula.choice] !== undefined) return fill(decisions[formula.choice] ? formula.yes : formula.no, depth + 1);
            const order = [false, true];
            for (const selected of order) {
              const previous = decisions[formula.choice]; decisions[formula.choice] = selected; complete[formula.choice] = selected;
              if (present(selected ? formula.yes : formula.no, decisions) !== false && fill(selected ? formula.yes : formula.no, depth + 1)) { decisions[formula.choice] = previous; return true; }
              decisions[formula.choice] = previous;
            }
            return false;
          };
          if (fill(presence)) {
            const observed = observe(complete);
            if (observed.result.status === "selected") {
              const occurrence = observed.result.sites.find(item => item.site === site);
              if (occurrence) {
                const path = observed.result.path;
                const matches = predicate.kind === "public-flow" && occurrence.kind === "sink" ? path.sinks[occurrence.index].value.flows.some(flow => flow.source.symbol === predicate.source && predicate.forms.includes(flow.form))
                  : occurrence.kind === "write" && predicate.kind !== "public-flow" && (predicate.kind === "missing-guard" ? !path.writes[occurrence.index].guards.includes(predicate.guard)
                    : (predicate.from === "*" || !path.writes[occurrence.index].excludedBefore.includes(predicate.from) && (key(path.writes[occurrence.index].before) === undefined || key(path.writes[occurrence.index].before) === predicate.from)) && (predicate.to === "*" || key(path.writes[occurrence.index].after) === undefined || key(path.writes[occurrence.index].after) === predicate.to));
                if (matches) return { witness: observed.witness!, index: occurrence.index };
              }
            }
          }
          if (depth === 0 && !possible(predicate, event, cofactor)) return undefined;
          // A rejected projection need not force enumeration of unrelated entry
          // flags. Prove impossibility over the shared required-success history
          // before splitting; choices left open are joined only as may-survive.
          const survival = new Map<number, boolean>();
          const survives = (node: CorrelatedHistory, depth = 0): boolean => {
            tick(); if (depth > 512) stop("correlated-query-depth-budget", "Required-success history depth exhausted");
            if (survival.has(node.id)) return survival.get(node.id)!;
            let result: boolean;
            if (node.kind === "empty") result = true;
            else if (node.kind === "append") result = (node.event.kind !== "require" || cofactor(node.event.value) !== undefined) && survives(node.prefix, depth + 1);
            else if (decisions[node.choice] !== undefined) result = survives(decisions[node.choice] ? node.yes : node.no, depth + 1);
            else result = survives(node.yes, depth + 1) || survives(node.no, depth + 1);
            retain(); survival.set(node.id, result); return result;
          };
          if (!survives(graph.history)) return undefined;
          const presenceChoice = (formula: Presence, depth = 0): number => {
            tick(); if (depth > 512) stop("correlated-query-depth-budget", "Candidate dependency depth exhausted");
            if (typeof formula === "boolean") return -1;
            if (decisions[formula.choice] === undefined) return formula.choice;
            return presenceChoice(decisions[formula.choice] ? formula.yes : formula.no, depth + 1);
          };
          const governing = presenceChoice(presence);
          // Cofactor walks transfer operands in order, visiting primary values
          // before identity/truth/control decoration. Prefer choices actually
          // demanded by this observation before the bounded all-choice fallback.
          const operand = [...dependencies].find(choice => decisions[choice] === undefined);
          const next = governing >= 0 ? governing : operand ?? decisions.findIndex(value => value === undefined);
          if (next < 0) return undefined;
          for (const selected of [false, true]) {
            const branch = [...decisions]; branch[next] = selected;
            const witness = search(branch, depth + 1); if (witness) return witness;
          }
          return undefined;
        };
        const witness = search(Array<boolean | undefined>(graph.choices.length).fill(undefined));
        if (witness) { found = true; retain(); evidence.push({ predicate: predicateIndex, site, eventIndex: witness.index, witness: witness.witness }); }
      }
      if (!found) absent.push(predicateIndex);
    }
    return { status: "complete", evidence, absent, witnesses, structuralAbsence: [...graph.structuralAbsence], work: { ...work } };
  } catch (error) {
    if (error !== exhausted) throw error;
    return { status: "incomplete", diagnostics, work: { ...work } };
  }
}
