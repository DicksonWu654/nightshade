import type { AssertionReach, Dataflow, SuccessfulPath, SuccessfulPredicate, SourcePreference } from "./index.js";
import { sourceEffectKey, querySourceHistory } from "./source-history.js";
import { projectEnforcedEqualities, enforcedEqualities, predicateOperandKey, publicOperand, rawWitnessSources, trustedPreimageSources } from "./predicates.js";
import type { PrivateSource } from "./index.js";
import { spanId, type Expr, type Statement } from "../model.js";
import type { Program } from "../semantic/index.js";
import { hashChoiceCandidate } from "../analysis/hash-choice.js";
import { sequenceLength } from "../semantic/types.js";
import { enforcedMerkleDigests, merkleEffectPairs } from "./merkle-enforcement.js";

/** Iterations of a bounded loop for admission estimates. A sequence loop over
 * a statically sized Vector/tuple repeats its body once per element, exactly
 * like the range form; an unknown sequence size keeps the single-pass count. */
function loopCount(program: Program, node: Extract<Statement, { kind: "for" }>): number {
  if (!node.sequence) return Number(node.end) - Number(node.start);
  const type = node.sequence.inferredType;
  return (type ? sequenceLength(program.representationOf(type)) : undefined) ?? 1;
}

/** Repeated branches or several joined expressions in stateful functions
 * distinguish expanding update histories from cheaply merging read-only helpers. Admission is not a
 * completion claim; unsuccessful attempts spend the ordinary allowance. */
export function sourceQueryCandidate(program: Program, entry: string, threshold: number, chargeWork: () => boolean, includeReadOnly = false): boolean {
  let exhausted = false, joinedExpressions = 0;
  const charge = (): boolean => {
    if (exhausted) return false;
    if (chargeWork()) return true;
    exhausted = true; return false;
  };
  const some = <T>(items: readonly T[], visit: (item: T) => boolean): boolean => {
    for (const item of items) {
      if (exhausted) return false;
      if (visit(item)) return true;
    }
    return false;
  };
  const expression = (value: Expr, repeats: number, depth: number): boolean => {
    if (depth > 64 || !charge()) return false;
    if (value.kind === "conditional" && !hashChoiceCandidate(value, program.symbols)
      || value.kind === "binary" && ["&&", "||"].includes(value.name!)) {
      joinedExpressions += repeats;
      if (joinedExpressions >= threshold) return true;
    }
    return some(value.args, arg => expression(arg, repeats, depth + 1));
  };
  const statement = (node: Statement, repeats = 1, depth = 0): boolean => {
    if (depth > 64 || !charge()) return false;
    if (node.kind === "block" || node.kind === "bindings") return some(node.body, child => statement(child, repeats, depth + 1));
    if (node.kind === "for") {
      const count = loopCount(program, node);
      if (!Number.isSafeInteger(count) || count <= 0) return false;
      return statement(node.body, Math.min(threshold, repeats * count), depth + 1);
    }
    if (node.kind === "if") return repeats >= threshold || expression(node.condition, repeats, depth + 1)
      || statement(node.then, repeats, depth + 1) || !!node.otherwise && statement(node.otherwise, repeats, depth + 1);
    return expression(node.expr, repeats, depth + 1);
  };
  const seen = new Set<string>(), pending = [entry];
  while (!exhausted && pending.length) {
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    if (!charge()) return false;
    seen.add(id);
    const fn = program.functions.get(id);
    // Read-only/pure callees can also expand joined value histories
    // (e.g. Boolean score/selection helpers); callers opt in separately.
    if (!fn || !fn.writesState.size && !includeReadOnly) continue;
    if (fn.declaration.body && statement(fn.declaration.body)) return true;
    pending.push(...fn.calls);
  }
  return false;
}

/** Fallback admission when sourceQueryCandidate declines: a callee's joined
 * expressions count once per call site, loop repeat and fold/map element that can
 * reach it, because exact interpretation re-expands each such invocation (e.g.
 * five calls of a four-candidate rejection fold). Callers charge its work only
 * when it admits an entry; admission is never a completion claim. */
export function repeatedCallCandidate(program: Program, entry: string, threshold: number, chargeWork: () => boolean, includeReadOnly = false): boolean {
  let exhausted = false;
  const charge = (): boolean => {
    if (exhausted) return false;
    if (chargeWork()) return true;
    exhausted = true; return false;
  };
  const cap = (value: number) => Math.min(threshold, value);
  interface Scan { joined: number; calls: Map<string, number>; repeatedBranch: boolean }
  const scans = new Map<string, Scan | undefined>();
  const scan = (id: string): Scan | undefined => {
    if (scans.has(id)) return scans.get(id);
    scans.set(id, undefined);
    if (!charge()) return;
    const fn = program.functions.get(id);
    // Read-only/pure callees can also expand joined value histories
    // (e.g. Boolean score/selection helpers); callers opt in separately.
    if (!fn || !fn.writesState.size && !includeReadOnly) return;
    const result: Scan = { joined: 0, calls: new Map(), repeatedBranch: false };
    // Stop scanning once this body alone saturates the threshold.
    const saturated = () => result.repeatedBranch || result.joined >= threshold;
    const call = (callee: string | undefined, repeats: number) => {
      if (callee && program.functions.has(callee)) result.calls.set(callee, cap((result.calls.get(callee) ?? 0) + repeats));
    };
    const expression = (value: Expr, repeats: number, depth: number): boolean => {
      if (depth > 64 || !charge()) return false;
      if (value.kind === "conditional" && !hashChoiceCandidate(value, program.symbols)
        || value.kind === "binary" && ["&&", "||"].includes(value.name!)) result.joined = cap(result.joined + repeats);
      if (value.kind === "call") call(value.symbol, repeats);
      if ((value.kind === "fold" || value.kind === "map") && value.args[0]) {
        const sequence = value.args[value.kind === "fold" ? 2 : 1]?.inferredType;
        const length = sequence ? sequenceLength(program.representationOf(sequence)) : undefined;
        call(value.args[0].symbol, cap(repeats * Math.max(1, length ?? 1)));
      }
      return saturated() || value.args.every(arg => expression(arg, repeats, depth + 1));
    };
    const statement = (node: Statement, repeats = 1, depth = 0): boolean => {
      if (depth > 64 || !charge()) return false;
      if (saturated()) return true;
      if (node.kind === "block" || node.kind === "bindings") return node.body.every(child => statement(child, repeats, depth + 1));
      if (node.kind === "for") {
        const count = loopCount(program, node);
        if (!Number.isSafeInteger(count) || count <= 0) return true;
        return statement(node.body, cap(repeats * count), depth + 1);
      }
      if (node.kind === "if") {
        if (repeats >= threshold) { result.repeatedBranch = true; return true; }
        return expression(node.condition, repeats, depth + 1) && statement(node.then, repeats, depth + 1) && (!node.otherwise || statement(node.otherwise, repeats, depth + 1));
      }
      return expression(node.expr, repeats, depth + 1);
    };
    if (fn.declaration.body && !statement(fn.declaration.body)) return;
    // Calls not visible as call/fold/map expressions still count once.
    if (!saturated()) for (const callee of fn.calls) if (!result.calls.has(callee)) call(callee, 1);
    scans.set(id, result);
    return result;
  };
  // Weighted totals over the (acyclic) call graph, saturating at the threshold.
  const totals = new Map<string, number>();
  const total = (id: string, depth = 0): number => {
    const known = totals.get(id);
    if (known !== undefined) return known;
    if (depth > 256 || !charge()) { exhausted = true; return 0; }
    totals.set(id, 0);
    const scanned = scan(id);
    let sum = scanned ? (scanned.repeatedBranch ? threshold : scanned.joined) : 0;
    for (const [callee, count] of scanned?.calls ?? []) {
      if (sum >= threshold || exhausted) break;
      sum = cap(sum + count * total(callee, depth + 1));
    }
    totals.set(id, sum);
    return sum;
  };
  const admitted = total(entry) >= threshold;
  return admitted && !exhausted;
}

/** A detector projection certified against conservative alternatives. The paths
 * are ordinary existence witnesses, never an enumeration of all histories. */
export interface SourceQueryEvidence {
  entry: string;
  paths: SuccessfulPath[];
  assertionReaches: AssertionReach[];
  requiredGuards: ReadonlyMap<string, ReadonlySet<string>>;
  rawOnlyEffects: ReadonlySet<string>;
  /** Set only by a view observing Merkle evidence: every conservative
   * proof-to-effect candidate has an ordinary existence witness among `paths`
   * with the same Merkle-membership finding identity, and nothing else does. */
  merkleCertified?: true;
}
export type SourceQueryResult = { status: "covered"; evidence: SourceQueryEvidence; steps: number; values: number; sources: number }
  | { status: "incomplete"; reason: string; steps: number; values: number; sources: number };

/** This deliberately refuses positive hash/commitment candidates and lost
 * predicate structure. Empty candidate sets are conservative absence proofs;
 * selected histories alone can never supply those proofs. */
export function querySourceEntry(flow: Dataflow, entry: string): SourceQueryResult {
  const view = flow.conservativeSourceView(entry);
  let steps = view.work.steps, values = view.work.values, sources = view.work.sources;
  const charge = (work: number, retained = 0): boolean => {
    steps += work; values += retained;
    return steps <= flow.maxSteps && values <= flow.maxValues;
  };
  const incomplete = (reason: string): SourceQueryResult => ({ status: "incomplete", reason, steps, values, sources });
  if (view.status !== "available" || !view.history) return incomplete("No complete conservative return history");
  if (!view.predicateStructureComplete) return incomplete("Joined Boolean expressions have unresolved predicate alternatives");
  const invocations = { witnessCalls: view.witnessCalls };
  const guardCache = new Map<SuccessfulPredicate, Set<string>>();
  // Declarations whose hash may be checked against ledger data on some history:
  // a possible preimage binding or trusted preimage. Coarse declaration/site
  // classes, never run-local source identities.
  const sourceClass = (source: PrivateSource) => JSON.stringify([source.kind, source.symbol ?? source.name, spanId(source.location)]);
  const bindingSources = new Set<string>();
  const atomicKeys = (equality: import("./predicates.js").EnforcedEquality, calls = invocations): { key: string; value: string }[] | undefined => {
    if (!charge(1)) return;
    const guards: { key: string; value: string }[] = [];
    if (!equality.equals) return guards;
    for (const [raw, available] of [[equality.left, equality.right], [equality.right, equality.left]]) {
      // Inspect every possible check, including facts absent from the must set.
      if (available.ledger.size && (raw.directHash || raw.flows.some(item => item.form === "hash"))) {
        // A hash compared with ledger data can be a preimage binding or trusted
        // preimage on some history. It is never a raw-witness guard unless the
        // (possibly joined) operand also has a raw dependency; keep refusing that.
        if (raw.flows.some(item => item.form === "raw")) return;
        for (const flow of raw.flows) if (flow.form === "hash") bindingSources.add(sourceClass(flow.source));
        if (raw.directHash) bindingSources.add(sourceClass(raw.directHash.source));
        continue;
      }
      if (!publicOperand(available)) continue;
      const sources = rawWitnessSources(raw);
      if (!sources.length) {
        if (raw.flows.some(item => item.source.kind === "witness" && item.form === "raw")) return;
        continue;
      }
      if (sources.some(source => !source.invocation || calls.witnessCalls?.get(source.invocation.site) !== 1)) return;
      const a = predicateOperandKey(raw, calls), b = predicateOperandKey(available, calls);
      if (!a || !b) return;
      if (a !== b) { const key = JSON.stringify([a, b]); guards.push({ key, value: key }); }
    }
    return guards;
  };
  let trustedPreimage = false;
  const keys = (predicates: readonly SuccessfulPredicate[], calls = invocations, cache = guardCache): Set<string> | undefined => {
    const result = new Set<string>();
    for (const predicate of predicates) {
      if (!charge(1)) return;
      let guards = cache.get(predicate);
      if (!guards) {
        const decoded = enforcedEqualities(predicate.value, predicate.truth);
        if (!charge(decoded.work) || !decoded.complete) return;
        if (decoded.equalities.some(equality => trustedPreimageSources(equality).length)) trustedPreimage = true;
        guards = new Set();
        for (const equality of decoded.equalities) {
          const projected = atomicKeys(equality, calls); if (!projected) return;
          for (const { key } of projected) guards.add(key);
        }
        cache.set(predicate, guards);
      }
      for (const key of guards) { if (!charge(1, 1)) return; result.add(key); }
    }
    return result;
  };
  const projectionCache = new Map<SuccessfulPredicate, import("./source-history.js").PredicateProjection<string> | readonly { key: string; value: string }[]>();
  const queried = querySourceHistory(view.history, charge, predicate => {
    const cached = projectionCache.get(predicate); if (cached) return cached;
    const projected = projectEnforcedEqualities(predicate.value, predicate.truth, equality => atomicKeys(equality), charge);
    if (!projected) return;
    const possible = [...projected.possible].map(([key, value]) => ({ key, value }));
    const result = projected.required.size === projected.possible.size ? possible : { possible,
      required: [...projected.required].map(([key, value]) => ({ key, value })) };
    projectionCache.set(predicate, result); return result;
  });
  if (queried.status !== "available") return incomplete(queried.reason);
  const facts = queried.facts;
  if (facts.possible.bindings.length) return incomplete("Preimage binding alternatives require a dedicated query");
  // Selector checks of compressed hash-order choices: possible, never required.
  const choiceGuards = new Set<string>();
  for (const predicate of view.choicePredicates) {
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    if (!charge(decoded.work + 1) || !decoded.complete) return incomplete("Hash-choice selector query exhausted its allowance");
    for (const equality of decoded.equalities) {
      const projected = atomicKeys(equality);
      if (!projected) return incomplete("Hash-choice selector projection is unresolved");
      for (const { key } of projected) choiceGuards.add(key);
    }
  }
  // Ledger-bound preimage publication needs a binding source published raw on
  // the same history. Possible sinks over-approximate every history's flows.
  if (bindingSources.size) for (const sink of facts.possible.sinks) for (const flow of sink.value.flows) {
    if (!charge(1)) return incomplete("Preimage publication query exhausted its allowance");
    if (flow.form === "raw" && bindingSources.has(sourceClass(flow.source))) return incomplete("A possibly ledger-bound preimage source may be published");
  }
  const tokenType = flow.program.functions.get("standard-library::tokenType")?.declaration;
  for (const sink of facts.possible.sinks) for (const commitment of sink.value.commitments ?? []) {
    if (!charge(1)) return incomplete("Commitment absence query exhausted its allowance");
    if (tokenType && commitment.location.file === tokenType.span.file
      && commitment.location.start >= tokenType.span.start && commitment.location.end <= tokenType.span.end) continue;
    if (commitment.input.flows.length) return incomplete("Private commitment alternatives require a dedicated query");
  }
  const paths: SuccessfulPath[] = [];
  const observedAssertions = new Map<string, { maySucceed: boolean; mayFail: boolean }>();
  const missingAssertionEvidence = () => view.mayReachAssertions.some(reach => {
    if (!charge(1)) return true;
    const observed = observedAssertions.get(JSON.stringify([reach.owner, spanId(reach.location)]));
    return !observed?.maySucceed || reach.mayFail && !observed.mayFail;
  });
  const preferences: SourcePreference[] = [{ first: false, alternateWitnessLeaves: true }, { first: true, alternateWitnessLeaves: true },
    { first: true, preferPresentCollections: true, evaluateBooleanRhs: true },
    { first: false, evaluateBooleanRhs: true }];
  // Routes whose alternating witness-leaf phase is complementary to the first
  // two, while still preferring present collections. Tried only when an
  // effect's optional guard has no ordinary counterexample yet; each selected
  // history is an ordinary existence witness charged to the same allowance.
  const complementary: SourcePreference[] = [{ first: true, alternateWitnessLeaves: true, witnessPhase: true, preferPresentCollections: true },
    { first: false, alternateWitnessLeaves: true, witnessPhase: true, preferPresentCollections: true }];
  const selectRoute = (preference: SourcePreference): SourceQueryResult | undefined => {
    if (!charge(1)) return incomplete("Ordinary evidence query exhausted its allowance");
    const selected = flow.selectSourceWitness(entry, preference, { steps: Math.max(0, flow.maxSteps - steps), values: Math.max(0, flow.maxValues - values) });
    sources += selected.metrics.sources;
    if (!charge(selected.metrics.steps, selected.metrics.abstractValues)) return incomplete("Ordinary evidence exhausted the shared allowance");
    if (selected.status === "incomplete") return incomplete("Ordinary source evidence is incomplete");
    if (selected.status === "selected") {
      if (paths.length >= flow.maxPaths) return incomplete("Selected histories exhausted the shared path allowance");
      paths.push(selected.path);
    }
    for (const item of selected.assertions) {
      if (!charge(1, 1)) return incomplete("Assertion query exhausted its allowance");
      const key = JSON.stringify([item.owner, spanId(item.location)]), before = observedAssertions.get(key);
      observedAssertions.set(key, { maySucceed: item.maySucceed || !!before?.maySucceed, mayFail: item.mayFail || !!before?.mayFail });
    }
    return undefined;
  };
  for (let index = 0; index < preferences.length; index++) {
    // Additional ordinary routes discharge missing reach obligations; they do
    // not change conservative universal facts or the shared allowance.
    if (index >= 2 && !missingAssertionEvidence()) break;
    const failed = selectRoute(preferences[index]);
    if (failed) return failed;
  }
  for (let attempt = 0; ; attempt++) {
    const certified = certify(attempt === 0);
    if (certified !== "retry") return certified;
    for (const preference of complementary) {
      const failed = selectRoute(preference);
      if (failed) return failed;
    }
  }
  function certify(retry: boolean): SourceQueryResult | "retry" {
  if (!paths.length) return incomplete("No ordinary successful history was selected");
  for (const reach of view.mayReachAssertions) {
    if (!charge(1)) return incomplete("Assertion query exhausted its allowance");
    const observed = observedAssertions.get(JSON.stringify([reach.owner, spanId(reach.location)]));
    // No new universally-failing claim is made by this projection. A true-only
    // conservative assertion also needs an ordinary reaching observation.
    if (!observed?.maySucceed || reach.mayFail && !observed.mayFail)
      return incomplete("An assertion classification lacks ordinary reaching evidence");
  }
  const pathGuards: Set<string>[] = [], alignedGuards: Set<string>[] = [], effects: Set<string>[] = [];
  for (const path of paths) {
    if (path.bindings.length) return incomplete("Selected history exposes an unresolved preimage binding");
    const guards = keys(path.predicates ?? [], { witnessCalls: path.witnessCalls }, new Map());
    if (!guards) return incomplete("Selected guard identities are unresolved");
    pathGuards.push(guards);
    // Compressed-choice selector guards align once per history, not per effect.
    const aligned = new Set<string>();
    for (const guard of guards) {
      if (!charge(1)) return incomplete("Guard identity query exhausted its allowance");
      if (!choiceGuards.has(guard)) aligned.add(guard);
    }
    alignedGuards.push(aligned);
    const sites = [...path.writes.map(effect => sourceEffectKey("ledger-write", effect)),
      ...(path.operations ?? []).filter(effect => effect.kind === "kernel-write").map(effect => sourceEffectKey("kernel-write", effect))];
    if (sites.some(site => site === undefined) || !charge(sites.length, sites.length)) return incomplete("Selected effect identity or allowance is unavailable");
    effects.push(new Set(sites as string[]));
  }
  const requiredGuards = new Map<string, ReadonlySet<string>>(), rawOnlyEffects = new Set<string>();
  for (const effect of facts.effects) {
    if (!charge(paths.length)) return incomplete("Effect query exhausted its allowance");
    const reaches = paths.flatMap((path, index) => effects[index].has(effect.key) ? [index] : []);
    if (!reaches.length) return incomplete("A possible effect lacks ordinary existence evidence");
    if (!charge(effect.possiblePredicates.length + effect.requiredPredicates.length, effect.possiblePredicates.length + effect.requiredPredicates.length)) return incomplete("Per-effect guards exhausted their allowance");
    const possible = new Set(effect.possiblePredicates), required = new Set(effect.requiredPredicates);
    // A trusted preimage can make a selected reach alternate-authenticated; the
    // projection then cannot certify an unprotected reach for an effect with a
    // required raw-witness guard. Possible guards over-approximate every history,
    // and each optional one needs an ordinary counterexample below, so an effect
    // without a required guard has no guard common to all its reaches: the
    // entry-wide authorization consumer cannot report that effect, whether or
    // not some reach is alternate-authenticated.
    if (trustedPreimage && required.size) return incomplete("Selected history has a trusted preimage check");
    // Ordinary selection enforces a hash selector before the later assertion;
    // that assertion may then refine to true and omit its original predicate.
    // A choice-only key cannot certify the real enforcing guard's origin.
    for (const guard of required) {
      if (!charge(1)) return incomplete("Guard-origin query exhausted its allowance");
      if (choiceGuards.has(guard)) return incomplete("A required guard shares a compressed choice-only selector; enforcement origin is unresolved");
    }
    for (const index of reaches) for (const guard of alignedGuards[index]) {
      if (!charge(1)) return incomplete("Guard identity query exhausted its allowance");
      if (!possible.has(guard)) return incomplete("Selected guard has no aligned conservative origin");
    }
    for (const guard of possible) {
      if (!charge(reaches.length)) return incomplete("Guard coverage query exhausted its allowance");
      if (required.has(guard)) {
        if (!reaches.some(index => pathGuards[index].has(guard))) return incomplete("A required guard lacks ordinary evidence");
      } else if (!reaches.some(index => !pathGuards[index].has(guard))) return retry ? "retry" : incomplete("An optional guard lacks an ordinary counterexample");
    }
    if (!view.otherChecks) rawOnlyEffects.add(effect.key);
    else if (reaches.every(index => paths[index].checkCoverage === "raw-witness-only"))
      return incomplete("Sole-gate classification lacks an ordinary counterexample");
    requiredGuards.set(effect.key, required);
  }
  const timeKey = (operation: NonNullable<SuccessfulPath["operations"]>[number]) => JSON.stringify([operation.name, spanId(operation.location), operation.callSites?.map(spanId)]);
  const selectedTime = new Set(paths.flatMap(path => (path.operations ?? []).filter(operation => operation.kind === "kernel-read").map(timeKey)));
  for (const operation of facts.possible.operations) {
    if (!charge(1)) return incomplete("Time observation query exhausted its allowance");
    if (operation.kind === "kernel-read" && ["blockTimeLessThan", "blockTimeGreaterThan"].includes(operation.name)
      && !selectedTime.has(timeKey(operation))) return incomplete("A possible time read lacks ordinary existence evidence");
  }
  const merkle = flow.observeMerkle ? certifyMerkle() : undefined;
  if (typeof merkle === "string") return incomplete(merkle);
  return { status: "covered", evidence: { entry, paths, assertionReaches: view.mayReachAssertions, requiredGuards, rawOnlyEffects, ...(merkle ? { merkleCertified: true as const } : {}) }, steps, values, sources };
  }

  /** Merkle-membership candidates are the review's proof-to-effect dependency
   * pairs over the union of possible observations, matched by coarse
   * declaration/site classes and ignoring enforcement. They over-approximate the
   * pairs of every successful history. Each candidate needs one selected history
   * reporting it with the same finding identity, so the review over the selected
   * histories reports exactly the exhaustive engine's findings. */
  function certifyMerkle(): true | string {
    if (flow.program.symbols.get(entry)!.kind === "constructor") return true;
    const identity = (pair: { root: import("./merkle-enforcement.js").MerkleRootUse; effect: import("./merkle-enforcement.js").MerkleEffectUse }) => ({
      key: JSON.stringify([spanId(pair.root.location), spanId(pair.effect.location), pair.root.origin]),
      content: JSON.stringify([pair.root.location, pair.effect.location, pair.effect.name, pair.root.callPath.length ? pair.root.callPath : pair.effect.callPath]) });
    const possible = merkleEffectPairs(flow.program, facts.possible, new Set(), item => sourceClass(item.source), Math.max(0, flow.maxSteps - steps));
    if (!charge(possible.work) || possible.status !== "complete") return "Merkle candidate query exhausted its allowance";
    const candidates = new Map<string, string>();
    for (const pair of possible.pairs) {
      if (!charge(1, 1)) return "Merkle candidate query exhausted its allowance";
      const { key, content } = identity(pair);
      if ((candidates.get(key) ?? content) !== content) return "A Merkle candidate has several finding identities";
      candidates.set(key, content);
    }
    const witnessed = new Set<string>();
    for (const path of paths) {
      const enforced = enforcedMerkleDigests(path, Math.max(0, flow.maxSteps - steps));
      if (!charge(enforced.work) || !enforced.complete) return "Selected Merkle enforcement is unresolved";
      const selected = merkleEffectPairs(flow.program, path, enforced.keys, item => item.source.id, Math.max(0, flow.maxSteps - steps));
      if (!charge(selected.work) || selected.status !== "complete") return "Selected Merkle observation query exhausted its allowance";
      for (const pair of selected.pairs) {
        if (!charge(1)) return "Selected Merkle observation query exhausted its allowance";
        const { key, content } = identity(pair);
        if (candidates.get(key) !== content) return "A selected Merkle observation lacks its conservative candidate";
        witnessed.add(key);
      }
    }
    for (const key of candidates.keys()) if (!witnessed.has(key)) return "A possible Merkle membership finding lacks ordinary existence evidence";
    return true;
  }
}
