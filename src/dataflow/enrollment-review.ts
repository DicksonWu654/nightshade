import { identityLength } from "../semantic/metering.js";
import type { AbstractValue, AnalysisFacts, PrivateSource, RuntimeOperation, StateWrite, SuccessfulPath } from "./index.js";
import type { EnrollmentScope, EnrollmentCharge } from "../semantic/enrollment-review.js";
import { enrollmentParameter, enrollmentReviewScope, STORED_ENROLLMENT_RULE } from "../semantic/enrollment-review.js";
import { persistentSignatureKeySnapshot, signatureKeyIdentityExclusions } from "./signature-key.js";
import { immutableOperandKey } from "./immutable-key.js";
import { enforcedEqualities } from "./predicates.js";
import { schnorrVerifier } from "../semantic/signature-targets.js";
import type { Diagnostic } from "../model.js";

export interface EnrollmentObservation {
  writerEntry: string; write: StateWrite; parameter: PrivateSource;
  useEntry: string; use: RuntimeOperation;
}
export interface EnrollmentReviewEvidence extends EnrollmentScope {
  maxSteps: number; maxValues: number; maxPaths: number;
  outcomes: readonly { entry: string; histories: number }[];
}

/** Dynamic Boolean relays are outside this first outcome proof. A represented
 * relay containing the exact occurrence is unavailable, never a quiet result. */
function containsOutcome(value: AbstractValue, occurrence: string, charge: EnrollmentCharge, depth = 0): boolean {
  charge(); if (depth > 32) throw new Error("Verifier relay dependency depth is unavailable");
  if (value.enrollmentSignatureOutcome === occurrence) return true;
  for (const input of value.enrollmentConjunctionInputs ?? [])
    if (containsOutcome(input, occurrence, charge, depth + 1)) return true;
  for (const item of value.items ?? [])
    if (containsOutcome(item, occurrence, charge, depth + 1)) return true;
  for (const name in value.fields) if (Object.hasOwn(value.fields, name)) {
    charge();
    if (containsOutcome(value.fields[name], occurrence, charge, depth + 1)) return true;
  }
  if (value.negated && containsOutcome(value.negated, occurrence, charge, depth + 1)) return true;
  if (value.comparison && (containsOutcome(value.comparison.left, occurrence, charge, depth + 1)
    || containsOutcome(value.comparison.right, occurrence, charge, depth + 1))) return true;
  return false;
}

/** Actual occurrence result, not another verifier or an input dependency. */
function enforcedOutcome(value: AbstractValue, truth: boolean, occurrence: string, charge: EnrollmentCharge, depth = 0): boolean {
  charge(); if (depth > 32) throw new Error("Verifier outcome predicate depth is unavailable");
  if (value.predicateStructureLost || value.predicateHasAlternatives || value.predicateAlternatives)
    throw new Error("Verifier outcome predicate structure is unavailable");
  // Check retained operands before any RHS marker inherited by the logical
  // result. Every asserted-true operand matters, even after one proves the
  // occurrence: another may expose an unsupported relay of that same result.
  if (value.enrollmentConjunctionInputs) {
    if (truth) {
      let enforced = false;
      for (const input of value.enrollmentConjunctionInputs)
        if (enforcedOutcome(input, true, occurrence, charge, depth + 1)) enforced = true;
      return enforced;
    }
    if (containsOutcome(value, occurrence, charge, depth + 1))
      throw new Error("Negated verifier conjunction enforcement is unavailable");
    return false;
  }
  if (value.enrollmentSignatureOutcome) return value.enrollmentSignatureOutcome === occurrence && truth;
  if (value.negated) return enforcedOutcome(value.negated, !truth, occurrence, charge, depth + 1);
  if (value.comparison) {
    const { left, right, operator } = value.comparison;
    charge(2);
    if (right.constantKind === "boolean" && right.constant !== undefined)
      return enforcedOutcome(left, (operator === "==" ? truth : !truth) === (right.constant === "true"), occurrence, charge, depth + 1);
    if (left.constantKind === "boolean" && left.constant !== undefined)
      return enforcedOutcome(right, (operator === "==" ? truth : !truth) === (left.constant === "true"), occurrence, charge, depth + 1);
    if (containsOutcome(left, occurrence, charge, depth + 1) || containsOutcome(right, occurrence, charge, depth + 1))
      throw new Error("Dynamic verifier Boolean relay enforcement is unavailable");
  }
  return false;
}

function point(facts: AnalysisFacts, value: AbstractValue): boolean {
  const type = facts.program.representationOf(value.type ?? "");
  return type === "JubjubPoint" || type === 'Opaque<"JubjubPoint">';
}

function supplied(facts: AnalysisFacts, entry: string, value: AbstractValue, charge: EnrollmentCharge): PrivateSource | undefined {
  charge(1 + value.flows.length);
  if (!point(facts, value) || !value.identity || value.constant !== undefined || value.fields || value.items
    || value.negated || value.comparison || value.ordering || value.pointIdentityInput || value.pointIdentityEvidenceLost) return;
  const raw = value.flows.find(flow => flow.form === "raw" && flow.source.id === value.identity)?.source;
  return raw && enrollmentParameter(facts.program, entry, raw, charge) ? raw : undefined;
}

/** The absence claim is about qualified represented identity constraints only.
 * Relevant opaque predicates cannot supply compatibility/absence evidence. */
function exclusion(facts: AnalysisFacts, path: SuccessfulPath, target: AbstractValue, charge: EnrollmentCharge, remaining: () => number): boolean {
  charge(0, 2);
  const operand = immutableOperandKey(target, Math.min(4096, remaining()), undefined, charge);
  if (!operand.complete || !operand.key) throw new Error("Enrollment point immutable identity is unavailable");
  if (!path.predicates) throw new Error("Enrollment predicate history is unavailable");
  charge(0, 1); const closurePredicates: NonNullable<SuccessfulPath["predicates"]> = [];
  const relevant = (value: AbstractValue): boolean => {
    charge(0, 3); const seen = new Set<AbstractValue>(), pending = [{ value, depth: 0 }];
    let found = false;
    while (pending.length) {
      const part = pending.pop()!; charge(1 + part.value.flows.length + part.value.ledger.size);
      if (part.depth > 32) throw new Error("Relevant point dependency depth is unavailable");
      if (seen.has(part.value)) continue; charge(0, 1); seen.add(part.value);
      if (part.value.enrollmentSignatureOutcome) continue;
      found ||= !!target.identity && part.value.flows.some(flow => flow.source.id === target.identity);
      for (const root of target.preexistingLedger ?? []) { charge(); found ||= part.value.ledger.has(root); }
      const push = (child: AbstractValue) => { charge(1, 2); pending.push({ value: child, depth: part.depth + 1 }); };
      for (const child of part.value.enrollmentPointInputs ?? []) push(child);
      for (const child of part.value.items ?? []) push(child);
      for (const name in part.value.fields) if (Object.hasOwn(part.value.fields, name)) push(part.value.fields[name]);
      if (part.value.comparison) { push(part.value.comparison.left); push(part.value.comparison.right); }
      if (part.value.negated) push(part.value.negated);
      if (part.value.pointIdentityInput) push(part.value.pointIdentityInput);
      if (part.value.ordering) { push(part.value.ordering.left); push(part.value.ordering.right); }
    }
    return found;
  };
  for (const predicate of path.predicates) {
    charge();
    if (predicate.value.enrollmentSignatureOutcome) continue;
    const touches = relevant(predicate.value);
    if (!touches && (predicate.value.predicateStructureLost || predicate.value.predicateHasAlternatives || predicate.value.predicateAlternatives)) continue;
    charge(0, 1); closurePredicates.push(predicate);
    if (!touches) continue;
    const decoded = enforcedEqualities(predicate.value, predicate.truth, charge);
    if (!decoded.complete || predicate.value.predicateStructureLost || predicate.value.predicateHasAlternatives)
      throw new Error("Relevant enrollment predicate structure is unavailable");
    let classified = false;
    for (const relation of decoded.equalities) {
      charge();
      if (relation.left.enrollmentSignatureOutcome || relation.right.enrollmentSignatureOutcome) { classified = true; continue; }
      if (point(facts, relation.left) && point(facts, relation.right)) {
        const left = immutableOperandKey(relation.left, Math.min(4096, remaining()), undefined, charge);
        const right = immutableOperandKey(relation.right, Math.min(4096, remaining()), undefined, charge);
        if (!left.complete || !right.complete || !left.key || !right.key) throw new Error("Relevant point relation has unavailable operands");
        classified = true;
      }
    }
    if (!classified) throw new Error("A relevant opaque point predicate cannot establish identity compatibility");
  }
  charge(0, 1);
  const closure = signatureKeyIdentityExclusions({ ...path, predicates: closurePredicates }, remaining(), charge);
  if (!closure.complete) throw new Error("Mandatory point identity closure is unavailable or exhausted");
  return closure.excluded.has(operand.key);
}

export function enrollmentReviewObservations(facts: AnalysisFacts) {
  const observations: EnrollmentObservation[] = [], diagnostics: Diagnostic[] = [];
  const evidence = facts.enrollmentReviewEvidence;
  if (!evidence) {
    diagnostics.push({ code: "enrollment-review-evidence-unavailable", message: "Complete enrollment writer/use observation is unavailable", location: facts.program.rootSource.ast.span });
    return { observations, diagnostics };
  }
  let work = 0, retained = 0;
  const remaining = () => Math.max(0, evidence.maxSteps - facts.metrics.steps - work);
  const charge: EnrollmentCharge = (amount = 1, values = 0) => {
    work += amount; retained += values;
    if (facts.metrics.steps + work > evidence.maxSteps || facts.metrics.abstractValues + retained > evidence.maxValues)
      throw new Error("Enrollment proof exhausted its shared work/value allowance");
    return true;
  };
  Object.assign(charge, { identityText: facts.program.meteringIdentity });
  try {
    charge(0, 4);
    if (!facts.signatureEvidence || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states" || facts.diagnostics.length)
      throw new Error("Complete original enrollment and verifier histories are unavailable");
    const inventory = enrollmentReviewScope(facts.program, charge);
    const same = (left: readonly string[], right: readonly string[]) => {
      charge(left.length + right.length);
      return left.length === right.length && left.every((id, index) => id === right[index]);
    };
    if (!same(inventory.entries, evidence.entries) || !same(inventory.cells, evidence.cells)
      || !same(inventory.uses, evidence.uses) || !same(inventory.constructors, evidence.constructors))
      throw new Error("Enrollment writer/use inventory is incomplete or inconsistent");
    for (const cell of inventory.cells) if (!same(inventory.writers.get(cell)!, evidence.writers.get(cell) ?? []))
      throw new Error("Enrollment all-writer inventory is incomplete");
    if (!evidence.outcomes || evidence.outcomes.length !== evidence.entries.length) throw new Error("Enrollment outcome coverage is unavailable");
    for (const [index, entry] of evidence.entries.entries()) {
      charge(facts.paths.length + 1);
      let histories = 0; for (const path of facts.paths) if (path.entry === entry) histories++;
      if (evidence.outcomes[index].entry !== entry || evidence.outcomes[index].histories !== histories)
        throw new Error("Enrollment original outcome coverage is inconsistent");
    }
    for (const entry of evidence.entries) { charge(facts.completedEntries.length); if (!facts.completedEntries.includes(entry)) throw new Error("A dependent writer/use entry did not complete"); }
    if (facts.paths.length > evidence.maxPaths) throw new Error("Enrollment retained path allowance exhausted");
    charge(0, 2);
    const writers: { entry: string; write: StateWrite; parameter: PrivateSource }[] = [];
    const uses: { entry: string; use: RuntimeOperation; root: string }[] = [];
    for (const path of facts.paths) {
      charge(0, 1);
      if (!evidence.entries.includes(path.entry) || !path.predicates) throw new Error("Unexpected or incomplete enrollment history");
      if (!path.enrollmentHistory || path.enrollmentHistory.writes !== path.writes.length
        || path.enrollmentHistory.operations !== (path.operations?.length ?? 0) || path.enrollmentHistory.predicates !== path.predicates.length)
        throw new Error("Enrollment original history row coverage is unavailable");
      charge(0, 1); const final = new Map<string, StateWrite>();
      for (const write of path.writes) {
        charge(1 + evidence.cells.length);
        if (!evidence.cells.includes(write.ledger)) continue;
        if (write.region.length) throw new Error("Whole-Cell enrollment has an unsupported projected mutation");
        charge(0, 1); final.set(write.ledger, write);
      }
      for (const write of final.values()) {
        charge();
        if (!write.callSites || write.callSites.length !== write.callPath.length || write.enrollmentWriteObserved !== true)
          throw new Error("Final whole-Cell write identity observation is unavailable");
        const source = supplied(facts, path.entry, write.after, charge);
        if (!source) {
          // Transformed/witness writes cannot establish this narrow writer
          // premise. Lost point identity evidence cannot certify any absence.
          if (write.after.pointIdentityEvidenceLost) throw new Error("Final native point evidence is unavailable");
          continue;
        }
        const excluded = exclusion(facts, path, write.after, charge, remaining);
        if (excluded) continue;
        charge(0, 4); writers.push({ entry: path.entry, write, parameter: source });
      }
      for (const use of path.operations ?? []) {
        charge();
        if (use.kind !== "signature-verification" || !schnorrVerifier(use.name)) continue;
        const key = use.args[2], root = key && persistentSignatureKeySnapshot(key);
        if (!root || !evidence.cells.includes(root)) continue;
        if (typeof use.signatureKeyExcludesIdentity !== "boolean" || !use.result.enrollmentSignatureOutcome)
          throw new Error("Canonical verifier outcome/exclusion evidence is unavailable");
        let enforced = false;
        for (const predicate of path.predicates) { charge(); if (predicate.assertionGate && enforcedOutcome(predicate.value, predicate.truth, use.result.enrollmentSignatureOutcome, charge)) enforced = true; }
        if (!enforced) continue;
        const excluded = exclusion(facts, path, key, charge, remaining);
        if (use.signatureKeyExcludesIdentity || excluded) continue;
        charge(0, 3); uses.push({ entry: path.entry, use, root });
      }
    }
    for (const writer of writers) for (const use of uses) {
      charge(); if (writer.write.ledger !== use.root) continue;
      // Charge result, metadata and copied trace/callsite evidence before emission.
      let emission = 160 + writer.write.callPath.length * 8 + writer.write.callSites!.length * 8 + use.use.callPath.length * 8;
      charge(0, 8 + writer.write.callPath.length + use.use.callPath.length + evidence.entries.length + evidence.constructors.length);
      for (const text of [writer.entry, use.entry, writer.write.ledger, writer.parameter.id, ...writer.write.callPath, ...use.use.callPath,
        ...evidence.entries, ...evidence.constructors, writer.parameter.location.file, writer.write.location.file, use.use.location.file]) { charge(); emission += Math.ceil(identityLength(text, charge) / 64) * 4; }
      charge(emission, emission);
      observations.push({ writerEntry: writer.entry, write: writer.write, parameter: writer.parameter, useEntry: use.entry, use: use.use });
    }
  } catch (error) {
    observations.length = 0;
    // Failure reporting is fixed-size after proof admission has been exhausted.
    // The outer observer marks every admitted dependent coverage row incomplete.
    const entry = evidence.entries[0];
    diagnostics.push({ code: "enrollment-review-evidence-unavailable",
      message: `${error instanceof Error ? error.message : String(error)}; complete enrollment proof for all ${evidence.entries.length} dependent entries is unavailable`,
      location: entry ? facts.program.functions.get(entry)!.declaration.span : facts.program.rootSource.ast.span,
      ...(entry ? { scope: { kind: "rule" as const, detectorId: STORED_ENROLLMENT_RULE, entry } } : {}) });
  } finally { facts.metrics.steps += work; facts.metrics.abstractValues += retained; }
  return { observations, diagnostics };
}
