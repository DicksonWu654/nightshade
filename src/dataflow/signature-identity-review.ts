import type { AbstractValue, AnalysisFacts, RuntimeOperation, SuccessfulPath } from "./index.js";
import { immutableOperandKey } from "./immutable-key.js";
import { persistentSignatureKeySnapshot, signatureKeyIdentityExclusions } from "./signature-key.js";
import { enforcedEqualities } from "./predicates.js";
import { SIGNATURE_IDENTITY_REVIEW, signatureIdentityScope, signaturePointCurve, signatureVerifierCurve, type SignatureCharge, type SignatureCurve } from "../semantic/signature-targets.js";
import type { Diagnostic } from "../model.js";

export interface SignatureIdentityObservation {
  entry: string; operation: RuntimeOperation; curve: SignatureCurve;
  source: { kind: "caller-key" | "persistent-cell-snapshot"; symbol: string };
}

/** Only exact raw caller operands and whole native persistent Cell snapshots.
 * Dependency overlap and collection may-alias regions never identify keys. */
function sourceOf(facts: AnalysisFacts, path: SuccessfulPath, value: AbstractValue, curve: SignatureCurve, charge: SignatureCharge) {
  charge(1 + value.flows.length);
  if (value.pointIdentityInput || value.pointIdentityEvidenceLost || value.fields || value.items) return;
  // Legacy snapshot helper makes a bounded one-element Set copy. Reserve it
  // here so ordinary callers retain their existing helper cost/behavior.
  charge(0, 2);
  const root = persistentSignatureKeySnapshot(value);
  if (root) {
    const symbol = facts.program.symbols.get(root);
    if (symbol?.kind === "ledger" && signaturePointCurve(facts.program, symbol.type) === curve) {
      charge(0, 2); return { kind: "persistent-cell-snapshot" as const, symbol: root };
    }
    return;
  }
  for (const flow of value.flows) {
    charge(); const source = flow.source;
    if (flow.form !== "raw" || source.kind !== "entry-parameter" || !source.symbol || source.id !== value.identity) continue;
    for (const parameter of facts.program.functions.get(path.entry)!.declaration.parameters) {
      charge();
      if (parameter.symbol === source.symbol && signaturePointCurve(facts.program, parameter.type) === curve) {
        charge(0, 2); return { kind: "caller-key" as const, symbol: source.symbol };
      }
    }
  }
}

/** Mandatory typed point constraints on a complete original history. Opaque
 * predicates that touch this operand cannot certify absence or compatibility. */
function excluded(facts: AnalysisFacts, path: SuccessfulPath, target: AbstractValue, curve: SignatureCurve,
  charge: SignatureCharge, remaining: () => number): boolean {
  charge(0, 2);
  const operand = immutableOperandKey(target, Math.min(4096, remaining()), undefined, charge);
  if (!operand.complete || !operand.key || !path.predicates) throw new Error("Exact immutable key or predicate history is unavailable");
  const point = (value: AbstractValue) => signaturePointCurve(facts.program, value.type ?? "") === curve;
  charge(0, 1); const predicates: NonNullable<SuccessfulPath["predicates"]> = [];
  const relevant = (root: AbstractValue) => {
    charge(0, 3); const pending = [{ value: root, depth: 0 }], seen = new Set<AbstractValue>();
    let found = false;
    while (pending.length) {
      const { value, depth } = pending.pop()!; charge(1 + value.flows.length + value.ledger.size);
      if (depth > 32) throw new Error("Relevant key dependency depth is unavailable");
      if (seen.has(value)) continue; charge(0, 1); seen.add(value);
      if (value.enrollmentSignatureOutcome) continue;
      found ||= !!target.identity && value.flows.some(flow => flow.source.id === target.identity);
      for (const ledger of target.preexistingLedger ?? []) { charge(); found ||= value.ledger.has(ledger); }
      const push = (child: AbstractValue) => { charge(1, 2); pending.push({ value: child, depth: depth + 1 }); };
      for (const child of value.enrollmentPointInputs ?? []) push(child);
      for (const child of value.items ?? []) push(child);
      for (const name in value.fields) if (Object.hasOwn(value.fields, name)) push(value.fields[name]);
      if (value.comparison) { push(value.comparison.left); push(value.comparison.right); }
      if (value.negated) push(value.negated);
      if (value.ordering) { push(value.ordering.left); push(value.ordering.right); }
      if (value.pointIdentityInput) push(value.pointIdentityInput);
    }
    return found;
  };
  for (const predicate of path.predicates) {
    charge();
    if (predicate.value.enrollmentSignatureOutcome) continue;
    const touches = relevant(predicate.value);
    if (!touches && (predicate.value.predicateStructureLost || predicate.value.predicateHasAlternatives || predicate.value.predicateAlternatives)) continue;
    charge(0, 1); predicates.push(predicate);
    if (!touches) continue;
    const decoded = enforcedEqualities(predicate.value, predicate.truth, charge);
    if (!decoded.complete || predicate.value.predicateStructureLost || predicate.value.predicateHasAlternatives)
      throw new Error("Relevant key predicate structure is unavailable");
    let classified = false;
    for (const relation of decoded.equalities) {
      charge();
      if (relation.left.enrollmentSignatureOutcome || relation.right.enrollmentSignatureOutcome) { classified = true; continue; }
      if (point(relation.left) && point(relation.right)) {
        for (const value of [relation.left, relation.right]) {
          const key = immutableOperandKey(value, Math.min(4096, remaining()), undefined, charge);
          if (!key.complete || !key.key) throw new Error("Relevant point relation operand is unavailable");
        }
        classified = true;
      }
    }
    if (!classified) throw new Error("Relevant opaque or coordinate predicate does not establish exact key identity exclusion");
  }
  charge(0, 1);
  const closure = signatureKeyIdentityExclusions({ ...path, predicates }, remaining(), charge, curve, point);
  if (!closure.complete) throw new Error("Mandatory typed key identity closure is unavailable or exhausted");
  return closure.excluded.has(operand.key);
}

export function signatureIdentityObservations(facts: AnalysisFacts) {
  const observations: SignatureIdentityObservation[] = [], diagnostics: Diagnostic[] = [];
  const evidence = facts.signatureIdentityEvidence;
  const entry = evidence?.entry ?? facts.program.entries[0];
  const issue = (message: string) => diagnostics.push({ code: "signature-identity-review-unavailable", message,
    location: facts.program.functions.get(entry)?.declaration.span ?? facts.program.rootSource.ast.span,
    ...(entry ? { scope: { kind: "rule" as const, detectorId: SIGNATURE_IDENTITY_REVIEW, entry } } : {}) });
  const charge: SignatureCharge = (work = 1, values = 0) => {
    facts.metrics.steps += work; facts.metrics.abstractValues += values;
    if (!evidence || facts.metrics.steps > evidence.maxSteps || facts.metrics.abstractValues > evidence.maxValues)
      throw new Error("Signature review proof exhausted the shared observer/preparation allowance");
    return true;
  };
  try {
    if (!evidence || !facts.signatureEvidence || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states"
      || facts.diagnostics.length || !facts.completedEntries.includes(evidence.entry) || evidence.histories !== facts.paths.length
      || facts.paths.length > evidence.maxPaths) throw new Error("Complete original native signature histories are unavailable");
    if (!(facts.program.compilerVersion === "0.34.0" || facts.program.zkirVersion === 2 && ["0.35.0", "0.35.0-rc.1"].includes(facts.program.compilerVersion)))
      throw new Error("Exact compiler/ZKIR signature review profile is unsupported");
    signatureIdentityScope(facts.program, evidence.entry, charge);
    charge(0, 2);
    for (const path of facts.paths) {
      charge();
      if (path.entry !== evidence.entry || !path.enrollmentHistory || path.enrollmentHistory.operations !== (path.operations?.length ?? 0)
        || path.enrollmentHistory.predicates !== path.predicates?.length || path.enrollmentHistory.writes !== path.writes.length)
        throw new Error("Signature history rows are incomplete or inconsistent");
      for (const operation of path.operations ?? []) {
        charge(); if (operation.kind !== "signature-verification") continue;
        const curve = signatureVerifierCurve(operation.name), key = operation.args[2];
        if (!curve || curve !== operation.signatureCurve || !key || signaturePointCurve(facts.program, key.type ?? "") !== curve)
          throw new Error("Canonical verifier curve or exact typed key observation is unavailable");
        if (key.constantKind === "point" && key.constant !== undefined) continue;
        if (key.pointIdentityExcluded) continue;
        const source = sourceOf(facts, path, key, curve, charge);
        if (!source) throw new Error("Verification key provenance is outside exact caller or whole persistent Cell snapshots");
        if (excluded(facts, path, key, curve, charge, () => evidence.maxSteps - facts.metrics.steps)) continue;
        // Reserve finding objects, trace/call arrays, strings, metadata and
        // uniqueness containers before retaining any emission operand.
        charge(facts.program.files.size);
        let emission = 128 + operation.callPath.length * 3 + facts.program.files.size * 3;
        for (const text of [path.entry, source.symbol, operation.name, operation.location.file,
          facts.program.symbols.get(source.symbol)!.name, facts.program.symbols.get(path.entry)!.name]) {
          charge(); emission += Math.ceil(text.length / 64) * 8;
        }
        for (const id of operation.callPath) { charge(); emission += Math.ceil((facts.program.symbols.get(id)?.name ?? id).length / 64) * 3; }
        charge(0, emission); observations.push({ entry: path.entry, operation, curve, source });
      }
    }
  } catch (error) { observations.length = 0; issue(error instanceof Error ? error.message : String(error)); }
  return { observations, diagnostics };
}
