import { observeRefundEndpoints } from "./refund-endpoint-observation.js";
import { REFUND_ENDPOINT_RULE } from "../semantic/refund-endpoint.js";
import { observeSourceMapGetters } from "./source-map-getters-observation.js";
import { SOURCE_MAP_GETTER_RULE } from "../semantic/source-map-getters.js";
import { observeClosedCapacity } from "./closed-capacity-observation.js";
import { CLOSED_CAPACITY_RULE } from "../semantic/closed-capacity.js";
import { observeMembershipIdentity } from "./membership-identity-observation.js";
import { MEMBERSHIP_IDENTITY_RULE } from "../semantic/membership-identity.js";
import { observeSourceClaims } from "./source-claims-observation.js";
import { SOURCE_CLAIM_RULE } from "../semantic/source-claims.js";
import { observeListGrowth } from "./list-growth-observation.js";
import { LIST_GROWTH_RULE } from "../semantic/list-growth.js";
import { observeSecretBindings } from "./secret-binding-observation.js";
import { SECRET_BINDING_RULE } from "../semantic/secret-binding.js";
import { observePublicScalar } from "./public-scalar-observation.js";
import { observeComplementarySend } from "./complementary-send-observation.js";
import { COMPLEMENTARY_SEND_RULE } from "../semantic/complementary-send-targets.js";
import { observeSignatureIdentity } from "./signature-identity-observation.js";
import { SIGNATURE_IDENTITY_REVIEW } from "../semantic/signature-targets.js";
import { observeOperationIntent } from "./operation-intent-observation.js";
import { observeContractRecipient } from "./contract-recipient-observation.js";
import { CONTRACT_RECIPIENT_RULE } from "../semantic/contract-recipient.js";
import { OPERATION_INTENT_RULE } from "../semantic/operation-intent.js";
import { observeDomainReview } from "./domain-review-observation.js";
import { observeEnrollmentReview } from "./enrollment-review-observation.js";
import { STORED_ENROLLMENT_RULE } from "../semantic/enrollment-review.js";
import { DOMAIN_REVIEW_RULE } from "../semantic/domain-review.js";
import { zeroConsumptionFindings } from "../detectors/zero-consumption.js";
import { ZERO_CONSUMPTION_RULE, zeroConsumptionScope } from "../semantic/zero-consumption-targets.js";
import { callerZeroAmountCandidates } from "../dataflow/caller-zero.js";
import { mapDebitAmountCandidates } from "../dataflow/map-debit.js";
import { observeZeroDefault } from "./zero-default-observation.js";
import { ZERO_DEFAULT_RULE } from "../semantic/zero-default-targets.js";
import { MAP_DEBIT_RULE, mapDebitScope } from "../semantic/map-debit-targets.js";
import { CALLER_ZERO_RULE, callerZeroScope } from "../semantic/caller-zero-targets.js";
import { observeConfiguredCapacity } from "./configured-capacity-observation.js";
import { CONFIGURED_CAPACITY_RULE } from "../dataflow/configured-capacity.js";
import { observeKeyedState } from "./keyed-state-observation.js";
import { KEYED_STATE_INVARIANT } from "../dataflow/keyed-state-invariant.js";
import { PUBLIC_SCALAR_RULE, PUBLIC_SCALAR_TARGETS, PUBLIC_SCALAR_PROFILE_MESSAGE, publicScalarProfile, publicScalarScope } from "../semantic/public-scalar-targets.js";
import { QUORUM_RULE, quorumScope, quorumTargets } from "../semantic/quorum-targets.js";
import { resettableListNonceFindings } from "../detectors/resettable-nonce.js";
import { memoNonceFindings } from "../detectors/memo-nonce.js";
import { MEMO_NONCE_APPEND, MEMO_NONCE_RULE } from "../semantic/memo-nonce-targets.js";
import { NATIVE_KEY_RULE, nativeKeyScope } from "../semantic/native-key-targets.js";
import { REDUNDANT_RECEIVE_RULE, SELF_COIN_TARGETS, redundantReceiveScope, redundantReceiveCheckpoints } from "../semantic/redundant-receive-targets.js";
import { zeroSendFindings } from "../detectors/zero-send.js";
import { merkleInsertFindings } from "../detectors/merkle-insert.js";
import { ZERO_SEND_RULE, ZERO_SEND_TARGET, zeroSendScope } from "../semantic/zero-send-targets.js";
import { FIELD_RECOMPOSITION_RULE, recompositionTargets } from "../semantic/field-recomposition.js";
import { fieldRecompositionFindings } from "../detectors/field-recomposition.js";
import { TRANSIENT_LEDGER_RULE, transientScope } from "../semantic/transient-targets.js";
import { CALLER_EQUALITY_RULE, callerEqualityScope } from "../semantic/caller-equality-targets.js";
import { nativeHashScope } from "../semantic/hash-targets.js";
import { runtimeWidthScope, SHIELDED_WIDTH_RULE } from "../semantic/runtime-width-targets.js";
import { runtimeWidthFindings } from "../detectors/runtime-width.js";
import { GUARD_TAG_RULE } from "./guard-tags.js";
import { ZERO_MAP_RULE } from "./zero-membership.js";
import { CURRENT_ROOT_RULE } from "../dataflow/merkle-freshness.js";
import { encryptionScope, encryptionTargets } from "../semantic/encryption-targets.js";
import { hasListWrites } from "../semantic/list-reset-targets.js";
import { collectionTargets } from "../semantic/collection-targets.js";
import { hasWitnessState } from "../semantic/witness-state-targets.js";
import { hasShieldedMint, hasTokenMint } from "../semantic/mint-targets.js";
import { hasDefaultAddressEffects } from "../semantic/default-address-targets.js";
import { hasContractOwnerEffects } from "../semantic/contract-owner-targets.js";
import { unsupportedContractOwnerFindings } from "../detectors/contract-owner.js";
import { performance } from "node:perf_hooks";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import type { Detector, Finding } from "../detectors/types.js";
import { AnalysisError, type Diagnostic } from "../model.js";
import type { Program } from "../semantic/index.js";
import type { ResolvedPolicies } from "../policies.js";
import { arithmeticTargets } from "../semantic/arithmetic-targets.js";
import { digestTargets } from "../semantic/digest-targets.js";
import { eitherTargets } from "../semantic/either-targets.js";
import { ENROLLED_SIGNATURE_KEY_RULE, schnorrVerifier } from "../semantic/signature-targets.js";
import { ECDSA_VERIFIER, signedInputTargets } from "../semantic/signed-input-targets.js";
import { repeatedCallCandidate, sourceQueryCandidate } from "../dataflow/source-queries.js";
import { ATOMIC_UPDATE_RULE } from "./atomic-updates.js";
import { MERKLE_INSERT_OBSERVER, MERKLE_INSERT_RULE, merkleInsertScope, merkleRootCircuit, merklePathWitnessTargets } from "../semantic/merkle-targets.js";

/** These consumers require exact observations unavailable in compressed histories.
 * They cannot alter admission or findings for the ordinary analysis consumers. */
export const OBSERVATION_RULES = new Set([
  REFUND_ENDPOINT_RULE, SOURCE_MAP_GETTER_RULE, SOURCE_CLAIM_RULE, LIST_GROWTH_RULE, COMPLEMENTARY_SEND_RULE, SIGNATURE_IDENTITY_REVIEW, CONTRACT_RECIPIENT_RULE,
  OPERATION_INTENT_RULE, STORED_ENROLLMENT_RULE, DOMAIN_REVIEW_RULE, ZERO_DEFAULT_RULE,
  KEYED_STATE_INVARIANT, CLOSED_CAPACITY_RULE, CONFIGURED_CAPACITY_RULE,
  PUBLIC_SCALAR_RULE, SECRET_BINDING_RULE, MEMBERSHIP_IDENTITY_RULE,
  "split-witness-identity", "resettable-list-nonce", MEMO_NONCE_RULE, NATIVE_KEY_RULE, REDUNDANT_RECEIVE_RULE,
  ZERO_SEND_RULE, ZERO_CONSUMPTION_RULE, "signed-effect-input", QUORUM_RULE, ENROLLED_SIGNATURE_KEY_RULE,
  MERKLE_INSERT_RULE,
  FIELD_RECOMPOSITION_RULE,
  "merkle-leaf-binding-review",
  ATOMIC_UPDATE_RULE,
  "destructive-list-reset", GUARD_TAG_RULE, ZERO_MAP_RULE, CALLER_ZERO_RULE, MAP_DEBIT_RULE, CURRENT_ROOT_RULE, TRANSIENT_LEDGER_RULE, CALLER_EQUALITY_RULE, SHIELDED_WIDTH_RULE,
  "publicly-derivable-encryption-secret", "unconstrained-witness-to-state", "unbounded-mint", "duplicate-shielded-mint", "default-recipient-or-owner", "unsupported-contract-owner", "either-payload-mismatch", "low-entropy-hash-disclosure", "identity-signature-key", "field-arithmetic-wraparound", "stale-nft-metadata", "public-key-membership-authorization",
]);
export interface RuleCoverage {
  root: string;
  detectorId: string;
  entry: string;
  status: "complete" | "incomplete" | "not-applicable";
  evidence: "source-local-formula" | "baseline" | "exact-observation" | "structural-absence" | "conservative-absence" | "unavailable";
  diagnosticCodes: string[];
}
export interface RuleObservationWork {
  detectorId: string;
  /** Original entry-local step/path and pass-wide value limits; no retry budget. */
  limits: { maxSteps: number; maxPaths: number; maxValues: number };
  metrics: AnalysisFacts["metrics"];
  analysisMs: number;
  detectorMs: number;
}

/** Rules whose consumer can be proven finding-free by a conservative may-view
 * of every relevant evaluation (Dataflow.conservativeRuleCertificate). */
const CERTIFICATES = new Map<string, "digest" | "either">([["low-entropy-hash-disclosure", "digest"], ["either-payload-mismatch", "either"]]);

function applicable(program: Program, id: string, entry: string, policies: ResolvedPolicies): boolean {
  if (id === QUORUM_RULE) {
    if (program.functions.get(entry)!.symbol.kind === "constructor") return false;
    const target = quorumScope(program, entry);
    if (!target.complete) throw new AnalysisError({ code: "quorum-target-budget", message: "Quorum verifier applicability exhausted its allowance; review is incomplete", location: program.functions.get(entry)!.declaration.span });
    return target.applicable;
  }
  if (id === "split-witness-identity") {
    if (program.functions.get(entry)!.symbol.kind === "constructor") return false;
    const target = nativeHashScope(program, entry);
    return !target.complete || target.applicable;
  }
  if (id === "resettable-list-nonce" || id === MEMO_NONCE_RULE) {
    if (program.entries.length > 64) throw new AnalysisError({ code: id === MEMO_NONCE_RULE ? "memo-nonce-cross-entry-budget" : "resettable-nonce-cross-entry-budget", message: "Cross-entry nonce reset proof exceeds its 64-entry allowance; review is incomplete", location: program.functions.get(entry)!.declaration.span });
    return hasShieldedMint(program, entry);
  }
  if (id === REDUNDANT_RECEIVE_RULE) {
    const scope = redundantReceiveScope(program, [entry]);
    if (!scope.complete) throw new AnalysisError({ code: "redundant-receive-target-budget", message: "Applicability exceeded allowance; redundant receive review is incomplete", location: program.rootSource.ast.span });
    const checkpoints = redundantReceiveCheckpoints(program, [entry]);
    if (scope.applicable && (!checkpoints.complete || checkpoints.present)) throw new AnalysisError({ code: "redundant-receive-evidence-unavailable", message: "Reachable checkpoint return snapshots unavailable; redundant receive review is incomplete", location: program.functions.get(entry)!.declaration.span });
    return scope.applicable;
  }
  if (id === MERKLE_INSERT_RULE) {
    const target = merkleInsertScope(program, [entry]);
    if (!target.complete) throw new AnalysisError({ code: "merkle-insert-target-budget", message: "Native tree insertion applicability exhausted its allowance; review is incomplete", location: program.functions.get(entry)!.declaration.span });
    return target.applicable;
  }
  if (["merkle-leaf-binding-review", "signed-effect-input"].includes(id) && program.functions.get(entry)!.symbol.kind === "constructor") return false;
  if (id === ZERO_SEND_RULE || id === ZERO_CONSUMPTION_RULE) {
    const target = id === ZERO_CONSUMPTION_RULE ? zeroConsumptionScope(program, [entry]) : zeroSendScope(program, [entry]);
    if (!target.complete) throw new AnalysisError({ code: "zero-send-target-budget", message: "Canonical unshielded send applicability exhausted its allowance; review is incomplete", location: program.functions.get(entry)!.declaration.span });
    return target.applicable;
  }
  if (id === SHIELDED_WIDTH_RULE) {
    const target = runtimeWidthScope(program, entry);
    if (!target.complete) throw new AnalysisError({ code: "runtime-width-target-budget", message: "Native output applicability exhausted its bounded allowance; runtime-width review is incomplete", location: program.functions.get(entry)!.declaration.span });
    if (!target.applicable) return false;
    if (program.compilerVersion !== "0.34.0" || program.zkirVersion !== 2) throw new AnalysisError({ code: "runtime-width-profile-unavailable", message: "Shielded coin width review requires Compact 0.34.0/ZKIR2 and the explicitly assumed reference runtime 0.19.0 descriptor; this profile is unavailable", location: program.functions.get(entry)!.declaration.span });
    return true;
  }
  if (id === NATIVE_KEY_RULE) { const target = nativeKeyScope(program, entry); return !target.complete || target.applicable; }
  if (id === CALLER_EQUALITY_RULE) {
    const target = callerEqualityScope(program, entry);
    return !target.complete || target.applicable;
  }
  if (id === TRANSIENT_LEDGER_RULE) {
    const target = transientScope(program, entry);
    return !target.complete || target.applicable;
  }
  if (id === CALLER_ZERO_RULE) {
    const target = callerZeroScope(program, entry);
    if (!target.complete) throw new AnalysisError({ code: "caller-zero-target-budget", message: "Map insertion applicability exceeded its allowance", location: program.functions.get(entry)!.declaration.span });
    return target.applicable;
  }
  if (id === MAP_DEBIT_RULE) {
    const target = mapDebitScope(program, entry);
    if (!target.complete) throw new AnalysisError({ code: "map-debit-target-budget", message: "Numeric Map debit applicability exceeded its allowance", location: program.functions.get(entry)!.declaration.span });
    return target.applicable;
  }
  if (id === ZERO_MAP_RULE) return !!policies.zeroAmountMembership?.some(policy => policy.circuit === entry);
  if (id === CURRENT_ROOT_RULE) return !!policies.currentRootMembership?.some(policy => policy.circuit === entry);
  if (id === ATOMIC_UPDATE_RULE) return !!policies.atomicUpdates?.some(policy => policy.circuit === entry);
  if (id === GUARD_TAG_RULE) {
    if (program.functions.get(entry)!.symbol.kind === "constructor") return false;
    const target = nativeHashScope(program, entry);
    return !target.complete || target.applicable;
  }
  if (id === "destructive-list-reset") return hasListWrites(program, entry);
  if (id === PUBLIC_SCALAR_RULE) {
    const target = publicScalarScope(program, entry);
    if (!target.complete) throw new AnalysisError({ code: target.unavailable === "budget" ? "public-scalar-target-budget" : "public-scalar-target-unavailable", message: "Canonical generator multiplication applicability is unavailable or exhausted its bounded allowance; review is incomplete", location: program.functions.get(entry)!.declaration.span });
    if (!target.applicable) return false;
    if (!publicScalarProfile(program)) throw new AnalysisError({ code: "public-scalar-profile", message: PUBLIC_SCALAR_PROFILE_MESSAGE, location: program.functions.get(entry)!.declaration.span });
    return true;
  }
  if (id === "publicly-derivable-encryption-secret") {
    const scope = encryptionScope(program, entry);
    if (!scope.complete || scope.unsupported) throw new AnalysisError({ code: "encryption-target-unavailable", message: "Generator derivation recipe/profile is unsupported or applicability exceeded its allowance; this entry is incomplete", location: program.functions.get(entry)!.declaration.span });
    return scope.applicable;
  }
  if (id === "public-key-membership-authorization") {
    if (program.functions.get(entry)!.symbol.kind === "constructor") return false;
    const target = collectionTargets(program, 20000, [entry]);
    if (target.complete && !target.applicable) return false;
  }
  if (id === "unsupported-contract-owner") return hasContractOwnerEffects(program, entry, policies);
  if (id === "stale-nft-metadata") return !!policies.currentNftMetadata?.some(policy => policy.consumer === entry);
  if (id === "unconstrained-witness-to-state") return hasWitnessState(program, entry);
  if (id === "unbounded-mint") return hasTokenMint(program, entry);
  if (id === "duplicate-shielded-mint") return hasShieldedMint(program, entry);
  if (id === "default-recipient-or-owner") return hasDefaultAddressEffects(program, entry);
  const entries = [entry];
  const target = id === FIELD_RECOMPOSITION_RULE ? recompositionTargets(program, 20000, entries)
    : id === "either-payload-mismatch" ? eitherTargets(program, 20000, entries)
    : id === "low-entropy-hash-disclosure" ? digestTargets(program, 20000, entries)
      : id === "field-arithmetic-wraparound" ? arithmeticTargets(program, 20000, entries) : undefined;
  if (target) return !target.complete || target.applicable;
  let work = 0;
  const seen = new Set<string>(), pending = [entry];
  while (pending.length) {
    if (++work > 20000) return true;
    const callee = pending.pop()!;
    if (seen.has(callee)) continue;
    seen.add(callee);
    if (id === "merkle-leaf-binding-review" ? merkleRootCircuit(callee)
      : id === "public-key-membership-authorization" ? callee === "intrinsic::ownPublicKey" : schnorrVerifier(callee) || id === "signed-effect-input" && callee === ECDSA_VERIFIER) return true;
    for (const next of program.functions.get(callee)?.calls ?? []) {
      if (++work > 20000) return true;
      pending.push(next);
    }
  }
  return false;
}

/** Entry-isolated facts include all observations and metadata for that entry.
 * Never filter a partial pass into an apparent complete absence certificate.
 * Entries share each rule's original value allowance; worker time/memory bounds
 * apply to the entire scan. Work across baseline and rules is reported in full. */
export function observeRules(program: Program, rules: readonly Detector[], policies: ResolvedPolicies,
  options: { maxSteps?: number; maxPaths?: number; maxValues?: number }, baselineCompleted?: ReadonlySet<string>) {
  const findings: Finding[] = [], diagnostics: Diagnostic[] = [], coverage: RuleCoverage[] = [], work: RuleObservationWork[] = [];
  for (const rule of rules) {
    if (rule.id === SOURCE_MAP_GETTER_RULE) {
      const observed = observeSourceMapGetters(program, rule, policies, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === SOURCE_CLAIM_RULE) {
      const observed = observeSourceClaims(program, rule, policies, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === SECRET_BINDING_RULE || rule.id === MEMBERSHIP_IDENTITY_RULE) {
      const observed = (rule.id === MEMBERSHIP_IDENTITY_RULE ? observeMembershipIdentity : observeSecretBindings)(program, rule, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === PUBLIC_SCALAR_RULE) {
      const observed = observePublicScalar(program, rule, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === REFUND_ENDPOINT_RULE) {
      const observed = observeRefundEndpoints(program, rule, options);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === COMPLEMENTARY_SEND_RULE) {
      const observed = observeComplementarySend(program, rule, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === SIGNATURE_IDENTITY_REVIEW) {
      const observed = observeSignatureIdentity(program, rule, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === CONTRACT_RECIPIENT_RULE) {
      const observed = observeContractRecipient(program, rule, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === OPERATION_INTENT_RULE) {
      const observed = observeOperationIntent(program, rule, policies, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === STORED_ENROLLMENT_RULE) {
      const observed = observeEnrollmentReview(program, rule, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === DOMAIN_REVIEW_RULE) {
      const observed = observeDomainReview(program, rule, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === ZERO_DEFAULT_RULE) {
      const observed = observeZeroDefault(program, rule, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    const resettableNonce = rule.id === "resettable-list-nonce" || rule.id === MEMO_NONCE_RULE;
    if (rule.id === CLOSED_CAPACITY_RULE) {
      const observed = observeClosedCapacity(program, rule, options);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === CONFIGURED_CAPACITY_RULE) {
      const observed = observeConfiguredCapacity(program, rule, options);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === LIST_GROWTH_RULE) {
      const observed = observeListGrowth(program, rule, options, baselineCompleted);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    if (rule.id === KEYED_STATE_INVARIANT) {
      const observed = observeKeyedState(program, rule, options);
      findings.push(...observed.findings); diagnostics.push(...observed.diagnostics); coverage.push(...observed.coverage); work.push(observed.work);
      continue;
    }
    const limits = { maxSteps: options.maxSteps ?? 40000, maxPaths: options.maxPaths ?? 256, maxValues: options.maxValues ?? 50000 };
    const metrics: AnalysisFacts["metrics"] = { steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0,
      statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 };
    const measured: RuleObservationWork = { detectorId: rule.id, limits, metrics, analysisMs: 0, detectorMs: 0 }; work.push(measured);
    for (const entry of program.entries) {
      const scope = { kind: "rule" as const, detectorId: rule.id, entry };
      const location = program.functions.get(entry)!.declaration.span;
      const row: RuleCoverage = { root: program.root, detectorId: rule.id, entry, status: "incomplete", evidence: "exact-observation", diagnosticCodes: [] };
      coverage.push(row);
      let started = performance.now();
      try {
        if (!applicable(program, rule.id, entry, policies)) {
          row.status = "not-applicable"; row.evidence = "structural-absence";
          measured.analysisMs += performance.now() - started;
          continue;
        }
        // This new review rule requires completed baseline semantics. Retrying
        // an already-incomplete entry can exhaust the whole worker and erase
        // otherwise available facts. Withholding its analysis certifies nothing.
        // Existing rule observation/absence contracts remain unchanged.
        if ((resettableNonce || rule.id === REDUNDANT_RECEIVE_RULE || rule.id === FIELD_RECOMPOSITION_RULE || rule.id === MERKLE_INSERT_RULE || rule.id === ATOMIC_UPDATE_RULE || rule.id === GUARD_TAG_RULE || rule.id === ZERO_MAP_RULE || rule.id === CALLER_ZERO_RULE || rule.id === MAP_DEBIT_RULE || rule.id === CURRENT_ROOT_RULE || rule.id === TRANSIENT_LEDGER_RULE || (rule.id === CALLER_EQUALITY_RULE || rule.id === NATIVE_KEY_RULE) || rule.id === SHIELDED_WIDTH_RULE || rule.id === ZERO_SEND_RULE || rule.id === ZERO_CONSUMPTION_RULE) && baselineCompleted && (!baselineCompleted.has(entry) || resettableNonce && program.entries.some(other => !baselineCompleted.has(other)))) {
          const issue: Diagnostic = { code: rule.id === MAP_DEBIT_RULE ? "map-debit-baseline-incomplete" : rule.id === CALLER_ZERO_RULE ? "caller-zero-baseline-incomplete" : rule.id === NATIVE_KEY_RULE ? "native-key-baseline-incomplete" : rule.id === MEMO_NONCE_RULE ? "memo-nonce-baseline-incomplete" : resettableNonce ? "resettable-nonce-baseline-incomplete" : rule.id === REDUNDANT_RECEIVE_RULE ? "redundant-receive-baseline-incomplete" : rule.id === FIELD_RECOMPOSITION_RULE ? "field-recomposition-baseline-incomplete" : rule.id === MERKLE_INSERT_RULE ? "merkle-insert-baseline-incomplete" : rule.id === ZERO_CONSUMPTION_RULE ? "zero-consumption-baseline-incomplete" : rule.id === ZERO_SEND_RULE ? "zero-send-baseline-incomplete" : rule.id === ATOMIC_UPDATE_RULE ? "atomic-update-baseline-incomplete" : rule.id === GUARD_TAG_RULE ? "guard-tag-baseline-incomplete" : rule.id === CURRENT_ROOT_RULE ? "current-root-baseline-incomplete" : rule.id === TRANSIENT_LEDGER_RULE ? "transient-ledger-baseline-incomplete" : rule.id === CALLER_EQUALITY_RULE ? "caller-equality-baseline-incomplete" : rule.id === SHIELDED_WIDTH_RULE ? "runtime-width-baseline-incomplete" : "zero-membership-baseline-incomplete", message: `${rule.id} requires completed baseline semantics for this entry; no clean rule result is available`, location, scope };
          diagnostics.push(issue); row.diagnosticCodes.push(issue.code); row.evidence = "unavailable";
          measured.analysisMs += performance.now() - started;
          continue;
        }
        const remaining = limits.maxValues - metrics.abstractValues;
        if (remaining <= 0) {
          const issue: Diagnostic = { code: "rule-observation-budget", message: `${rule.id} has exhausted its shared value allowance; this entry has no complete rule result`, location, scope };
          diagnostics.push(issue); row.diagnosticCodes.push(issue.code);
          measured.analysisMs += performance.now() - started;
          continue;
        }
        if (rule.id === ZERO_MAP_RULE || rule.id === CALLER_ZERO_RULE || rule.id === MAP_DEBIT_RULE) {
          let spent = 0;
          let amounts: string[];
          if (rule.id === CALLER_ZERO_RULE || rule.id === MAP_DEBIT_RULE) {
            const ordinary = rule.id === MAP_DEBIT_RULE
              ? new Dataflow(program, limits.maxSteps, limits.maxPaths, remaining).analyzeMapDebitCandidates(entry)
              : new Dataflow(program, limits.maxSteps, limits.maxPaths, remaining).analyzeCallerZeroCandidates(entry);
            let candidateError: string | undefined;
            try { amounts = rule.id === MAP_DEBIT_RULE
              ? mapDebitAmountCandidates(ordinary, entry, Math.max(0, limits.maxSteps - ordinary.metrics.steps))
              : callerZeroAmountCandidates(ordinary, entry, Math.max(0, limits.maxSteps - ordinary.metrics.steps)); }
            catch (error) { amounts = []; candidateError = error instanceof Error ? error.message : String(error); }
            if (!candidateError && !ordinary.diagnostics.length) findings.push(...rule.run(ordinary, policies));
            spent += ordinary.metrics.steps;
            for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += ordinary.metrics[key];
            diagnostics.push(...ordinary.diagnostics.map(issue => ({ ...issue, scope })));
            row.diagnosticCodes.push(...ordinary.diagnostics.map(issue => issue.code));
            if (candidateError && !ordinary.diagnostics.length) {
              const issue: Diagnostic = { code: rule.id === MAP_DEBIT_RULE ? "map-debit-candidates-unavailable" : "caller-zero-candidates-unavailable", message: candidateError, location, scope };
              diagnostics.push(issue); row.diagnosticCodes.push(issue.code);
            }
            measured.analysisMs += performance.now() - started; started = performance.now();
          } else amounts = [...new Set(policies.zeroAmountMembership!.filter(policy => policy.circuit === entry).map(policy => policy.amount))];
          for (const amount of amounts) {
            const available = limits.maxValues - metrics.abstractValues;
            if (spent >= limits.maxSteps || available <= 0) {
              const issue: Diagnostic = { code: "rule-observation-budget", message: "Zero-entry observations exhausted the shared entry work/value allowance", location, scope };
              diagnostics.push(issue); row.diagnosticCodes.push(issue.code); break;
            }
            const observer = new Dataflow(program, limits.maxSteps - spent, limits.maxPaths, available);
            const facts = rule.id === MAP_DEBIT_RULE ? observer.analyzeZeroMapDebitEntry(entry, amount)
              : observer.analyzeZeroEntry(entry, amount);
            measured.analysisMs += performance.now() - started; started = performance.now();
            const selected = rule.id === CALLER_ZERO_RULE || rule.id === MAP_DEBIT_RULE ? policies
              : { ...policies, zeroAmountMembership: policies.zeroAmountMembership!.filter(policy => policy.circuit === entry && policy.amount === amount) };
            if (facts.completedEntries.includes(entry) && !facts.diagnostics.length) findings.push(...rule.run(facts, selected));
            measured.detectorMs += performance.now() - started; started = performance.now();
            spent += facts.metrics.steps;
            for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
            diagnostics.push(...facts.diagnostics.map(issue => ({ ...issue, scope })));
            row.diagnosticCodes.push(...facts.diagnostics.map(issue => issue.code));
            if (!facts.completedEntries.includes(entry) && !facts.diagnostics.length) {
              const issue: Diagnostic = { code: "rule-observation-incomplete", message: "Zero-entry observation did not complete; no clean rule result is available", location, scope };
              diagnostics.push(issue); row.diagnosticCodes.push(issue.code);
            }
          }
          if (!row.diagnosticCodes.length) row.status = "complete";
          continue;
        }
        // Branch-expanding entries (the baseline source-query admission) first
        // try a conservative absence certificate. It shares this entry's step
        // allowance and the rule's value allowance with the exact pass; the
        // admission scan is charged only when it admits the entry.
        let spent = 0, spentValues = 0;
        const certificate = CERTIFICATES.get(rule.id);
        // Each admission scan is charged only when it admits the entry.
        let scan = 0;
        const threshold = Math.floor(Math.log2(limits.maxPaths)) + 1;
        const admitted = !!certificate && (sourceQueryCandidate(program, entry, threshold, () => ++scan <= limits.maxSteps, true)
          || (scan = 0, repeatedCallCandidate(program, entry, threshold, () => ++scan <= limits.maxSteps, true)));
        if (certificate && admitted) {
          spent = scan;
          const certified = new Dataflow(program, limits.maxSteps, limits.maxPaths, remaining, "instructions", true, true, "equivalent-states", false, true,
            rule.id === "either-payload-mismatch" ? "all" : "witness", false, false, false, true, false, rule.id === "either-payload-mismatch", rule.id === "low-entropy-hash-disclosure")
            .conservativeRuleCertificate(entry, certificate, { steps: Math.max(0, limits.maxSteps - spent), values: remaining });
          spent += certified.work.steps; spentValues = certified.work.values;
          metrics.steps += certified.work.steps + scan; metrics.abstractValues += certified.work.values;
          if (certified.status === "absent") {
            measured.analysisMs += performance.now() - started;
            row.status = "complete"; row.evidence = "conservative-absence";
            continue;
          }
          if (spent >= limits.maxSteps || spentValues >= remaining) {
            const issue: Diagnostic = { code: "analysis-budget", message: `${rule.id} unavailable/incomplete for ${entry}: conservative certificate (${certified.reason ?? certified.status}) exhausted the shared allowance`, location, scope };
            diagnostics.push(issue); row.diagnosticCodes.push(issue.code);
            measured.analysisMs += performance.now() - started;
            continue;
          }
        }
        const all = resettableNonce || rule.id === FIELD_RECOMPOSITION_RULE || (rule.id === ZERO_SEND_RULE || rule.id === ZERO_CONSUMPTION_RULE) || rule.id === "destructive-list-reset" || rule.id === "unconstrained-witness-to-state" || rule.id === "unbounded-mint" || rule.id === "duplicate-shielded-mint" || rule.id === "default-recipient-or-owner" || rule.id === "unsupported-contract-owner" || rule.id === "either-payload-mismatch" || rule.id === "field-arithmetic-wraparound" || rule.id === "stale-nft-metadata" || rule.id === "public-key-membership-authorization";
        const leafBinding = rule.id === "merkle-leaf-binding-review";
        const merkleInsert = rule.id === MERKLE_INSERT_RULE;
        const splitIdentity = rule.id === "split-witness-identity";
        const signedInput = rule.id === "signed-effect-input";
        const signatureReview = rule.id === ENROLLED_SIGNATURE_KEY_RULE;
        const quorum = rule.id === QUORUM_RULE;
        const leafTargets = leafBinding ? merklePathWitnessTargets(program) : undefined;
        if (leafTargets && !leafTargets.complete) throw new AnalysisError({ code: "merkle-witness-target-budget", message: "Path-witness invocation targets exceeded their allowance; leaf-binding review is incomplete", location });
        const flow = new Dataflow(program, limits.maxSteps - spent, limits.maxPaths, remaining - spentValues, "instructions", true, true, "equivalent-states", false, !splitIdentity && !merkleInsert && !signedInput && !quorum && !signatureReview && !leafBinding && rule.id !== ATOMIC_UPDATE_RULE && rule.id !== "unconstrained-witness-to-state" && rule.id !== TRANSIENT_LEDGER_RULE && rule.id !== NATIVE_KEY_RULE && rule.id !== CALLER_EQUALITY_RULE && rule.id !== CURRENT_ROOT_RULE && rule.id !== ZERO_CONSUMPTION_RULE && !(rule.id === "low-entropy-hash-disclosure" && program.compilerVersion === "0.31.1"),
          splitIdentity || merkleInsert || signedInput || quorum || signatureReview || leafBinding || all || rule.id === ATOMIC_UPDATE_RULE || rule.id === GUARD_TAG_RULE || rule.id === CURRENT_ROOT_RULE || rule.id === TRANSIENT_LEDGER_RULE || (rule.id === CALLER_EQUALITY_RULE || rule.id === NATIVE_KEY_RULE) || rule.id === SHIELDED_WIDTH_RULE ? "all" : "witness", leafBinding || rule.id === CURRENT_ROOT_RULE, splitIdentity || merkleInsert || quorum || rule.id === ZERO_CONSUMPTION_RULE || rule.id === "stale-nft-metadata" || rule.id === "public-key-membership-authorization", false, !splitIdentity && !merkleInsert && !signedInput && !quorum && !signatureReview && !leafBinding && rule.id !== ATOMIC_UPDATE_RULE && rule.id !== TRANSIENT_LEDGER_RULE && rule.id !== NATIVE_KEY_RULE && rule.id !== CALLER_EQUALITY_RULE && rule.id !== CURRENT_ROOT_RULE && rule.id !== ZERO_CONSUMPTION_RULE,
          signedInput || signatureReview || rule.id === "identity-signature-key", rule.id === "either-payload-mismatch", (resettableNonce || splitIdentity || signedInput || quorum || leafBinding || rule.id === GUARD_TAG_RULE || (rule.id === CALLER_EQUALITY_RULE || rule.id === NATIVE_KEY_RULE) || rule.id === PUBLIC_SCALAR_RULE || rule.id === "low-entropy-hash-disclosure" || rule.id === "publicly-derivable-encryption-secret"), rule.id === "field-arithmetic-wraparound", (resettableNonce || rule.id === REDUNDANT_RECEIVE_RULE || rule.id === "duplicate-shielded-mint" || rule.id === "unbounded-mint"), leafBinding || rule.id === "unbounded-mint" || rule.id === SHIELDED_WIDTH_RULE || rule.id === ZERO_SEND_RULE || rule.id === ZERO_CONSUMPTION_RULE || rule.id === FIELD_RECOMPOSITION_RULE, rule.id === MEMO_NONCE_RULE ? new Set([MEMO_NONCE_APPEND]) : rule.id === PUBLIC_SCALAR_RULE ? PUBLIC_SCALAR_TARGETS : rule.id === REDUNDANT_RECEIVE_RULE ? SELF_COIN_TARGETS : merkleInsert ? new Set([MERKLE_INSERT_OBSERVER]) : quorum ? quorumTargets(program) : signedInput ? signedInputTargets(program) : (rule.id === ZERO_SEND_RULE || rule.id === ZERO_CONSUMPTION_RULE) ? new Set([ZERO_SEND_TARGET]) : leafTargets?.targets ?? (rule.id === "publicly-derivable-encryption-secret" ? encryptionTargets(program).targets : undefined), rule.id === TRANSIENT_LEDGER_RULE, rule.id === NATIVE_KEY_RULE, signatureReview);
        const facts = leafBinding ? flow.analyzeMerkleLeafBindingEntry(entry)
          : rule.id === ATOMIC_UPDATE_RULE ? flow.analyzeAtomicUpdateEntry(entry)
          : rule.id === CURRENT_ROOT_RULE ? flow.analyzeCurrentRootEntry(entry)
          : flow.analyzeSubset(resettableNonce ? program.entries : [entry]);
        measured.analysisMs += performance.now() - started;
        if (rule.id !== CURRENT_ROOT_RULE && rule.id !== ATOMIC_UPDATE_RULE) for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
        const analysisComplete = facts.completedEntries.includes(entry) && !facts.diagnostics.length;
        started = performance.now();
        // A failed pass supplies no universal claim and no detector finding.
        // Independent completed entries still retain their positive evidence.
        if (analysisComplete) findings.push(...(rule.id === "unsupported-contract-owner"
          ? unsupportedContractOwnerFindings(facts, policies, undefined, [entry])
          : rule.id === MEMO_NONCE_RULE ? memoNonceFindings(facts, [entry])
          : rule.id === "resettable-list-nonce" ? resettableListNonceFindings(facts, [entry])
          : rule.id === MERKLE_INSERT_RULE ? merkleInsertFindings(facts, undefined, [entry])
          : rule.id === ZERO_CONSUMPTION_RULE ? zeroConsumptionFindings(facts, undefined, [entry])
          : rule.id === ZERO_SEND_RULE ? zeroSendFindings(facts, undefined, [entry])
          : rule.id === FIELD_RECOMPOSITION_RULE ? fieldRecompositionFindings(facts, undefined, [entry])
          : rule.id === SHIELDED_WIDTH_RULE ? runtimeWidthFindings(facts, undefined, undefined, [entry])
          : rule.run(facts, policies)));
        measured.detectorMs += performance.now() - started;
        if (rule.id === CURRENT_ROOT_RULE || rule.id === ATOMIC_UPDATE_RULE) for (const key of Object.keys(metrics) as (keyof typeof metrics)[]) metrics[key] += facts.metrics[key];
        diagnostics.push(...facts.diagnostics.map(issue => ({ ...issue, message: `${rule.id} unavailable/incomplete for ${entry}: ${issue.message}`, scope })));
        row.diagnosticCodes.push(...facts.diagnostics.map(issue => issue.code));
        if (analysisComplete && !facts.diagnostics.length) row.status = "complete";
        else if (!facts.diagnostics.length) {
          diagnostics.push({ code: "rule-observation-incomplete", message: `${rule.id} did not complete this entry; no clean rule result is available`, location, scope });
          row.diagnosticCodes.push("rule-observation-incomplete");
        }
      } catch (error) {
        measured.analysisMs += performance.now() - started;
        const issue = error instanceof AnalysisError ? error.diagnostic : { code: "rule-observation-error", message: error instanceof Error ? error.message : String(error), location };
        diagnostics.push({ ...issue, scope }); row.diagnosticCodes.push(issue.code);
      }
    }
  }
  return { findings, diagnostics, coverage, work };
}
