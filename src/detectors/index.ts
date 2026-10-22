import { unshieldedRefundEndpointReview } from "./refund-endpoint.js";
import { sourceClaimMapGetterReview } from "./source-map-getters.js";
import { closedMembershipCapacityReview } from "./closed-capacity.js";
import { independentMembershipIdentityReview } from "./membership-identity.js";
import { sourceClaimShieldedIssuanceReview } from "./source-claims.js";
import { zeroTransferRetainedListReview } from "./list-growth.js";
import { secretBindingDivergenceReview } from "./secret-binding.js";
import { zeroAmountComplementarySendReview } from "./complementary-send.js";
import { operationIntentPolicy } from "./operation-intent.js";
import { shieldedContractRecipientReview } from "./contract-recipient.js";
import { publicTwoComponentDomainReview } from "./domain-review.js";
import { storedSchnorrKeyEnrollmentReview } from "./enrollment-review.js";
import { configuredMembershipCapacityReview } from "./configured-capacity.js";
import { sharedModuleOnceGate } from "./shared-initializer.js";
import { exportedShieldedDescriptor } from "./exported-shielded-descriptor.js";
import { inconsistentKeyedStateGuard } from "./keyed-state-invariant.js";
import { publishedDigestGeneratorScalarReview } from "./public-scalar.js";
import { quorumSignerUniquenessReview } from "./quorum.js";
import { signatureKeyIdentityExclusionReview } from "./signature-identity-review.js";
import { enrolledSignatureKeyReview } from "./enrolled-signature-key.js";
import { splitWitnessIdentity } from "./split-identity.js";
import { resettableListNonce } from "./resettable-nonce.js";
import { resettableMemoNonce } from "./memo-nonce.js";
import { shieldedBurnAmountWidth } from "./burn-amount-width.js";
import { nativeKeyAuthenticationReview } from "./native-key.js";
import { redundantSelfShieldedReceive } from "./redundant-receive.js";
import { zeroAmountUnshieldedSend } from "./zero-send.js";
import { zeroAmountSetConsumptionReview } from "./zero-consumption.js";
import { merkleInsertWithoutDedupe } from "./merkle-insert.js";
import { fieldRecompositionReview } from "./field-recomposition.js";
import { transientDigestToLedger } from "./transient-ledger.js";
import { callerSuppliedLedgerEquality } from "./caller-equality.js";
import { publiclyDerivedGuardTag } from "./guard-tag.js";
import { callerKeyZeroEntryReview } from "./caller-zero.js";
import { zeroAmountUnguardedMapDebitReview } from "./map-debit.js";
import { zeroAmountInitialMembership } from "./zero-membership.js";
import { zeroDefaultGetterMembershipReview } from "./zero-default.js";
import { currentRootPolicyMismatch } from "./current-root.js";
import { publiclyDerivableEncryptionSecret } from "./encryption-secret.js";
import { destructiveListReset } from "./list-reset.js";
import { unconstrainedWitnessToState } from "./witness-state.js";
import { unboundedMint } from "./mint-limits.js";
import { duplicateShieldedMint } from "./duplicate-mint.js";
import { shieldedCoinRuntimeWidth } from "./runtime-width.js";
import { genericWitnessMaybeAbi } from "./generic-witness-abi.js";
import { conditionalHashRange } from "./conditional-hash-range.js";
import { defaultRecipientOrOwner } from "./default-address.js";
import { unsupportedContractOwner } from "./contract-owner.js";
import { createHash } from "node:crypto";
import { relative } from "node:path";
import { AnalysisFacts, TraceStep } from "../dataflow/index.js";
import { Span } from "../model.js";
import { Detector, Finding } from "./types.js";
import { secretPublication, unguardedWrite, forbiddenTransition, predictableCommitment, impossibleAssertion, workBudget } from "./rules.js";
import { openzeppelinPreconditions } from "./openzeppelin.js";
import { publicKeyMembershipAuthorization } from "./public-key-membership.js";
import { spoofableAuthorization } from "./authorization.js";
import { inconsistentAccessControl } from "./access-control.js";
import { unprotectedValueTransfer } from "./value-transfer.js";
import { merkleMembershipNotEnforced } from "./merkle-membership.js";
import { merkleLeafBindingReview } from "./merkle-leaf-binding.js";
import { signedEffectInput } from "./signed-effect-input.js";
import { nullifierCheckWithoutInsert } from "./nullifier-consumption.js";
import { reInitialization } from "./initialization.js";
import { receivedCoinNotValidated } from "./received-coin.js";
import { fieldArithmeticWraparound } from "./field-arithmetic.js";
import { lowEntropyHashDisclosure } from "./small-domain-hash.js";
import { eitherPayloadMismatch } from "./either-payload.js";
import { ignoredValidationResult } from "./validation-result.js";
import { discardedShieldedSendResult } from "./shielded-send-result.js";
import { discardedComparison } from "./discarded-comparison.js";
import { missingRoleBootstrap } from "./role-bootstrap.js";
import { staleNftMetadata } from "./nft-metadata.js";
import { identitySignatureKey } from "./signature-key.js";
import { informationalDetectors } from "./informational.js";
import { checkpointSplitsAtomicUpdate } from "./atomic-updates.js";
import { exactBalanceThreshold } from "./balance-thresholds.js";
import { checkedDigestNarrowing } from "./digest-narrowing.js";
import { callerSuppliedDeadline } from "./caller-deadline.js";
import { freshnessBoundCallerTime } from "./freshness-bound-caller-time.js";
import { permissionlessMintEgress } from "./permissionless-mint-egress.js";
import { mutuallyExclusiveTerminalPayout } from "./mutually-exclusive-terminal-payout.js";
import { callerSuppliedTimeReview, unassertedSecurityResult, witnessDerivedValueReview } from "./development-patterns.js";
export type { Detector, Finding, Severity, Confidence } from "./types.js";

export const ledgerPreimage: Detector = {
  id: "ledger-bound-preimage-publication",
  description: "A private preimage checked against a ledger hash is also published on a potential successful path",
  requires: ["resolved-calls", "cfg", "private-provenance", "hash-bindings", "public-sinks"],
  run(facts) {
    const findings = new Map<string, Finding>();
    for (const path of facts.paths) {
      for (const sink of path.sinks) {
        for (const flow of sink.value.flows.filter(item => item.form === "raw")) {
          for (const binding of path.bindings.filter(item => item.source.id === flow.source.id)) {
            const root = facts.program.sourceRoot;
            const key = `${ledgerPreimage.id}:${relative(root, facts.program.root)}:${relative(root, sink.location.file)}:${sink.location.start}:${relative(root, flow.source.location.file)}:${flow.source.location.start}:${relative(root, binding.location.file)}:${binding.location.start}`;
            const ledger = facts.program.symbols.get(binding.ledger)!;
            findings.set(key, {
              detectorId: ledgerPreimage.id, severity: "medium", confidence: "medium",
              title: "Ledger-bound private preimage is published",
              message: `Private value from ${flow.source.name} reaches ${sink.kind} ${sink.name} without a hiding transformation. A hash of this value is asserted equal to ledger ${ledger.name} on the same potential successful path. ${sink.kind === "exported-return" ? "This exposes the value at the Compact/application output boundary, not necessarily in the public ledger." : "Ledger operation data is public."} If an untrusted observer obtains a reusable authentication secret through this boundary, secrecy is lost. An intentional reveal protocol may permit this flow.`,
              location: sink.location, source: flow.source.location, constraint: binding.location,
              trace: [...flow.trace, { kind: "sink", label: sink.name, location: sink.location }],
              callPath: sink.callPath.map(id => facts.program.symbols.get(id)!.name),
              remediation: "Keep reusable authentication preimages private; publish a suitable commitment or non-secret result. If this is intentional reveal, confirm that the revealed value grants no remaining authority and document that policy.",
              fingerprint: createHash("sha256").update(key).digest("hex"),
              metadata: { reviewRequired: true, sourceKind: flow.source.kind, sinkKind: sink.kind, visibility: sink.kind === "exported-return" ? "application-output" : "public-ledger", ledger: ledger.name, pathFeasibility: "not-proven", constraintTrace: binding.trace, branches: path.path },
            });
          }
        }
      }
    }
    return [...findings.values()];
  },
};

export const detectors: Detector[] = [
  ledgerPreimage, secretPublication, unguardedWrite, forbiddenTransition, predictableCommitment, impossibleAssertion, workBudget, openzeppelinPreconditions, spoofableAuthorization, publicKeyMembershipAuthorization, inconsistentKeyedStateGuard, inconsistentAccessControl, unprotectedValueTransfer, merkleMembershipNotEnforced, nullifierCheckWithoutInsert, reInitialization, receivedCoinNotValidated, identitySignatureKey, ignoredValidationResult, eitherPayloadMismatch, lowEntropyHashDisclosure, fieldArithmeticWraparound, defaultRecipientOrOwner, unsupportedContractOwner, duplicateShieldedMint, unboundedMint, unconstrainedWitnessToState, missingRoleBootstrap, staleNftMetadata, ...informationalDetectors, publiclyDerivableEncryptionSecret, destructiveListReset, publiclyDerivedGuardTag, zeroAmountInitialMembership, callerKeyZeroEntryReview, zeroAmountUnguardedMapDebitReview, currentRootPolicyMismatch, transientDigestToLedger, callerSuppliedLedgerEquality, shieldedCoinRuntimeWidth, genericWitnessMaybeAbi, conditionalHashRange,
  fieldRecompositionReview,
  checkpointSplitsAtomicUpdate,
  operationIntentPolicy,
  exactBalanceThreshold,
  checkedDigestNarrowing,
  callerSuppliedDeadline,
  discardedComparison,
  discardedShieldedSendResult,
  merkleLeafBindingReview,
  signedEffectInput,
  zeroAmountUnshieldedSend,
  zeroTransferRetainedListReview,
  zeroAmountComplementarySendReview,
  zeroAmountSetConsumptionReview,
  merkleInsertWithoutDedupe,
  redundantSelfShieldedReceive,
  splitWitnessIdentity, resettableListNonce, resettableMemoNonce,
  shieldedBurnAmountWidth,
  nativeKeyAuthenticationReview,
  quorumSignerUniquenessReview,
  enrolledSignatureKeyReview,
  signatureKeyIdentityExclusionReview,
  storedSchnorrKeyEnrollmentReview,
  publishedDigestGeneratorScalarReview,
  secretBindingDivergenceReview,
  independentMembershipIdentityReview,
  exportedShieldedDescriptor,
  sharedModuleOnceGate,
  zeroDefaultGetterMembershipReview,
  shieldedContractRecipientReview,
  publicTwoComponentDomainReview,
  sourceClaimShieldedIssuanceReview,
  closedMembershipCapacityReview,
  sourceClaimMapGetterReview,
  unshieldedRefundEndpointReview,
  freshnessBoundCallerTime,
  permissionlessMintEgress,
  mutuallyExclusiveTerminalPayout,
  callerSuppliedTimeReview,
  unassertedSecurityResult,
  witnessDerivedValueReview,
  configuredMembershipCapacityReview,
];
