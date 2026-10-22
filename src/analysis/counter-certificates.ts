import type { Program } from "../semantic/index.js";
import type { ResolvedPolicies } from "../policies.js";
import { extractTerminalCounterRegion, type CounterRegionLimits, type CounterRegionExtraction } from "./counter-regions.js";
import { accessTargets } from "../semantic/access-targets.js";

export type CounterAbsenceDetector = "zero-amount-set-consumption-review" | "zero-amount-unshielded-send" | "merkle-insert-without-dedupe" | "merkle-leaf-binding-review" | "field-recomposition-range-review" | "native-key-authentication-review" | "split-witness-identity" | "publicly-derivable-encryption-secret" | "ledger-bound-preimage-publication" | "predictable-commitment-randomness" | "impossible-assertion" | "forbidden-state-transition" | "spoofable-authorization" | "public-key-membership-authorization" | "inconsistent-access-control" | "unprotected-value-transfer" | "merkle-membership-not-enforced" | "nullifier-check-without-insert" | "identity-signature-key" | "either-payload-mismatch" | "low-entropy-hash-disclosure" | "field-arithmetic-wraparound" | "duplicate-shielded-mint" | "redundant-self-shielded-receive" | "resettable-list-nonce";
export interface CounterAbsenceCertificate {
  contract: "terminal-counter-absence-1";
  root: string;
  entry: string;
  detector: CounterAbsenceDetector;
  reason: "no-hash-bindings" | "no-commitments" | "no-assertions" | "no-policy-target-writes" | "no-witnesses" | "no-caller-convention" | "no-token-operations" | "no-merkle-proofs" | "no-merkle-inserts" | "no-collection-queries" | "no-signature-verification" | "no-either-receivers" | "no-hash-inputs" | "no-field-arithmetic";
}
export type CounterQualification = Exclude<CounterRegionExtraction, { status: "eligible" }>
  | (Extract<CounterRegionExtraction, { status: "eligible" }> & { certificates: CounterAbsenceCertificate[] });

/** The whitelist is a proof boundary: a new detector must fall back to exact. */
export function qualifyCounterDetectors(program: Program, entry: string, selected: readonly string[], policies: ResolvedPolicies, limits?: CounterRegionLimits): CounterQualification {
  const extracted = extractTerminalCounterRegion(program, entry, limits);
  if (extracted.status !== "eligible") return extracted;
  const { region } = extracted;
  if (selected.length > 256 || policies.transitions.length > 256) return { status: "incomplete", work: extracted.work, diagnostics: [{ code: "counter-certificate-budget", message: "Counter certificate detector/policy capacity exhausted; results are incomplete", location: { ...region.location } }] };
  if (selected.includes("forbidden-state-transition")) for (const policy of policies.transitions) {
    const state = program.symbols.get(policy.state);
    const type = state && program.representationOf(state.type);
    if (state?.kind !== "ledger" || !(type === "Boolean" || /^(Field|Uint<)/.test(type ?? "") || program.symbols.get(type ?? "")?.declaration?.typeKind === "enum")) {
      return { status: "incomplete", work: extracted.work, diagnostics: [{ code: "counter-transition-policy", message: "Counter coverage requires resolved scalar transition policies; results are incomplete", location: { ...region.location } }] };
    }
  }
  const certificates: CounterAbsenceCertificate[] = [];
  const callerScope = selected.includes("inconsistent-access-control") ? accessTargets(program) : undefined;
  if (callerScope) {
    extracted.work.syntaxNodes += callerScope.work;
    if (!callerScope.complete) return { status: "incomplete", work: extracted.work, diagnostics: [{ code: "counter-certificate-budget", message: "Caller-convention applicability work exhausted; results are incomplete", location: { ...region.location } }] };
  }
  const reasons: Record<string, CounterAbsenceCertificate["reason"]> = {
    "ledger-bound-preimage-publication": "no-hash-bindings",
    "predictable-commitment-randomness": "no-commitments",
    // The closed Counter grammar excludes all witness calls, including natives.
    "spoofable-authorization": "no-witnesses",
    "split-witness-identity": "no-witnesses",
    "native-key-authentication-review": "no-witnesses",
    "public-key-membership-authorization": "no-witnesses",
    "unprotected-value-transfer": "no-token-operations",
    // The same closed grammar excludes unshielded sends and all tree writes.
    "zero-amount-unshielded-send": "no-token-operations",
    "zero-amount-set-consumption-review": "no-token-operations",
    "merkle-insert-without-dedupe": "no-merkle-inserts",
    // The closed terminal Counter grammar excludes all mint/token calls.
    "duplicate-shielded-mint": "no-token-operations",
    // The unchanged closed grammar excludes canonical receive/mint/send calls;
    // an exact returned self coin followed by receive therefore cannot occur.
    "redundant-self-shielded-receive": "no-token-operations",
    "resettable-list-nonce": "no-token-operations",
    "merkle-membership-not-enforced": "no-merkle-proofs",
    // Leaf-binding review requires a canonical root call. The unchanged closed
    // grammar admits only Counter mutations and no Merkle helper/witness calls.
    "merkle-leaf-binding-review": "no-merkle-proofs",
    "nullifier-check-without-insert": "no-collection-queries",
    // The closed Counter grammar has no cryptographic verifier calls.
    "identity-signature-key": "no-signature-verification",
    // The closed Counter grammar contains no hashes or Either payload receivers.
    "either-payload-mismatch": "no-either-receivers",
    "low-entropy-hash-disclosure": "no-hash-inputs",
    // This unchanged closed grammar has no hashes or key-derivation calls.
    "publicly-derivable-encryption-secret": "no-hash-inputs",
    // Existing terminal Counter grammar has no Field numeric operations.
    "field-arithmetic-wraparound": "no-field-arithmetic",
    "field-recomposition-range-review": "no-field-arithmetic",
    // The qualified terminal Counter domain also has a successful all-false
    // history: reset, independent Boolean choices skipping each increment,
    // final read. No-assertions alone would not cover a no-successful-path rule.
    "impossible-assertion": "no-assertions",
    "forbidden-state-transition": "no-policy-target-writes",
  };
  if (callerScope && !callerScope.applicable) reasons["inconsistent-access-control"] = "no-caller-convention";
  for (const detector of selected) {
    if (["declared-secret-publication", "unguarded-sensitive-state-write", "circuit-work-budget"].includes(detector)) continue;
    if (!Object.hasOwn(reasons, detector) || detector === "forbidden-state-transition" && policies.transitions.some(policy => policy.state === region.ledger)) {
      return { status: "ineligible", reason: "Selected detector has no qualified Counter absence contract", location: { ...region.location }, work: extracted.work };
    }
    certificates.push({ contract: "terminal-counter-absence-1", root: program.root, entry, detector: detector as CounterAbsenceDetector, reason: reasons[detector] });
  }
  return { ...extracted, certificates };
}
