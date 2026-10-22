import type { AnalysisFacts, PrivateSource, SuccessfulPath, SuccessfulPredicate } from "../dataflow/index.js";
import { predicateEvidence, predicateOperandKey, predicateSourceKey, publicOperand, rawWitnessSources, trustedPreimageSources } from "../dataflow/predicates.js";
import { constantOf } from "../dataflow/transfers.js";
import { spanId, type Span } from "../model.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

interface Guard {
  key: string;
  predicate: SuccessfulPredicate;
  source: Span;
  sources: string[];
  ledger: string[];
  signatureAttestation: boolean;
}
interface EffectReach {
  path: SuccessfulPath;
  kind: "ledger-write" | "kernel-write";
  index: number;
  name: string;
  location: Span;
  callPath: string[];
  callSites: Span[];
  guards: Map<string, Guard>;
  alternate: boolean;
}

type AuthorizationKind = "witness-only-authorization" | "public-key-equality" | "witness-validation";

/** Bound detector-side intersection work independently of engine enumeration. */
const MAX_GUARD_CHECKS = 1_000_000;

// A priority hint, never authentication or privilege evidence. Resolve the
// witness declaration so import aliases, helper names and aggregate projections
// cannot manufacture it. The accepted Boolean polarity is checked separately.
function signatureWitness(facts: AnalysisFacts, source: PrivateSource): boolean {
  const symbol = source.symbol && facts.program.symbols.get(source.symbol);
  if (!symbol || symbol.kind !== "witness" || symbol.type !== "Boolean") return false;
  const name = symbol.name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
  const validationOnly = name.split("_").some(word => ["format", "shape", "length", "width", "encoding", "syntax", "size", "structure", "schema", "formed"].includes(word));
  return !validationOnly && /(^|_)signature_valid$/.test(name);
}

export const spoofableAuthorization: Detector = {
  id: "spoofable-authorization",
  description: "A raw witness equality with public data is required for a state-changing effect; review the intended authentication",
  requires: ["successful-predicates", "private-provenance", "state-writes", "runtime-operations", "completed-entries"],
  run(facts) {
    const findings: Finding[] = [];
    let work = 0;
    const entries = [...facts.completedEntries.map(entry => ({ entry, paths: facts.paths.filter(path => path.entry === entry), query: undefined as NonNullable<AnalysisFacts["sourceQueries"]>[number] | undefined })),
      ...facts.sourceQueries?.map(query => ({ entry: query.entry, paths: query.paths, query })) ?? []];
    for (const { entry, paths, query } of entries) {
      if (!paths.length) continue;
      if (paths.some(path => path.predicates === undefined)) {
        facts.diagnostics.push({ code: "predicate-evidence-unavailable", message: "Successful predicate evidence is unavailable for authorization review; results are incomplete", location: facts.program.functions.get(entry)!.declaration.span });
        continue;
      }
      const groups = new Map<string, EffectReach[]>();
      let exhausted = false;
      let missingInvocation = false;
      for (const path of paths) {
        const guards = new Map<string, Guard>();
        const evidence = predicateEvidence(path, MAX_GUARD_CHECKS - work);
        work += evidence.work;
        if (!evidence.complete) { exhausted = true; break; }
        const preimages: PrivateSource[] = [];
        for (const { predicate, equality } of evidence.equalities) {
          if (++work > MAX_GUARD_CHECKS) { exhausted = true; break; }
          preimages.push(...trustedPreimageSources(equality));
          if (!equality.equals) continue;
          for (const [raw, available] of [[equality.left, equality.right], [equality.right, equality.left]]) {
            const sources = rawWitnessSources(raw);
            if (!sources.length || !publicOperand(available)) continue;
            const left = predicateOperandKey(raw, path), right = predicateOperandKey(available, path);
            if (!left || !right || left === right) continue;
            const key = JSON.stringify([left, right]);
            // Keep the first enforcement for its actual position in the history.
            const constant = constantOf(available);
            const signatureAttestation = constant?.kind === "boolean" && constant.value === "true" && sources.every(source => signatureWitness(facts, source));
            if (!guards.has(key)) guards.set(key, { key, predicate, source: sources[0].location, sources: sources.map(source => source.name), ledger: [...available.ledger], signatureAttestation });
          }
        }
        if (exhausted) break;
        const alternate = preimages.some(source => !evidence.publicValues.has(predicateSourceKey(source, path)));
        const effects = [
          ...path.writes.map((effect, index) => ({ ...effect, kind: "ledger-write" as const, name: facts.program.symbols.get(effect.ledger)!.name, index })),
          ...(path.operations ?? []).flatMap((effect, index) => effect.kind === "kernel-write" ? [{ ...effect, kind: "kernel-write" as const, index }] : []),
        ];
        for (const effect of effects) {
          if (++work > MAX_GUARD_CHECKS) { exhausted = true; break; }
          if (!effect.callSites) {
            exhausted = missingInvocation = true; break; // Exact engine must supply invocation evidence.
          }
          const key = JSON.stringify([effect.kind, spanId(effect.location), effect.callPath, effect.callSites.map(spanId)]);
          const reaches = groups.get(key) ?? [];
          reaches.push({ path, ...effect, callSites: effect.callSites, guards, alternate });
          groups.set(key, reaches);
        }
        if (exhausted) break;
      }
      const entryFindings: Finding[] = [];
      const guardEffects = new Map<string, { guard: Guard; reaches: EffectReach[]; soleGate: boolean }>();
      for (const [site, reaches] of groups) {
        if (exhausted) break;
        const unprotected = reaches.find(reach => !reach.alternate);
        if (!unprotected) continue;
        for (const [key, guard] of unprotected.guards) {
          const common = query ? query.requiredGuards.get(site)?.has(key) : reaches.every(reach => {
            if (++work > MAX_GUARD_CHECKS) { exhausted = true; return false; }
            return reach.guards.has(key);
          });
          if (exhausted) break;
          if (!common) continue;
          // The user-facing unit is a guard site in a circuit. Different path
          // histories can carry distinct operand identities for that same
          // source guard; they must not multiply the finding.
          const groupedKey = JSON.stringify([entry, spanId(guard.predicate.location)]);
          const grouped = guardEffects.get(groupedKey) ?? { guard, reaches: [], soleGate: true };
          // Quantify before location/invocation grouping discards histories.
          grouped.soleGate &&= query ? query.rawOnlyEffects.has(site) : reaches.every(reach => reach.path.checkCoverage === "raw-witness-only");
          if (grouped.guard !== guard) {
            grouped.guard.sources = [...new Set([...grouped.guard.sources, ...guard.sources])];
            grouped.guard.ledger = [...new Set([...grouped.guard.ledger, ...guard.ledger])];
            grouped.guard.signatureAttestation &&= guard.signatureAttestation;
          }
          const seen = new Set(grouped.reaches.map(reach => JSON.stringify([reach.kind, spanId(reach.location), reach.callPath, reach.callSites.map(spanId)])));
          for (const reach of reaches) {
            const reachKey = JSON.stringify([reach.kind, spanId(reach.location), reach.callPath, reach.callSites.map(spanId)]);
            if (!seen.has(reachKey)) grouped.reaches.push(reach);
          }
          guardEffects.set(groupedKey, grouped);
        }
      }
      if (!exhausted) for (const grouped of guardEffects.values()) {
        const representative = grouped.reaches[0];
        const result = makeFinding(facts, entry, representative, grouped.guard, grouped.reaches, grouped.soleGate);
        if (query) result.metadata = { ...result.metadata, historyCoverage: "shared-source-query-with-ordinary-witnesses" };
        // A receipt-only kernel claim coordinates the sender/recipient bookkeeping
        // of a shielded transfer. Independent review found these matches to be
        // either false positives or harmless coordination; they do not describe
        // caller authorization or an outgoing transfer.
        if (result.metadata.effectRoleEvidence === "receipt-coordination") continue;
        entryFindings.push(result);
      }
      if (exhausted) facts.diagnostics.push({ code: missingInvocation ? "predicate-evidence-unavailable" : "predicate-analysis-budget", message: missingInvocation
        ? "Effect invocation evidence is unavailable for authorization review; results are incomplete"
        : "Authorization predicate decomposition or required-guard intersection exceeded its bounded allowance; results are incomplete", location: facts.program.functions.get(entry)!.declaration.span });
      else findings.push(...entryFindings);
    }
    return unique(findings);
  },
};

function makeFinding(facts: AnalysisFacts, entry: string, reach: EffectReach, guard: Guard, reaches: EffectReach[], soleGate: boolean): Finding {
  const names = (ids: string[]) => ids.map(id => facts.program.symbols.get(id)?.name ?? id);
  const before = reach.kind === "ledger-write" ? guard.predicate.writesBefore <= reach.index : guard.predicate.operationsBefore <= reach.index;
  // Required equality is static evidence; the effect-role classification below
  // is a heuristic, not proof of authentication intent or a deployed bypass.
  const guardTrace = [{ kind: "source", label: "raw witness input", location: guard.source },
    { kind: "constraint", label: before ? "required witness equality before effect" : "required witness equality after effect", location: guard.predicate.location }];
  const effectMap = new Map<string, EffectReach>();
  for (const item of reaches) {
    const key = JSON.stringify([item.kind, spanId(item.location), item.callPath]);
    const previous = effectMap.get(key);
    if (previous) previous.callSites = [...new Map([...previous.callSites, ...item.callSites].map(site => [spanId(site), site] as const)).values()];
    else effectMap.set(key, { ...item, callSites: [...item.callSites] });
  }
  const allEffects = [...effectMap.values()];
  const effectTrace = allEffects.flatMap(item => [...item.callSites.slice(1).map(location => ({ kind: "call", label: "effect invocation", location })),
    { kind: "effect", label: item.name, location: item.location }]);
  const ledgerPublic = guard.ledger.length > 0 && reaches.every(item => (item.guards.get(guard.key)?.ledger.length ?? 0) > 0);
  const publicKeyEquality = ledgerPublic && guard.sources.some(source => source === "ownPublicKey");
  const entrySymbol = facts.program.symbols.get(entry)!;
  const setupOnly = entrySymbol.kind === "constructor";
  // A canonical receive claim declares coin-receipt coordination. It does not
  // itself authorize spending, minting or storage mutation. Classify the entire
  // grouped effect set, so another guarded write/spend keeps its usual priority.
  // Runtime operation kinds come from resolved Kernel transfers, not user names.
  const receiptOnly = allEffects.every(item => item.kind === "kernel-write" && item.name === "claimZswapCoinReceive");
  const effectNames = allEffects.filter(item => item.kind === "ledger-write").map(item => item.name.toLowerCase());
  // Compact has no authorization annotation. Keep this classification tied to
  // the observed circuit/effect role, including the ecosystem's setter names
  // (living-dividend, federation, recipient and attestor rotations), instead
  // of treating every witness assertion before an arbitrary write as admin
  // authentication. Receipt-only Kernel bookkeeping has no privileged role.
  const roleNameHeuristic = [entrySymbol.name.toLowerCase(), ...effectNames].some(name => /(mint|burn|transfer|send|owner|authority|role|member|kyc|admin|grant|revoke|permission|balance|supply|settle|claim|reissue|withdraw|deposit|approve|register|unregister|dividend|federation|attestor|recipient|rotation)/i.test(name));
  const privilegedEffect = !receiptOnly && (roleNameHeuristic || allEffects.some(item => item.kind === "kernel-write"));
  // Mixed receipt/storage groups retain their documented review priority, but
  // a receive declaration cannot establish the role of their storage effects.
  const nonReceiptKernelEffect = allEffects.some(item => item.kind === "kernel-write" && item.name !== "claimZswapCoinReceive");
  const signatureAttestation = !setupOnly && !receiptOnly && guard.signatureAttestation;
  const authorizationKind: AuthorizationKind = !setupOnly && !receiptOnly && publicKeyEquality ? "public-key-equality" : !setupOnly && (privilegedEffect || signatureAttestation) ? "witness-only-authorization" : "witness-validation";
  // The witness-name hint cannot supply the effect-role evidence for critical.
  const critical = authorizationKind === "witness-only-authorization" && privilegedEffect && !guard.ledger.length && soleGate;
  const attestationPriority = signatureAttestation && !privilegedEffect;
  const authorization = authorizationKind !== "witness-validation";
  const severity = critical ? "critical" : authorization ? "high" : "low";
  const confidence = authorization ? "high" : "low";
  const priority = critical ? "critical" : authorization ? "high" : "informational";
  return finding(facts, {
    detectorId: spoofableAuthorization.id, severity, confidence, title: receiptOnly ? "Witness validation gates coin receipt bookkeeping" : critical ? "Witness checks are the sole modeled gate for a privileged effect" : attestationPriority ? "Raw signature-attestation witness gates a state-changing effect" : authorizationKind === "witness-only-authorization" ? "Raw witness check gates a privileged effect" : authorizationKind === "public-key-equality" ? "Public-key equality gates a state-changing effect" : "Witness validation gates a state-changing effect",
    message: `${names([entry])[0]} requires raw witness data from ${[...new Set(guard.sources)].join(", ")} to equal ${guard.ledger.length ? `ledger ${names(guard.ledger).join(", ")}` : "a public constant"} on every modeled successful reach. The guard covers ${allEffects.length} effect site${allEffects.length === 1 ? "" : "s"}: ${allEffects.map(item => `${item.kind} ${item.name}`).join(", ")}. ${soleGate ? "Every successful history reaching these effects has only raw-witness/public-data checks; no additional modeled gate is present." : "Sole-gate coverage is unproven: another condition or implicit check is unclassified. At least one history lacks a modeled private-preimage check against preexisting ledger data."} ${receiptOnly ? "These affected effects declare coin receipt only; this finding does not characterize an outgoing transfer or caller authorization." : `${attestationPriority ? "High review priority uses the Boolean signature-witness name as a heuristic; it does not establish the effect role or authentication intent. " : ""}Equality alone does not demonstrate possession of a secret; review the intended authentication and protocol role.`}`,
    location: guard.predicate.location, source: guard.source, constraint: guard.predicate.location,
    trace: before ? [...guardTrace, ...effectTrace] : [...effectTrace, ...guardTrace],
    callPath: names(guard.predicate.callPath),
    remediation: receiptOnly ? "Review the intended coin-receipt coordination and recipient encoding. This receipt-only evidence establishes neither outgoing-transfer authorization nor whole-transaction receipt validity." : authorizationKind === "witness-validation" ? "Confirm that this witness check is validation rather than authentication. If it is intended as authentication, enforce a suitable secret-preimage or protocol-specific proof and document the protocol role." : "If this check is intended as authentication, enforce a suitable secret-preimage or protocol-specific proof. Review key initialization, secrecy and replay assumptions. Document and triage intentional public-data validation.",
    metadata: { reviewRequired: true, evidence: "raw-witness-equality-required", comparedValue: ledgerPublic ? "ledger-public" : "public-constant", authorizationKind, priority,
      soleGate: soleGate ? "proven-in-model" : "unproven",
      rootCause: receiptOnly ? "receipt-coordination" : critical ? "raw-witness-checks-are-the-only-modeled-gates" : authorizationKind === "witness-only-authorization" ? "required-witness-result-without-a-modeled-private-preimage-check" : authorizationKind === "public-key-equality" ? "native-witness-compared-with-ledger-public-identity" : "witness-validation-or-setup-check",
      effectRoleEvidence: receiptOnly ? "receipt-coordination" : nonReceiptKernelEffect ? "kernel-effect" : roleNameHeuristic ? "circuit-or-ledger-name-heuristic" : "unclassified",
      ...(attestationPriority ? { priorityEvidence: "boolean-signature-witness-name-heuristic" } : {}),
      confidenceScope: "required-static-equality-not-deployed-exploitability", pathFeasibility: "not-proven", authenticationIntent: "unknown", entry: names([entry])[0],
      guardCallPath: names(guard.predicate.callPath), guardCallSites: guard.predicate.callSites, effectCallSites: reach.callSites,
      affectedEffects: allEffects.map(item => ({ kind: item.kind, name: item.name, location: item.location, callPath: names(item.callPath), callSites: item.callSites })),
      invocationSites: [...new Map(allEffects.flatMap(item => item.callSites.map(site => [spanId(site), site] as const))).values()],
      successfulReaches: reaches.length, rawOnlyReaches: reaches.filter(reach => !reach.alternate).length,
      effectIndex: reach.index, guardPosition: before ? "before-effect" : "after-effect", guardTruth: guard.predicate.truth,
      writesBeforeGuard: guard.predicate.writesBefore, operationsBeforeGuard: guard.predicate.operationsBefore },
  }, `${entry}:${spanId(guard.predicate.location)}:${guard.sources.join(",")}`);
}
