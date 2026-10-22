import { ReportIdentityKeys } from "../reporting/identity-keys.js";
import { callerEqualityObservations } from "../analysis/caller-equality.js";
import { CALLER_EQUALITY_RULE } from "../semantic/caller-equality-targets.js";
import { spanId } from "../model.js";
import { finding, type Detector } from "./types.js";

export const callerSuppliedLedgerEquality: Detector = {
  id: CALLER_EQUALITY_RULE, defaultEnabled: false,
  description: "An unchanged caller input must equal preexisting public ledger bytes before a state-changing effect",
  requires: ["all-successful-predicates", "private-provenance", "exact-effect-histories"],
  run(facts) {
    const report = new ReportIdentityKeys(facts.program, CALLER_EQUALITY_RULE, facts.program.rootSource.ast.span);
    const result = callerEqualityObservations(facts);
    facts.diagnostics.push(...result.diagnostics);
    return result.observations.map(({ entry, guard, reaches }) => {
      const names = (ids: string[]) => ids.map(id => facts.program.symbols.get(id)!.name);
      const effects = [...new Map(reaches.map(reach => [JSON.stringify([reach.effect.kind, spanId(reach.effect.location), reach.effect.callPath, reach.effect.callSites.map(spanId), reach.effect.occurrence]), reach.effect])).values()];
      return finding(facts, {
        detectorId: CALLER_EQUALITY_RULE, severity: "medium", confidence: "high",
        title: "Caller input equality with public ledger bytes gates an effect",
        message: `${names([entry])[0]} requires an unchanged caller-supplied Bytes<32> input to equal definite preexisting public ledger data before every modeled successful reach of ${effects.length} effect site(s). At least one reaching history lacks the supported private-preimage check against preexisting ledger data. This equality alone does not establish secret possession. Other protocol checks may apply; routing and record-consistency checks can intentionally match.`,
        location: guard.predicate.location, source: guard.supplied.location,
        trace: [{ kind: "source", label: "unchanged caller input", location: guard.supplied.location },
          { kind: "constraint", label: "required equality with preexisting public ledger bytes", location: guard.predicate.location },
          ...effects.map(effect => ({ kind: "sink", label: `${effect.kind} ${effect.name}`, location: effect.location }))],
        callPath: names(guard.predicate.callPath),
        remediation: "If the supplied bytes represent an authorized caller, enforce the protocol's reviewed secret-possession or signature relationship. Preserve message/domain/replay binding. Document intentional routing or record consistency; no authentication defect is established by this finding alone.",
        metadata: { reviewRequired: true, evidence: "required-caller-input-ledger-equality", entry: names([entry])[0],
          suppliedInput: guard.supplied.name, ledger: names(guard.ledger), soleGate: "unproven", authenticationIntent: "unknown",
          confidenceScope: "required-static-equality", pathFeasibility: "not-proven", guardPosition: "before-effect",
          affectedEffects: effects.map(effect => ({ ...effect, callIdentities: effect.callPath, callPath: names(effect.callPath) })),
          historyEvidence: reaches.map(({ path, effect, guard: match }) => ({ branches: path.path, effect,
            supplied: match.supplied, ledger: names(match.ledger), ledgerIdentity: report.key(match.ledgerIdentity),
            predicateLocation: match.predicate.location, predicateCallPath: match.predicate.callPath, predicateCallSites: match.predicate.callSites,
            writesBefore: match.predicate.writesBefore, operationsBefore: match.predicate.operationsBefore })) },
      }, `${entry}:${spanId(guard.predicate.location)}`);
    });
  },
};
