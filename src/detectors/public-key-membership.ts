import { publicKeyMembershipObservations } from "../analysis/public-key-membership.js";
import { spanId } from "../model.js";
import { finding, unique, type Detector } from "./types.js";

export const publicKeyMembershipAuthorization: Detector = {
  id: "public-key-membership-authorization",
  description: "A raw native ownPublicKey selects a required member of preexisting public ledger storage before successful state-changing effects",
  defaultEnabled: true,
  requires: ["collection-observations", "successful-predicates", "successful-histories", "private-provenance", "state-writes", "runtime-operations", "completed-entries"],
  run(facts) {
    const result = publicKeyMembershipObservations(facts);
    facts.diagnostics.push(...result.diagnostics);
    const names = (ids: string[]) => ids.map(id => facts.program.symbols.get(id)?.name ?? id);
    return unique(result.observations.map(({ entry, guard, reaches }) => {
      const effects = [...new Map(reaches.map(({ effect }) => [JSON.stringify([effect.kind, spanId(effect.location), effect.callPath, effect.callSites.map(spanId), effect.occurrence]), effect])).values()];
      const histories = new Map([...new Set(reaches.map(reach => reach.path))].map((path, index) => [path, index]));
      const successfulReaches = new Set(reaches.map(({ path, effect }) => JSON.stringify([histories.get(path), effect.kind,
        spanId(effect.location), effect.callPath, effect.callSites.map(spanId), effect.occurrence]))).size;
      const entryName = names([entry])[0];
      return finding(facts, {
        detectorId: publicKeyMembershipAuthorization.id, severity: "high", confidence: "high",
        title: "Public-key membership gates state-changing effects",
        message: `${entryName} requires the exact raw native ownPublicKey to select a member of preexisting public Map/Set storage on every modeled successful reach of ${effects.length} affected effect invocation${effects.length === 1 ? "" : "s"}. Public identity membership does not establish possession of a secret. Sole-gate coverage and authentication intent remain unproven; review this trust boundary with the other protocol checks.`,
        location: guard.predicate.location, source: guard.source.location, constraint: guard.predicate.location,
        callPath: names(guard.query.callPath),
        trace: [{ kind: "source", label: "raw canonical native ownPublicKey", location: guard.source.location },
          { kind: "ledger-query", label: "preexisting public identity membership", location: guard.query.location },
          { kind: "constraint", label: "required exact membership result", location: guard.predicate.location },
          ...effects.flatMap(effect => [...effect.callSites.slice(1).map(location => ({ kind: "call", label: "effect invocation", location })),
            { kind: "effect", label: effect.name, location: effect.location }])],
        remediation: "If membership is intended to authenticate an identity, enforce the application's reviewed secret-possession or protocol proof. Review initialization, secret handling and replay assumptions; triage intentional public-identity validation with its protocol role.",
        metadata: { reviewRequired: true, evidence: "raw-native-public-key-membership-required", authorizationKind: "public-key-membership",
          rootCause: "native-witness-selects-preexisting-public-identity-member", comparedValue: "ledger-public", priority: "high",
          soleGate: "unproven", authenticationIntent: "unknown", pathFeasibility: "not-proven",
          confidenceScope: "required-static-membership-not-deployed-exploitability", historyCoverage: "exact-completed-entry-histories",
          entry: entryName, entryIdentity: entry, guardPosition: "before-effect",
          guardCallPath: names(guard.predicate.callPath), guardCallIdentities: guard.predicate.callPath, guardCallSites: guard.predicate.callSites,
          queryCallIdentities: guard.query.callPath, queryCallSites: guard.query.callSites,
          affectedEffects: effects.map(effect => ({ ...effect, callIdentities: effect.callPath, callPath: names(effect.callPath) })),
          invocationSites: [...new Map(effects.flatMap(effect => effect.callSites.map(site => [spanId(site), site] as const))).values()],
          successfulReaches, guardEffectRelations: reaches.length,
          historyEvidence: reaches.map(({ path, effect, guard }) => ({ branches: path.path, witnessCalls: [...path.witnessCalls!], effectKind: effect.kind, effectIndex: effect.index, effectOccurrence: effect.occurrence,
            effectCallIdentities: effect.callPath, effectCallSites: effect.callSites,
            queryIndex: guard.queryIndex, queryResultIdentity: guard.query.result.identity, receiverIdentity: guard.receiver,
            memberIdentity: guard.member, receiverRevision: guard.revision, receiverProvenance: [...guard.query.args[0].preexistingLedger!],
            nativeSource: guard.source, queryLocation: guard.query.location, queryCallIdentities: guard.query.callPath, queryCallSites: guard.query.callSites,
            predicateLocation: guard.predicate.location, predicateTruth: guard.predicate.truth,
            writesBeforeQuery: guard.query.writesBefore, writesBeforeGuard: guard.predicate.writesBefore,
            operationsBeforeGuard: guard.predicate.operationsBefore })) },
      }, `${entry}:${spanId(guard.predicate.location)}`);
    }));
  },
};
