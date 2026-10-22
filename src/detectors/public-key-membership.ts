import { publicKeyMembershipObservations } from "../analysis/public-key-membership.js";
import { createHash } from "node:crypto";
import { immutableCollectionAddress, immutableOperandKey } from "../dataflow/immutable-key.js";
import { ReportIdentityKeys } from "../reporting/identity-keys.js";
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
    const reportedKeys = new WeakMap<object, { receiver: string; member: string; query: string }>();
    const identities = new ReportIdentityKeys(facts.program, publicKeyMembershipAuthorization.id, facts.program.rootSource.ast.span);
    // Report stable semantic tokens while the guard retains its original
    // physical-path equality keys. Reconstruct represented aggregates so an
    // already-hashed raw aggregate cannot carry a checkout path into metadata.
    const reported = (guard: typeof result.observations[number]["guard"], entry: string) => {
      const cached = reportedKeys.get(guard.query);
      if (cached) return cached;
      const normalize = facts.program.meteringIdentity;
      // Opaque analysis digests cannot be recovered from their spelling. Reject
      // those leaves throughout represented keys, including nested selectors
      // and byte projections, then use a source-occurrence report token.
      const opaque = /^(?:id:)?(?:native|hash-derived|collection-derived|merkle-digest|collection-query|hash-choice|hash-relation|expression|aggregate):[0-9a-f]{64}(?=$|::)/;
      let reconstructible = true;
      const canonicalize = (key: string) => {
        if (opaque.test(key)) reconstructible = false;
        return normalize(key);
      };
      const receiver = immutableCollectionAddress(guard.query.args[0], 4096, canonicalize, undefined, normalize);
      const member = immutableOperandKey(guard.query.args[1], 4096, canonicalize, undefined, normalize);
      const hash = (parts: unknown[]) => createHash("sha256").update(JSON.stringify(parts)).digest("hex");
      // A complete guard can have a pre-hashed aggregate whose represented
      // fields exceed the report reconstruction bound. Its source/query site
      // gives a stable namespace. Canonical companion recipes preserve distinctions between
      // branch values at that same site without exposing path-bearing digests.
      const value = reconstructible && receiver.complete && member.complete && receiver.key && member.key
        ? { receiver: normalize(receiver.key), member: member.key, query: `collection-query:${hash([normalize(receiver.key), guard.revision, member.key])}` }
        : (() => {
          const coordinates = [normalize(entry), facts.program.meteringPath(guard.source.location.file), guard.source.location.start,
            guard.source.invocation && { ...guard.source.invocation, site: normalize(guard.source.invocation.site) },
            facts.program.meteringPath(guard.query.location.file), guard.query.location.start,
            guard.query.callPath.map(normalize), guard.query.callSites?.map(site => [facts.program.meteringPath(site.file), site.start]),
            guard.queryIndex, guard.revision];
          const token = (raw: string) => hash([...coordinates, identities.opaqueIdentity(raw)]);
          return { receiver: `opaque-receiver:${token(guard.receiver)}`, member: `opaque-member:${token(guard.member)}`,
            query: `collection-query:${token(guard.query.result.identity!)}` };
        })();
      reportedKeys.set(guard.query, value);
      return value;
    };
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
            queryIndex: guard.queryIndex, queryResultIdentity: reported(guard, entry).query, receiverIdentity: reported(guard, entry).receiver,
            memberIdentity: reported(guard, entry).member, receiverRevision: guard.revision, receiverProvenance: [...guard.query.args[0].preexistingLedger!],
            nativeSource: guard.source, queryLocation: guard.query.location, queryCallIdentities: guard.query.callPath, queryCallSites: guard.query.callSites,
            predicateLocation: guard.predicate.location, predicateTruth: guard.predicate.truth,
            writesBeforeQuery: guard.query.writesBefore, writesBeforeGuard: guard.predicate.writesBefore,
            operationsBeforeGuard: guard.predicate.operationsBefore })) },
      }, `${entry}:${spanId(guard.predicate.location)}`);
    }));
  },
};
