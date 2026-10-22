import { roleBootstrapObservations } from "../analysis/role-bootstrap.js";
import { OZ_POLICY_REVISION, SHIELDED_ACCESS_CONTROL_IDENTITY } from "../semantic/openzeppelin-identities.js";
import { finding, type Detector } from "./types.js";
import type { AnalysisFacts } from "../dataflow/index.js";

export function roleBootstrapFindings(facts: AnalysisFacts, allowance = 200000) {
    const result = roleBootstrapObservations(facts, allowance);
    if (!result.complete) {
      for (const entry of facts.program.entries) facts.diagnostics.push({
        code: result.unsupportedProfile ? "role-bootstrap-profile-unavailable" : result.needsConstructor ? "role-bootstrap-constructor-incomplete" : result.unresolvedCall ? "role-bootstrap-unresolved-call" : "role-bootstrap-observation-budget",
        message: "Role-bootstrap absence is unavailable: the pinned profile, constructor histories or conservative source traversal did not qualify",
        location: facts.program.functions.get(entry)!.declaration.span, scope: { kind: "rule", detectorId: "missing-role-bootstrap", entry },
      });
      return [];
    }
    return result.observations.map(item => finding(facts, {
      detectorId: "missing-role-bootstrap", severity: "low", confidence: "high",
      title: "ShieldedAccessControl has no role bootstrap route",
      message: "The authenticated instance initializes in every modeled successful constructor history, but no entry-reachable source route seeds any role. Its guarded grantRole requires an existing role holder and cannot bootstrap the empty role tree. The published library requires a separate initial role grant; initialize stores initialization state and salt only.",
      location: item.location, constraint: item.initializer,
      trace: [{ kind: "import", label: "Authenticated ShieldedAccessControl instance", location: item.location }], callPath: [],
      remediation: "Seed a role holder using _grantRole during construction, typically DEFAULT_ADMIN_ROLE. Preserve deliberate delayed setup routes and custom seeded administrator relationships.",
      metadata: { instance: item.instance, libraryRevision: OZ_POLICY_REVISION, librarySha256: SHIELDED_ACCESS_CONTROL_IDENTITY.hash,
        missing: "any-role-seeding-route", protectedCircuits: item.protectedCircuits.map(id => facts.program.symbols.get(id)?.name ?? id),
        evidence: "complete-constructor-and-conservative-source-absence", work: result.work, allowance },
    }, item.instance));
}

export const missingRoleBootstrap: Detector = {
  id: "missing-role-bootstrap",
  description: "An authenticated ShieldedAccessControl instance initializes but has no role-seeding route",
  defaultEnabled: true,
  requires: ["resolved-calls", "module-identities", "constructor-histories"],
  run: facts => roleBootstrapFindings(facts),
};
