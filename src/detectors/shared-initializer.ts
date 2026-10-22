import { SHARED_INITIALIZER_RULE, sharedInitializerTargets } from "../semantic/shared-initializer.js";
import { finding, unique, type Detector } from "./types.js";

export const sharedModuleOnceGate: Detector = {
  id: SHARED_INITIALIZER_RULE, defaultEnabled: false,
  description: "Distinct importing module wrappers expose one canonical false-guard then true-write Boolean gate",
  requires: ["resolved-model", "canonical-module-identities"],
  run(facts) {
    const result = sharedInitializerTargets(facts.program);
    facts.metrics.steps += result.work;
    facts.diagnostics.push(...result.gaps.map(gap => ({ code: "shared-gate-source-unavailable", message: gap.message, location: gap.location,
      scope: { kind: "rule" as const, detectorId: SHARED_INITIALIZER_RULE, entry: gap.entry } })));
    return unique(result.groups.map(group => finding(facts, {
      detectorId: SHARED_INITIALIZER_RULE, severity: "info", confidence: "high",
      title: "Distinct modules expose one shared once gate",
      message: `${group.wrappers.length} wrappers in distinct importing module instances call the same canonical Boolean gate, which asserts false then writes true. They share the represented state slot. A successful gate write contradicts its next false-state guard unless another operation resets the flag. Independent initialization intent, actual invocation order and deployed compiler behavior remain unproven; review intentional shared initialization.`,
      location: group.wrappers[0].call, constraint: group.guard, callPath: [],
      trace: [...group.wrappers.flatMap(wrapper => wrapper.imports.map(location => ({ kind: "call", label: "import of canonical shared gate module", location }))),
        { kind: "constraint", label: "require shared flag false", location: group.guard }, { kind: "effect", label: "write shared flag true", location: group.write }],
      remediation: "Confirm whether the modules intentionally share one initialization lifecycle. If each must initialize independently, give each module its own flag and guard. Retain intentional aliases of one shared module.",
      metadata: { reviewRequired: true, initializationIntent: "unknown", feasibility: "unproven", compilerBehavior: "represented-canonical-identity",
        evidence: "distinct-importing-modules-share-canonical-false-then-true-gate", gateIdentity: group.gate, ledgerIdentity: group.ledger,
        wrappers: group.wrappers, guard: group.guard, write: group.write, orderClaim: "successful-write-contradicts-next-guard-unless-reset" },
    }, `${group.gate}:${group.ledger}`)));
  },
};
