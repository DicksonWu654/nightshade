import { OZ_POLICY_REVISION, openzeppelinIdentities } from "../semantic/openzeppelin-identities.js";
import type { AnalysisFacts, CallReach } from "../dataflow/index.js";
import { uncoveredDeclarations } from "../analysis/assertions.js";
import { spanId, type Span } from "../model.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

export { OZ_POLICY_REVISION } from "../semantic/openzeppelin-identities.js";

export const openzeppelinPreconditions: Detector = {
  id: "openzeppelin-preconditions",
  description: "Opt-in documented preconditions of authenticated OpenZeppelin Compact modules",
  requires: ["resolved-calls", "call-reaches", "complete-caller-coverage", "builtin-policy"],
  policyRequired: true,
  run(facts, policies) {
    if (!policies?.builtins?.length) return [];
    const identity = openzeppelinIdentities(facts.program, policies.builtins);
    const findings: Finding[] = [];
    if (identity.functions.size && !facts.callReaches) facts.diagnostics.push({
      code: "call-observation-unavailable", message: "Built-in preconditions require exact call observations; results are incomplete",
      location: facts.program.rootSource.ast.span,
    });
    const complete = new Set(facts.completedEntries), uncovered = uncoveredDeclarations(facts);
    const sites = new Map<string, CallReach[]>();
    for (const reach of facts.callReaches ?? []) {
      const key = spanId(reach.location);
      sites.set(key, [...(sites.get(key) ?? []), reach]);
    }
    const covered = (reach: CallReach): boolean => {
      const owner = facts.program.functions.get(reach.owner);
      return complete.has(reach.entry) && !!owner && !uncovered.has(spanId(owner.declaration.span));
    };
    for (const reaches of sites.values()) {
      if (!reaches.every(covered)) continue;
      const reach = reaches[0], module = identity.functions.get(reach.callee);
      // Report at application boundaries, not duplicate failures inside the
      // authenticated library implementation.
      if (!module || identity.authenticated(reach.location) || reaches.some(item => !identity.functions.has(item.callee))) continue;
      const callee = facts.program.functions.get(reach.callee)!;
      const outsideConstructor = module.name === "Ownable" && callee.symbol.name === "initialize"
        && reaches.some(item => facts.program.symbols.get(item.entry)?.kind !== "constructor");
      const alwaysRejects = reaches.every(item => !item.maySucceed && !item.failedWithoutAssertion && item.failure
        && identity.authenticated(item.failure.location));
      if (!outsideConstructor && !alwaysRejects) continue;
      const evidence = outsideConstructor ? reaches.find(item => facts.program.symbols.get(item.entry)?.kind !== "constructor")! : reach;
      const failure = reaches.find(item => item.failure)?.failure;
      findings.push(finding(facts, {
        detectorId: openzeppelinPreconditions.id, severity: "medium", confidence: "high",
        title: outsideConstructor ? "Ownable initialization is outside construction" : "OpenZeppelin call cannot satisfy its preconditions",
        message: outsideConstructor
          ? "The pinned Ownable module documents that initialize must be called in the contract constructor. This call is reachable outside construction."
          : `Every analyzed path reaching ${module.name}.${callee.symbol.name} at this call site rejects inside the authenticated library. One rejecting trace reports ${failure!.message}. Successful invocations at other sites do not make this call usable.`,
        location: reach.location, constraint: outsideConstructor ? callee.declaration.span : failure!.location,
        trace: outsideConstructor ? [{ kind: "call", label: "Ownable.initialize outside constructor", location: reach.location }] : [...failure!.path, { kind: "constraint", label: failure!.message, location: failure!.location }],
        callPath: (outsideConstructor ? evidence.callPath : failure!.callPath).map(id => facts.program.symbols.get(id)?.name ?? id),
        remediation: outsideConstructor ? "Initialize Ownable from the constructor with a valid nonzero account identifier."
          : "Correct this call's ordering, state or arguments to satisfy the documented precondition; preserve guards that intentionally reject invalid inputs.",
        metadata: { builtinPolicy: module.policy, libraryRevision: OZ_POLICY_REVISION,
          precondition: outsideConstructor ? "constructor-only" : "call-always-rejects", callSiteUniversal: !outsideConstructor },
      }));
    }
    for (const entry of facts.program.entries) {
      const module = identity.functions.get(entry), fn = facts.program.functions.get(entry)!;
      if (module?.name !== "Ownable" || fn.symbol.name !== "initialize") continue;
      const edge = identity.instances.find(edge => entry.startsWith(`${edge.target}::`))!;
      findings.push(finding(facts, {
        detectorId: openzeppelinPreconditions.id, severity: "medium", confidence: "high",
        title: "Ownable initializer is exported as an entrypoint",
        message: "The authenticated Ownable.initialize circuit is directly exposed as an entrypoint. The pinned module documents that initialization must occur during construction.",
        location: edge.location, constraint: fn.declaration.span,
        trace: [{ kind: "export", label: "Ownable.initialize exposed outside construction", location: edge.location }], callPath: [fn.symbol.name],
        remediation: "Call Ownable.initialize from the constructor instead of re-exporting the imported initializer.",
        metadata: { builtinPolicy: module.policy, libraryRevision: OZ_POLICY_REVISION, precondition: "constructor-only", callSiteUniversal: false },
      }));
    }
    const initializable = identity.instances.filter(edge => identity.authenticated(edge.declaration)?.name === "Initializable");
    const owners = new Set(initializable.map(edge => edge.owner));
    for (const edge of initializable) if (!edge.topLevel || owners.size > 1) findings.push(finding(facts, {
      detectorId: openzeppelinPreconditions.id, severity: "medium", confidence: "high",
      title: "Initializable import violates its documented composition restriction",
      message: "The pinned Initializable module requires use at the top contract layer and import into at most one module per contract. This resolved import violates that documented restriction. This check does not model or reproduce the upstream compiler state-deduplication issue.",
      location: edge.location, constraint: edge.declaration,
      trace: [{ kind: "import", label: "Initializable composition restriction", location: edge.location }], callPath: [],
      remediation: "Import Initializable directly at the top contract layer; give composed modules their own initialization state as documented by OpenZeppelin.",
      metadata: { builtinPolicy: "openzeppelin-initializable", libraryRevision: OZ_POLICY_REVISION, precondition: "top-level-single-importer", importers: owners.size },
    }));
    return unique(findings);
  },
};
