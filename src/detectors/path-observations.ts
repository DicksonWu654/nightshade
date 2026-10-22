import { relative } from "node:path";
import type { AbstractValue, SuccessfulPath } from "../dataflow/index.js";
import type { Program } from "../semantic/index.js";
import type { ResolvedPolicies } from "../policies.js";
import { type Finding, finding, unique } from "./types.js";

const names = (program: Program, path: string[]): string[] => path.map(id => program.symbols.get(id)?.name ?? id);

/** Shared predicates and finding construction for one actual abstract history.
 * Calling these helpers does not establish coverage of unvisited histories.
 */
export function secretPublicationOnPath(program: Program, path: SuccessfulPath, policies?: ResolvedPolicies, sinks = path.sinks): Finding[] {
  const results: Finding[] = [];
  for (const sink of sinks) for (const flow of sink.value.flows) {
    const policy = policies?.secrets.find(policy => policy.symbol === flow.source.symbol);
    if (!policy || (policy.sinkKinds && !policy.sinkKinds.includes(sink.kind)) || policy.allowedForms.includes(flow.form)) continue;
    results.push(finding({ program }, {
      detectorId: "declared-secret-publication", severity: "high", confidence: "medium", title: "Declared secret reaches a public sink",
      message: `Secret ${flow.source.name} influences ${sink.kind} ${sink.name} as ${flow.form} data, contrary to the configured privacy policy. Disclosure permission does not remove this dependency.`,
      location: sink.location, source: flow.source.location, trace: [...flow.trace, { kind: "sink", label: sink.name, location: sink.location }], callPath: names(program, sink.callPath),
      remediation: "Remove this public dependency, including private-controlled branch effects, or explicitly approve the transformation after reviewing the application's disclosure requirements.",
      metadata: { policyRequired: true, form: flow.form, sinkKind: sink.kind, visibility: sink.kind === "exported-return" ? "application-output" : "public-ledger", pathFeasibility: "not-proven" },
    }, `${relative(program.sourceRoot, flow.source.location.file)}:${flow.source.location.start}:${flow.source.name}`));
  }
  return unique(results);
}

export function unguardedWriteOnPath(program: Program, path: SuccessfulPath, policies?: ResolvedPolicies, writes = path.writes): Finding[] {
  const results: Finding[] = [];
  for (const write of writes) for (const policy of policies?.authorization ?? []) {
    if (write.ledger !== policy.state || write.guards.includes(policy.guard)) continue;
    const state = program.symbols.get(write.ledger)!;
    const guard = program.symbols.get(policy.guard)!;
    results.push(finding({ program }, {
      detectorId: "unguarded-sensitive-state-write", severity: "high", confidence: "medium", title: "Sensitive state write lacks its required guard",
      message: `State ${state.name} can be written without a preceding successful ${guard.name} call on this abstract execution path. The policy declares this guard mandatory; function names are not used to infer authorization.`,
      location: write.location, constraint: guard.span, trace: [{ kind: "state-write", label: state.name, location: write.location }], callPath: names(program, write.callPath),
      remediation: `Run the reviewed, constraining ${guard.name} circuit before this mutation on every successful path. Recheck after modifying state on which that guard depends.`,
      metadata: { state: state.name, requiredGuard: guard.name, pathFeasibility: "not-proven", guardSemantics: "policy-trusted-successful-void-call-before-write" },
    }, `${state.name}:${guard.name}`));
  }
  return unique(results);
}

export function forbiddenTransitionOnPath(program: Program, path: SuccessfulPath, policies?: ResolvedPolicies, writes = path.writes): Finding[] {
  const key = (value: AbstractValue): string | undefined => value.constant !== undefined && value.constantKind ? `${value.constantKind}:${value.constant}` : undefined;
  const results: Finding[] = [];
  for (const write of writes) for (const policy of policies?.transitions ?? []) {
    if (write.ledger !== policy.state || write.region.length) continue;
    const before = key(write.before), after = key(write.after);
    if (policy.from !== "*" && (before !== undefined && before !== policy.from || write.excludedBefore.includes(policy.from))) continue;
    if (policy.to !== "*" && after !== undefined && after !== policy.to) continue;
    const state = program.symbols.get(write.ledger)!;
    results.push(finding({ program }, {
      detectorId: "forbidden-state-transition", severity: "medium", confidence: "medium", title: "State write may permit a forbidden transition",
      message: `The write to ${state.name} does not exclude configured transition ${policy.from} → ${policy.to}. ${before === undefined ? "The preceding state is not fixed by modeled constraints." : "The preceding state is known on this path."}`,
      location: write.location, trace: [{ kind: "state-write", label: state.name, location: write.location }], callPath: names(program, write.callPath),
      remediation: "Constrain the current state before mutation so forbidden transitions cannot succeed. Use an explicit transition table and test terminal states separately.",
      metadata: { state: state.name, from: policy.from, to: policy.to, before: before ?? "unknown", after: after ?? "unknown", pathFeasibility: "not-proven", scope: "single-invocation" },
    }, `${state.name}:${policy.from}:${policy.to}`));
  }
  return unique(results);
}
