import { relative } from "node:path";
import { estimateWork } from "../analysis/work.js";
import { universallyFailedAssertions } from "../analysis/assertions.js";
import { AbstractValue, AnalysisFacts } from "../dataflow/index.js";
import { Detector, Finding, finding, unique } from "./types.js";
import { secretPublicationOnPath, unguardedWriteOnPath, forbiddenTransitionOnPath } from "./path-observations.js";

const names = (facts: AnalysisFacts, path: string[]): string[] => path.map(id => facts.program.symbols.get(id)?.name ?? id);
const key = (value: AbstractValue): string | undefined => value.constant !== undefined && value.constantKind ? `${value.constantKind}:${value.constant}` : undefined;
const known = (value: AbstractValue): boolean => key(value) !== undefined || Boolean(value.items?.every(known)) || Boolean(value.fields && Object.values(value.fields).every(known));

export const secretPublication: Detector = {
  id: "declared-secret-publication",
  description: "Policy-declared secret information reaches a public sink through an unapproved transformation",
  requires: ["private-provenance", "implicit-flows", "public-sinks", "privacy-policy"],
  policyRequired: true,
  run(facts, policies) {
    return unique(facts.paths.flatMap(path => secretPublicationOnPath(facts.program, path, policies)));
  },
};

export const unguardedWrite: Detector = {
  id: "unguarded-sensitive-state-write",
  description: "A successful path writes policy-protected state without the configured preceding guard",
  requires: ["successful-paths", "state-writes", "guard-calls", "authorization-policy"],
  policyRequired: true,
  run(facts, policies) {
    return unique(facts.paths.flatMap(path => unguardedWriteOnPath(facts.program, path, policies)));
  },
};

export const forbiddenTransition: Detector = {
  id: "forbidden-state-transition",
  description: "A scalar state write may cross a transition explicitly forbidden by policy",
  requires: ["successful-paths", "state-writes", "constant-constraints", "transition-policy"],
  policyRequired: true,
  run(facts, policies) {
    return unique(facts.paths.flatMap(path => forbiddenTransitionOnPath(facts.program, path, policies)));
  },
};

export const predictableCommitment: Detector = {
  id: "predictable-commitment-randomness",
  description: "A published private-derived commitment uses statically known randomness",
  requires: ["private-provenance", "commitments", "public-sinks", "constants"],
  run(facts) {
    const results: Finding[] = [];
    // The pinned stdlib intentionally uses persistentCommit as domain-separated
    // public token derivation. Authenticate its resolved declaration; a user
    // circuit with the same name or salt does not inherit this exception.
    const tokenType = facts.program.functions.get("standard-library::tokenType")?.declaration;
    for (const path of facts.paths) for (const sink of path.sinks) for (const commitment of sink.value.commitments ?? []) {
      if (!commitment.input.flows.length || !known(commitment.randomness)) continue;
      if (tokenType && commitment.location.file === tokenType.span.file
        && commitment.location.start >= tokenType.span.start && commitment.location.end <= tokenType.span.end) continue;
      results.push(finding(facts, {
        detectorId: predictableCommitment.id, severity: "medium", confidence: "high", title: "Public commitment uses predictable randomness",
        message: `${commitment.primitive} commits private-derived input using statically known randomness, and its result influences ${sink.kind} ${sink.name}. This removes the protection supplied by secret, unpredictable commitment randomness; low-entropy inputs can remain guessable. Intentional deterministic commitments require review.`,
        location: sink.location, source: commitment.location, trace: [{ kind: "commitment", label: commitment.primitive, location: commitment.location }, { kind: "sink", label: sink.name, location: sink.location }], callPath: names(facts, sink.callPath),
        remediation: "Use independently generated, sufficiently entropic private randomness appropriate to the primitive and protocol. Do not replace intentional deterministic protocol commitments without reviewing compatibility.",
        metadata: { primitive: commitment.primitive, reviewRequired: true, entropyAnalysis: "constant-only", pathFeasibility: "not-proven" },
      }, `${relative(facts.program.sourceRoot, commitment.location.file)}:${commitment.location.start}`));
    }
    return unique(results);
  },
};

export const impossibleAssertion: Detector = {
  id: "impossible-assertion",
  description: "A nonliteral assertion fails on every reaching path, or an entry has no successful path",
  requires: ["cfg", "constants", "path-constraints", "failed-assertions", "assertion-reaches", "completed-entries"],
  run(facts) {
    const failures = universallyFailedAssertions(facts);
    const results = failures.map(failure => finding(facts, {
      detectorId: impossibleAssertion.id, severity: "medium", confidence: "high", title: "Assertion fails on every reaching path",
      message: `Assertion ${failure.message} is false on every modeled path that reaches this source site. All entrypoints that may call it completed analysis, and no reaching invocation could pass it.`,
      location: failure.location, trace: [...failure.path, { kind: "failed-assertion", label: failure.message, location: failure.location }], callPath: names(facts, failure.callPath),
      remediation: "Check the assertion and preceding constraints for a contradiction. Preserve guards that reject invalid inputs while allowing intended inputs to succeed.",
      metadata: { reviewRequired: true, reachability: "abstract-path", certainty: "fails-on-every-reaching-path", successfulMutation: false },
    }));
    const successful = new Set(facts.paths.map(path => path.entry));
    const explained = new Set(failures.map(failure => failure.callPath[0]));
    for (const entry of facts.completedEntries) {
      if (successful.has(entry) || explained.has(entry)) continue;
      const fn = facts.program.functions.get(entry)!;
      const failure = facts.failedAssertions.find(failure => failure.callPath[0] === entry);
      results.push(finding(facts, {
        detectorId: impossibleAssertion.id, severity: "medium", confidence: "high", title: "Entrypoint has no successful path",
        message: `${fn.symbol.name} has no successful path under the modeled constants and constraints after complete entry analysis. This may be an intentionally disabled entrypoint; it is not evidence of a successful state change.`,
        location: fn.declaration.span, trace: failure ? [...failure.path, { kind: "failed-assertion", label: failure.message, location: failure.location }] : [{ kind: "analysis", label: "complete entry analysis; no successful path", location: fn.declaration.span }], callPath: [fn.symbol.name],
        remediation: "Check whether the entrypoint should accept any inputs. Review its assertions and checked operations for contradictions; document an intentionally disabled entrypoint.",
        metadata: { reviewRequired: true, reachability: "abstract-path", certainty: "no-successful-path", successfulMutation: false },
      }, entry));
    }
    return unique(results);
  },
};

export const workBudget: Detector = {
  id: "circuit-work-budget",
  description: "Expanded source-operation estimate exceeds an explicit circuit work budget",
  requires: ["cfg", "resolved-calls", "static-loop-bounds", "work-policy"],
  policyRequired: true,
  run(facts, policies) {
    const results: Finding[] = [];
    for (const policy of policies?.workBudgets ?? []) {
      const estimate = estimateWork(facts.program, policy.circuit);
      const circuit = facts.program.symbols.get(policy.circuit)!;
      if (!estimate) {
        facts.diagnostics.push({ code: "work-estimate-unavailable", message: `Cannot establish a finite source-work estimate for policy circuit ${circuit.name}; its budget was not checked`, location: circuit.span });
        continue;
      }
      if (estimate.units <= policy.maxUnits) continue;
      results.push(finding(facts, {
        detectorId: workBudget.id, severity: "low", confidence: "high", title: "Circuit exceeds its declared source-work budget",
        message: `${circuit.name} has an expanded source-operation upper bound of ${estimate.units} units, exceeding policy budget ${policy.maxUnits}. This is a source-level complexity measure, not measured proof rows, runtime, or evidence of an attacker-controlled unbounded loop.`,
        location: circuit.span, trace: [], callPath: [circuit.name],
        remediation: "Review loop sizes and repeated callee work; measure actual compiler/prover cost before adjusting the explicit budget.",
        metadata: { ...estimate, budget: policy.maxUnits, estimateOnly: true },
      }));
    }
    return results;
  },
};
