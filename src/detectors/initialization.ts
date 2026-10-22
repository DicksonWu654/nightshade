import { initializerEntries } from "../semantic/initializers.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

export const reInitialization: Detector = {
  id: "re-initialization",
  defaultEnabled: false,
  description: "Opt-in review of initializer-named entries with a state-changing second invocation",
  requires: ["consecutive-invocations", "completed-entries"],
  run(facts) {
    const candidates = initializerEntries(facts.program);
    if (!candidates.length) return [];
    if (!facts.initialization || candidates.some(entry => facts.completedEntries.includes(entry)
      && !facts.initialization!.some(row => row.entry === entry))) {
      facts.diagnostics.push({ code: "initialization-evidence-unavailable", message: "Initialization review requires consecutive invocation evidence; results are incomplete", location: facts.program.rootSource.ast.span });
      return [];
    }
    const findings: Finding[] = [];
    for (const row of facts.initialization) {
      if (!facts.completedEntries.includes(row.entry)) continue;
      const fn = facts.program.functions.get(row.entry)!;
      const pair = row.pairs.find(pair => pair.changes.length > 0);
      if (!pair) continue;
      const fields = [...new Set(pair.changes.map(change => facts.program.symbols.get(change.ledger)!.name))];
      findings.push(finding(facts, {
        detectorId: reInitialization.id, severity: "low", confidence: "low",
        title: "Initializer has a modeled state-changing second invocation",
        message: `${fn.symbol.name} has two consecutive modeled successful invocations from constructor/default storage, with fresh inputs and a potentially different surviving value in ${fields.join(", ")} after the second invocation. Review whether this entry is intended to run only once; its name alone does not establish that requirement.`,
        location: fn.declaration.span,
        trace: [...pair.first.path, ...pair.second.path], callPath: [fn.symbol.name],
        remediation: "If initialization must run once, require the pre-initialized state and preserve its transition on every successful invocation. Review intentional reconfiguration separately.",
        metadata: { reviewRequired: true, entry: fn.symbol.name, ledger: fields,
          candidateEvidence: "initializer-name", initializationIntent: "unknown",
          evidence: "consecutive-modeled-invocations-with-potential-storage-change",
          pathFeasibility: "not-proven", doesNotProve: "concrete-repeatability-or-exploitability",
          firstBranches: pair.first.path, secondBranches: pair.second.path },
      }, row.entry));
    }
    return unique(findings);
  },
};
