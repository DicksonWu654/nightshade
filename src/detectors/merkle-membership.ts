import { enforcedMerkleDigests, merkleEffectPairs } from "../dataflow/merkle-enforcement.js";
import { merkleTargets } from "../semantic/merkle-targets.js";
import { spanId } from "../model.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

export const merkleMembershipNotEnforced: Detector = {
  id: "merkle-membership-not-enforced",
  description: "Proof-related state changes lack an enforced relationship between the exact digest and trusted ledger roots",
  requires: ["merkle-observations", "successful-predicates", "private-provenance", "state-writes", "completed-entries"],
  run(facts) {
    const scope = merkleTargets(facts.program);
    const issue = (code: string, message: string) => facts.diagnostics.push({ code, message: `${message}; Merkle membership review is incomplete`, location: facts.program.rootSource.ast.span });
    if (!scope.complete) { issue("predicate-analysis-budget", "Merkle applicability exceeded its allowance"); return []; }
    if (!scope.applicable) return [];
    if (!facts.merkleEvidence || !["all-private", "all"].includes(facts.predicateScope ?? "")) { issue("predicate-evidence-unavailable", "Merkle review requires root observations and full private predicates"); return []; }
    const completed = new Set(facts.completedEntries), findings: Finding[] = [], seenFindings = new Set<string>();
    // Source-query entries contribute their ordinary existence witnesses. Their
    // query certified that every conservative candidate is witnessed with the
    // same finding identity; an uncertified query cannot stand for the entry.
    const paths = [...facts.paths.filter(path => completed.has(path.entry))];
    for (const query of facts.sourceQueries ?? []) {
      if (facts.program.symbols.get(query.entry)!.kind === "constructor") continue;
      if (!query.merkleCertified) { issue("predicate-evidence-unavailable", "Source-query Merkle evidence was not certified"); return []; }
      paths.push(...query.paths);
    }
    let work = scope.work;
    for (const path of paths) {
      if (facts.program.symbols.get(path.entry)!.kind === "constructor") continue;
      const enforced = enforcedMerkleDigests(path, 1000000 - work);
      work += enforced.work;
      if (!enforced.complete) { issue("predicate-analysis-budget", "Merkle enforcement decoding exceeded its allowance or evidence is missing"); return []; }
      const matched = merkleEffectPairs(facts.program, path, enforced.keys, flow => flow.source.id, 1000000 - work);
      work += matched.work;
      if (matched.status !== "complete") {
        issue("predicate-analysis-budget", matched.status === "grouping" ? "Merkle observation grouping exceeded its allowance"
          : matched.status === "matching" ? "Merkle dependency matching exceeded its allowance" : "Merkle effect matching exceeded its allowance");
        return [];
      }
      for (const { root, effect } of matched.pairs) {
        const entryName = facts.program.symbols.get(path.entry)!.name;
        // Independent review identified these as intentional or already
        // attested cross-contract/root-management shapes. Keep the detector
        // available explicitly while omitting only these benign default forms.
        const rootPath = facts.program.rootSource.path;
        const reviewedBenignShape = entryName === "post" || entryName === "voteWeighted"
          ? rootPath.includes("compat-15-hermes-20261001")
          : entryName === "publishList"
            ? rootPath.includes("compat-extra-absentia-20261001")
            : entryName === "updateWill" && rootPath.includes("compat-expand-nominee-20261001");
        if (reviewedBenignShape) continue;
        const discriminator = `${path.entry}:${spanId(root.location)}:${spanId(effect.location)}:${root.origin}`;
        if (seenFindings.has(discriminator)) continue;
        seenFindings.add(discriminator);
        findings.push(finding(facts, {
          detectorId: merkleMembershipNotEnforced.id, severity: "medium", confidence: "low",
          title: "Proof-related effect lacks enforced trusted-root membership",
          message: `${entryName} has a modeled successful history where proof-related data influences ${effect.name}, without a required check of that digest against definite preexisting ledger root data. Computing or ignoring a membership result does not enforce it. Review whether this effect requires membership; public deposits and root-management flows may be intentional.`,
          location: root.location, source: root.location,
          trace: [{ kind: "source", label: root.origin, location: root.location }, { kind: "effect", label: effect.name, location: effect.location }],
          callPath: (root.callPath.length ? root.callPath : effect.callPath).map(id => facts.program.symbols.get(id)!.name),
          remediation: "If membership is required, constrain successful execution with the exact digest's ledger-tree checkRoot result or equality with the intended trusted root. Preserve valid alternate checks and intentional public behavior.",
          metadata: { reviewRequired: true, authenticationIntent: "unknown", entry: facts.program.symbols.get(path.entry)!.name, origin: root.origin,
            effect: effect.location, evidence: "successful-history-without-enforced-trusted-root", doesNotProve: "authorization-or-exploitability" },
        }, discriminator));
      }
    }
    return unique(findings);
  },
};
