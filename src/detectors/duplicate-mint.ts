import { shieldedMintKey } from "../dataflow/mint-inputs.js";
import { successfulConstants } from "../dataflow/successful-constants.js";
import { hasShieldedMint, SHIELDED_MINT } from "../semantic/mint-targets.js";
import { finding, type Detector, type Finding } from "./types.js";

export const duplicateShieldedMint: Detector = {
  id: "duplicate-shielded-mint",
  description: "Identical canonical shielded mint inputs produce a duplicate coin commitment in one transaction",
  requires: ["resolved-calls", "cfg", "successful-predicates", "canonical-mint-observations"],
  run(facts) {
    const relevant = facts.program.entries.filter(entry => hasShieldedMint(facts.program, entry));
    if (!relevant.length) return [];
    if (!facts.mintEvidence || facts.predicateScope !== "all") {
      facts.diagnostics.push({ code: "duplicate-mint-evidence-unavailable", message: "Exact canonical mint operands and successful constraints are required; rule is incomplete", location: facts.program.rootSource.ast.span });
      return [];
    }
    let work = 0;
    const findings = new Map<string, Finding>();
    for (const path of facts.paths) {
      if (!facts.completedEntries.includes(path.entry)) continue;
      const constants = successfulConstants(path, Math.min(100000, 1000000 - work));
      let evidenceComplete = true;
      const seen = new Map<string, NonNullable<typeof path.operations>[number]>();
      for (const operation of path.operations ?? []) {
        if (operation.kind !== "shielded-mint" || operation.name !== SHIELDED_MINT) continue;
        const result = shieldedMintKey(operation.args, constants, Math.min(4096, 1000000 - work));
        work += result.work;
        if (!result.complete) { evidenceComplete = false; break; }
        if (!result.key) continue;
        const previous = seen.get(result.key);
        if (!previous) { seen.set(result.key, operation); continue; }
        const name = facts.program.symbols.get(path.entry)!.name;
        const item = finding(facts, {
          detectorId: duplicateShieldedMint.id, severity: "medium", confidence: "high",
          title: "Duplicate shielded mint commitment",
          message: `${name} invokes mintShieldedToken twice with provably identical token domain, amount, nonce and active recipient on one modeled successful history. The pinned library derives the same coin commitment in this contract context; duplicate commitments are rejected by the ledger. This is a transaction availability defect, not proof of token theft or a generic commitment-opening vulnerability.`,
          location: operation.location, source: previous.location,
          trace: [{ kind: "effect", label: "first identical mint", location: previous.location }, { kind: "effect", label: "duplicate mint", location: operation.location }],
          callPath: operation.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
          remediation: "Use a distinct nonce for each minted output, for example evolveNonce with a distinct index. Review freshness across separate transactions independently.",
          metadata: { entry: name, evidence: "identical-canonical-mint-inputs", pathFeasibility: "not-proven",
            affectedEffects: [previous.location, operation.location], invocationSites: [previous.callSites ?? [], operation.callSites ?? []] },
        }, path.entry);
        const prior = findings.get(item.fingerprint);
        if (prior) for (const key of ["affectedEffects", "invocationSites"] as const) {
          const values = [...prior.metadata[key] as unknown[], ...item.metadata[key] as unknown[]];
          prior.metadata[key] = [...new Map(values.map(value => [JSON.stringify(value), value])).values()];
        } else findings.set(item.fingerprint, item);
      }
      work += constants.work;
      if (!evidenceComplete || !constants.complete || work > 1000000) {
        facts.diagnostics.push({ code: "duplicate-mint-evidence-budget", message: "Canonical mint equality evidence exhausted its bounded allowance; rule is incomplete", location: facts.program.functions.get(path.entry)!.declaration.span });
        return [];
      }
    }
    return [...findings.values()];
  },
};
