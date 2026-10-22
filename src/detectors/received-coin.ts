import { receivedCoinValidation } from "../dataflow/coin-validation.js";
import { mayReceiveShielded, RECEIVE_SHIELDED } from "../semantic/value-transfers.js";
import { spanId, type Span } from "../model.js";
import { finding, type Detector, type Finding } from "./types.js";

export const receivedCoinNotValidated: Detector = {
  id: "received-coin-not-validated",
  description: "Received shielded coin lacks a recorded application constraint on color or value",
  defaultEnabled: false,
  requires: ["successful-predicates", "all-predicates", "runtime-operations", "completed-entries"],
  run(facts) {
    const scope = mayReceiveShielded(facts.program);
    const issue = (code: string, message: string, location: Span = facts.program.rootSource.ast.span) =>
      facts.diagnostics.push({ code, message: `${message}; received-coin review is incomplete`, location });
    if (!scope.complete) { issue("predicate-analysis-budget", "Received-coin applicability exceeded its allowance"); return []; }
    if (!scope.applicable) return [];
    if (facts.predicateScope !== "all") { issue("predicate-evidence-unavailable", "Received-coin review requires complete public and private predicates"); return []; }
    const findings: Finding[] = [];
    let work = scope.work;
    for (const entry of facts.completedEntries) {
      const groups = new Map<string, { location: Span; callPath: string[]; missing: Set<string>; reaches: number; unconstrained: number }>();
      for (const path of facts.paths) {
        if (path.entry !== entry) continue;
        for (const operation of path.operations ?? []) {
          if (++work > 1000000) { issue("predicate-analysis-budget", "Received-coin query exceeded its allowance"); return []; }
          if (operation.kind !== "native-witness" || operation.name !== "createZswapOutput") continue;
          const index = operation.callPath.indexOf(RECEIVE_SHIELDED);
          if (index < 0) continue;
          const location = operation.callSites?.[index], coin = operation.args[0];
          if (!location || !coin) { issue("predicate-evidence-unavailable", "Received-coin operand or invocation is missing", operation.location); return []; }
          const checked = receivedCoinValidation(path, coin, Math.min(100000, 1000000 - work)); work += checked.work;
          if (!checked.complete) { issue("predicate-analysis-budget", "Received-coin constraint evidence is unavailable or exceeded its allowance", location); return []; }
          const key = JSON.stringify(operation.callSites!.slice(0, index + 1).map(spanId));
          const group = groups.get(key) ?? { location, callPath: operation.callPath.slice(0, index + 1), missing: new Set<string>(), reaches: 0, unconstrained: 0 };
          group.reaches++;
          if (!checked.color) group.missing.add("color");
          if (!checked.value) group.missing.add("value");
          if (!checked.color || !checked.value) group.unconstrained++;
          groups.set(key, group);
        }
      }
      for (const [site, group] of groups) {
        if (!group.missing.size) continue;
        const name = facts.program.symbols.get(entry)!.name, missing = [...group.missing].sort();
        findings.push(finding(facts, {
          detectorId: receivedCoinNotValidated.id, severity: "low", confidence: "low", title: "Review received coin color and value constraints",
          message: `${name} receives a shielded coin with a missing recognized application constraint on one or more of: ${missing.join(", ")}. This affects ${group.unconstrained} of ${group.reaches} modeled successful receives at this invocation. Protocol receipt alone does not check expected payment terms. Unrestricted deposits may be intentional.`,
          location: group.location, trace: [{ kind: "effect", label: "receiveShielded", location: group.location }],
          callPath: group.callPath.map(id => facts.program.symbols.get(id)!.name),
          remediation: "If this is a payment, check this coin's expected color and amount against constants or trusted ledger terms. Record intentional unrestricted receipt in the application policy.",
          metadata: { reviewRequired: true, paymentIntent: "unknown", pathFeasibility: "not-proven", entry: name, missingConstraints: missing,
            successfulReceives: group.reaches, unconstrainedReceives: group.unconstrained, evidence: "exact-received-coin-operands", scope: "receiveShielded; equality or value lower bound to constant/preexisting ledger" },
        }, `${entry}:${site}`));
      }
    }
    return findings;
  },
};
