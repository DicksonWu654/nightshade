import { transientLedgerObservations } from "../analysis/transient-ledger.js";
import { TRANSIENT_LEDGER_RULE } from "../semantic/transient-targets.js";
import { finding, type Detector } from "./types.js";

export const transientDigestToLedger: Detector = {
  id: TRANSIENT_LEDGER_RULE, defaultEnabled: false,
  description: "Terminal ledger data is constructed using an upgrade-unstable transient hash or commitment",
  requires: ["transient-data-origins", "state-writes", "completed-entries"],
  run(facts) {
    const result = transientLedgerObservations(facts);
    facts.diagnostics.push(...result.diagnostics);
    return result.observations.map(({ entry, origin, writes }) => {
      const name = facts.program.symbols.get(entry)!.name;
      return finding(facts, {
        detectorId: TRANSIENT_LEDGER_RULE, severity: "low", confidence: "high",
        title: "Ledger data uses an upgrade-unstable transient primitive",
        message: `${name} constructs a terminal modeled ledger operand using ${origin.primitive}. The standard library does not guarantee this primitive remains stable across upgrades and recommends persistent primitives for state derivation. Review whether this state must remain reproducible across upgrades; intentional version-bound data and compiler tests can match. Wrapping a transient digest in a persistent hash does not stabilize the inner computation.`,
        location: writes[0].location, source: origin.location,
        trace: [{ kind: "transform", label: origin.primitive, location: origin.location }, ...writes.map(write => ({ kind: "sink", label: facts.program.symbols.get(write.ledger)!.name, location: write.location }))],
        callPath: writes[0].callPath.map(id => facts.program.symbols.get(id)!.name),
        remediation: "For state that must survive upgrades, derive it with persistentHash or persistentCommit over stable inputs. Changing an existing representation requires an explicit migration; consistency-only transient checks need no replacement.",
        metadata: { reviewRequired: true, entry: name, primitive: origin.primitive, evidence: "terminal-ledger-data-derivation", derivation: "syntactic-data", upgradeFailure: "not-proven", pathFeasibility: "not-proven",
          affectedEffects: writes.map(write => write.location), invocationSites: writes.map(write => write.callSites ?? []) },
      }, entry);
    });
  },
};
