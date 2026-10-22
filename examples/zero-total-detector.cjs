// Organization-specific review example, not an additional built-in security rule.
// API types: import("nightshade-compact/detector-api").CustomDetector / DetectorFinding.
module.exports = {
  apiVersion: 1,
  factsVersion: 1,
  id: "custom-zero-total-write",
  description: "Review successful writes of zero to an organization's total ledger",
  requires: [],
  run({ facts }) {
    const findings = [];
    for (const path of facts.paths) for (const write of path.writes) {
      const ledger = facts.program.symbols.get(write.ledger);
      if (ledger?.name !== "total" || write.after.constant !== "0") continue;
      findings.push({
        severity: "info", confidence: "high", title: "Review clearing total",
        message: "A potential successful history writes zero to ledger total. This organization-specific policy requires review of resets; an intentional reset is not a vulnerability.",
        location: write.location, trace: path.path,
        callPath: write.callPath.map(id => facts.program.symbols.get(id).name),
        remediation: "Confirm the reset is intended and document its business preconditions.",
        metadata: { reviewRequired: true, entry: facts.program.symbols.get(path.entry).name, entryComplete: facts.completedEntries.includes(path.entry), pathFeasibility: "not-proven" },
        discriminator: path.entry,
      });
    }
    return findings;
  },
};
