import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { Dataflow, Program, scanFile, scanFileIsolated, type AnalysisFacts } from "../src/index.js";
import { spoofableAuthorization as rule } from "../src/detectors/authorization.js";
import { semanticPaths } from "./helpers.js";

const fixtureRoot = "tests/corpus/drafts/htlc36/owned";
const kinds = ["positive", "corrected", "lookalike"] as const;
// Fixture expectations fix these sites independently of scan output.
const review = readFileSync(`${fixtureRoot}/README.md`, "utf8");
const sites = ["Receiver", "Sender"].map(party => {
  const match = review.match(new RegExp(`${party} guard: \x60htlc-positive\\.compact:(\\d+)\x60`));
  assert.ok(match, `${party} source-first guard site must be documented`);
  return Number(match[1]);
}).sort((a, b) => a - b);
const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).htlcAuthorizationLifecycle36 as {
  cases: { file: string; lines: number[] }[];
};
for (const kind of kinds) {
  const row = manifest.cases.find(item => item.file === `drafts/htlc36/owned/htlc-${kind}.compact`);
  assert.ok(row, `${kind} lifecycle expectation must be registered`);
  assert.deepEqual(row.lines, kind === "positive" ? sites : []);
}
function lines(findings: ReturnType<typeof rule.run>): number[] {
  return findings.filter(item => item.detectorId === rule.id).map(item => item.location.line).sort((a, b) => a - b);
}
function complete(facts: AnalysisFacts): void {
  assert.deepEqual(facts.diagnostics, []);
  assert.deepEqual(facts.completedEntries, facts.program.entries);
  for (const entry of facts.program.entries) assert.ok(facts.paths.some(path => path.entry === entry), `successful lifecycle entry ${entry}`);
}

test("full HTLC lifecycle preserves both party guards and secret controls across engines and caches", () => {
  const positive = readFileSync(`${fixtureRoot}/htlc-positive.compact`, "utf8").split("\n");
  assert.match(positive[sites[0] - 1], /assert\(ownPublicKey\(\)\.bytes == receiverAuth\.lookup\(hash\)/);
  assert.match(positive[sites[1] - 1], /assert\(ownPublicKey\(\)\.bytes == senderAuth\.lookup\(disclose\(hash\)\)/);
  for (const kind of kinds) {
    const file = resolve(`${fixtureRoot}/htlc-${kind}.compact`);
    const program = new Program(file, [], dirname(file), undefined, 3, "0.34.0");
    let oracle: AnalysisFacts | undefined;
    let expectedFindings: ReturnType<typeof rule.run> | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      const actual = rule.run(facts);
      complete(facts);
      assert.deepEqual(lines(actual), kind === "positive" ? sites : []);
      for (const entry of ["withdrawWithPreimage", "reclaimAfterExpiry"]) {
        const paths = facts.paths.filter(path => program.symbols.get(path.entry)?.name === entry);
        assert.ok(paths.some(path => path.operations?.some(operation => operation.name === "claimUnshieldedCoinSpend")), `${kind} ${entry} native spend retained`);
        assert.ok(paths.some(path => path.writes.some(write => program.symbols.get(write.ledger)?.name === "amounts")), `${kind} ${entry} completion retained`);
      }
      if (kind === "positive") for (const finding of actual) {
        assert.equal(finding.metadata.authorizationKind, "public-key-equality");
        assert.equal(finding.metadata.confidenceScope, "required-static-equality-not-deployed-exploitability");
        const effects = finding.metadata.affectedEffects as { kind: string; name: string }[];
        assert.ok(effects.some(effect => effect.kind === "kernel-write" && effect.name === "claimUnshieldedCoinSpend"));
        assert.ok(effects.some(effect => effect.kind === "ledger-write" && effect.name === "amounts"));
      }
      if (oracle) {
        assert.deepEqual(semanticPaths(facts), semanticPaths(oracle), `${kind} ${engine} cached=${cached}`);
        assert.deepEqual(actual, expectedFindings);
      } else { oracle = facts; expectedFindings = actual; }
    }
  }
});

test("full HTLC selected, implicit default and supervised scans agree on source-first party sites", async () => {
  for (const kind of kinds) {
    const file = resolve(`${fixtureRoot}/htlc-${kind}.compact`);
    const options = { compilerVersion: "0.34.0" as const, zkirVersion: 3 as const };
    const selected = scanFile(file, { ...options, detectors: [rule.id] });
    const implicit = scanFile(file, options);
    const supervisedSelected = await scanFileIsolated(file, { ...options, detectors: [rule.id] });
    const supervisedDefault = await scanFileIsolated(file, options);
    for (const report of [selected, implicit, supervisedSelected, supervisedDefault]) {
      assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
      assert.deepEqual(report.diagnostics, []);
      assert.deepEqual(lines(report.findings), kind === "positive" ? sites : []);
      assert.deepEqual(report.coverage.completedEntries, report.entrypoints);
    }
    assert.deepEqual(supervisedSelected.findings, selected.findings);
    assert.deepEqual(supervisedSelected.coverage, selected.coverage);
    assert.deepEqual(supervisedDefault.findings, implicit.findings);
    assert.deepEqual(supervisedDefault.coverage, implicit.coverage);
    assert.deepEqual(implicit.findings.filter(item => item.detectorId === rule.id), selected.findings);
  }
});
