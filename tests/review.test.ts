import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { reviewFile, reviewFileIsolated, reviewMarkdown } from "../src/reporting/review.js";
import { withFiles } from "./helpers.js";

const source = `pragma language_version 0.26.0;
import CompactStandardLibrary;
export ledger owner: Bytes<32>;
export ledger state: Uint<8>;
export ledger milestoneConfirmed: Boolean;
export ledger amount: Uint<64>;
witness secret(): Bytes<32>;
circuit authorize(): [] { assert(persistentHash<Bytes<32>>(secret()) == owner, "secret"); }
export circuit attest(): [] { authorize(); milestoneConfirmed = true; }
export circuit releaseOnTimeout(currentTimestamp: Uint<64>): [] {
  assert(disclose(currentTimestamp) >= amount, "time");
  sendUnshielded(default<Bytes<32>>, 1, right<ContractAddress,UserAddress>(default<UserAddress>));
  state = 2;
}
export circuit privateRelease(): [] { authorize(); state = 2; }
export circuit initialize(next: Uint<8>): [] { state = disclose(next); }
`;

test("review separates source maps, per-history checks, state markers and audit findings", () => {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), report = reviewFile(file);
    assert.equal(report.status, "complete", JSON.stringify(report.coverage.diagnostics));
    assert.equal(report.schemaVersion, "nightshade-review-1");
    assert.equal(new Set(report.questions.map(q => q.id)).size, report.questions.length, "Different detector questions at one source span have distinct IDs");
    assert.deepEqual(reviewFile(file), report, "The same inputs produce identical briefs");
    const release = report.circuits.find(r => r.name === "releaseOnTimeout")!;
    const attestation = report.circuits.find(r => r.name === "attest")!;
    assert.equal(release.arguments[0].control, "caller-controlled-input");
    assert.ok(release.timeUsage.length && release.valueMovement.length && release.disclosures.length);
    assert.equal(release.authorization.strength, "checks-observed-authentication-unclassified", "A time assertion is not caller authentication");
    assert.ok(attestation.witnesses.some(w => w.name === "secret"), "Transitive helper witnesses are retained");
    assert.ok(attestation.authorization.histories.some(h => h.privatePreimages.length));
    assert.ok(report.questions.some(q => q.kind === "value-authorization" && q.circuitIds.includes(release.id)));
    assert.ok(report.questions.some(q => q.kind === "time-binding" && q.circuitIds.includes(release.id)));
    const marker = report.stateMachine.fields.find(f => f.name === "milestoneConfirmed")!;
    assert.ok(marker.writers.includes(attestation.id));
    assert.ok(!marker.readers.includes(release.id), "A competing timeout does not inherit an attestation-marker read");
    assert.ok(report.questions.some(q => q.kind === "cross-circuit-marker" && q.question.includes("milestoneConfirmed")));
    assert.ok(report.findings.some(f => f.detectorId === "freshness-bound-caller-time"));
    assert.ok(release.findings.some(f => f.detectorId === "freshness-bound-caller-time"));
    assert.equal(report.explorer.status, "not-run");
    const md = reviewMarkdown(report);
    assert.match(md, /Circuit table/); assert.match(md, /Cross-circuit state sketch/);
    assert.match(md, /freshness-bound-caller-time/); assert.match(md, /releaseOnTimeout/);
    assert.match(md, /Authorization histories/); assert.match(md, /observed private-preimage sources: secret/);
    assert.match(md, /no cross-transaction reachability/i);
  });
});

test("review preserves separate histories and never turns a conditional check into universal authentication", () => {
  withFiles({ "main.compact": source + `export circuit maybe(flag: Boolean): [] {
    if (disclose(flag)) { authorize(); } state = 1;
  }` }, directory => {
    const row = reviewFile(resolve(directory, "main.compact")).circuits.find(r => r.name === "maybe")!;
    assert.equal(row.historyStatus, "complete");
    assert.ok(row.authorization.histories.some(h => h.privatePreimages.length));
    assert.ok(row.authorization.histories.some(h => !h.privatePreimages.length));
    assert.match(row.authorization.scope, /not universal/);
  });
});

test("review has explicit parse/budget gaps and accurate UTF-8 source excerpts", () => {
  withFiles({ "main.compact": source.replace('"time"', '"é⌛ time"'), "bad.compact": "export circuit broken(): [] { missing(); }" }, directory => {
    const broken = reviewFile(resolve(directory, "bad.compact"));
    assert.equal(broken.status, "incomplete"); assert.ok(broken.coverage.diagnostics.length);
    const report = reviewFile(resolve(directory, "main.compact"), { maxSteps: 1 });
    assert.equal(report.status, "incomplete");
    assert.ok(report.circuits.some(r => r.historyStatus === "incomplete"));
    assert.ok(report.coverage.diagnostics.some(d => d.code.includes("budget")));
    assert.ok(report.questions.some(q => q.kind === "coverage-gap"));
    const row = report.circuits.find(r => r.name === "releaseOnTimeout")!;
    assert.ok(row.assertions.some(s => s.expression.includes("é⌛ time")));
  });
});

test("supervised review returns incomplete worker errors and CLI writes both formats without overwrite", async () => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-review-test-"));
  try {
    const file = resolve(directory, "main.compact"); writeFileSync(file, source);
    const report = await reviewFileIsolated(file);
    assert.equal(report.status, "complete", JSON.stringify(report.coverage.diagnostics));
    const timed = await reviewFileIsolated(file, {}, { timeoutMs: 1 });
    assert.equal(timed.status, "incomplete");
    assert.ok(timed.coverage.diagnostics.some(d => d.code === "worker-timeout"));
    const output = resolve(directory, "briefs");
    const run = () => spawnSync(process.execPath, [resolve("dist/src/cli.js"), "review", file, "--out", output], { encoding: "utf8", timeout: 20000 });
    const result = run(); assert.equal(result.status, 0, result.stdout + result.stderr);
    const manifest = JSON.parse(readFileSync(resolve(output, "manifest.json"), "utf8"));
    assert.equal(manifest.contracts.length, 1);
    assert.ok(readdirSync(output).some(f => f.endsWith(".md")));
    const attachment = resolve(directory, "explorer.json");
    writeFileSync(attachment, JSON.stringify({ schemaVersion: "nightshade-explore-2", root: file, replay: [{ circuit: "attest", status: "executed", replayId: "historical-replay", transition: true, arguments: ["DO_NOT_COPY_PRIVATE_VALUE"] }] }));
    const attachedOutput = resolve(directory, "attached");
    const attached = spawnSync(process.execPath, [resolve("dist/src/cli.js"), "review", file, "--out", attachedOutput, "--explorer-report", attachment], { encoding: "utf8", timeout: 20000 });
    assert.equal(attached.status, 0, attached.stdout + attached.stderr);
    const attachedManifest = JSON.parse(readFileSync(resolve(attachedOutput, "manifest.json"), "utf8"));
    const attachedBytes = readFileSync(resolve(attachedOutput, attachedManifest.contracts[0].json), "utf8");
    assert.ok(!attachedBytes.includes("DO_NOT_COPY_PRIVATE_VALUE"));
    assert.equal(JSON.parse(attachedBytes).explorer.status, "attached-source-unverified");
    const before = readFileSync(resolve(output, "manifest.json"), "utf8");
    assert.notEqual(run().status, 0);
    assert.equal(readFileSync(resolve(output, "manifest.json"), "utf8"), before);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("review includes re-exported circuits and the defining helper's sites", () => {
  withFiles({
    "main.compact": 'import "lib" prefix Lib_; export { Lib_mintCoins };',
    "lib.compact": `module lib { import CompactStandardLibrary; export ledger supply: Counter;
      export circuit mintCoins(): [] { supply.increment(1); mintShieldedToken(default<Bytes<32>>, 1, default<Bytes<32>>, left<ZswapCoinPublicKey,ContractAddress>(default<ZswapCoinPublicKey>)); } }`,
  }, directory => {
    const brief = reviewFile(resolve(directory, "main.compact"));
    assert.equal(brief.status, "complete", JSON.stringify(brief.coverage.diagnostics));
    const mint = brief.circuits.find(c => c.name === "mintCoins")!;
    assert.ok(mint); assert.equal(mint.location.file, resolve(directory, "lib.compact"));
    assert.ok(mint.valueMovement.length); assert.equal(mint.authorization.strength, "no-check-observed-in-source");
    assert.ok(brief.questions.some(q => q.kind === "value-authorization" && q.circuitIds.includes(mint.id)));
  });
});

test("review ranking follows evidence strength and caps the visible list", () => {
  withFiles({ "main.compact": source }, directory => {
    const report = reviewFile(resolve(directory, "main.compact"));
    const releaseId = report.circuits.find(c => c.name === "releaseOnTimeout")!.id;
    const release = report.questions.find(q => q.circuitIds.includes(releaseId) && q.kind === "value-authorization")!;
    const time = report.questions.find(q => q.circuitIds.includes(releaseId) && q.kind === "time-binding")!;
    assert.ok(release && time && time.score > release.score && time.rank < release.rank && time.signals.includes("caller time compared against gate"));
    assert.equal(report.questionSummary.visible, Math.min(10, report.questions.length));
    assert.equal(report.summary.topQuestions[0].rank, 1);
  });
});


test("Opaque signature reviews remain explicitly incomplete and lifecycle prompts use verbs", () => {
  withFiles({ "main.compact": 'export circuit echo(input: Opaque<"string">): Opaque<"string"> { return input; }' }, directory => {
    const file = resolve(directory, "main.compact"), report = reviewFile(file);
    assert.equal(report.status, "incomplete");
    assert.ok(report.coverage.diagnostics.some(d => d.code === "inventory-unsupported-type"));
    const run = spawnSync(process.execPath, [resolve("dist/src/cli.js"), "review", file, "--out", resolve(directory, "review")], { encoding: "utf8" });
    assert.equal(run.status, 2, run.stderr);
    assert.equal(JSON.parse(run.stdout).status, "incomplete");
  });
  withFiles({ "main.compact": 'export ledger flag: Boolean; export circuit post(count: Uint<8>): [] { flag = true; }' }, directory => {
    const report = reviewFile(resolve(directory, "main.compact"));
    const prompt = report.questions.find(q => q.kind === "state-lifecycle")!.question;
    assert.match(prompt, /Can post be called repeatedly or race a competing transition/);
    assert.match(prompt, /mishandle zero or boundary inputs/);
    assert.doesNotMatch(prompt, /Can post repeat or competing/);
  });
});
