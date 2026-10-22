import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test, { type TestContext } from "node:test";
import { auditPersistentReduction } from "./generative/persistent-reduction-audit.js";
import { writePersistentReductionRun, type OwnedPersistentEvaluator, type PersistentReductionRunOptions, type PersistentReductionSummary } from "./generative/persistent-reduction-cli.js";
import { comparePersistentResults, incompletePersistentResult, makePersistentArtifact, persistentBuildIdentity, runPersistentSequenceIsolated, validatePersistentArtifact, type PersistentArtifact, type PersistentIdentity } from "./generative/persistent-artifacts.js";
import { checkPersistentObservation, expectedPersistentSequence, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, persistentDigest, validatePersistentSequence, type PersistentObservation, type PersistentOperation, type PersistentSequence } from "./generative/persistent-model.js";

const sequence = (operations: PersistentOperation[]) => validatePersistentSequence({ schemaVersion: "nightshade-persistent-sequence-1", seed: 17, operations });
const input = sequence([{ kind: "inspect" }, { kind: "reject" }, { kind: "inspect" }]);
const identity: PersistentIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 };
const limits = { timeoutMs: 1000, heapMiB: 64, maxOutputBytes: 16384 };

/** Explicitly synthetic observations; no runtime execution or defect is claimed. */
function fixture(model: PersistentSequence): PersistentObservation {
  const expected = expectedPersistentSequence(model);
  const snapshot = (value: { count: string; next: string }) => ({ ...value, publicSha256: persistentDigest(`synthetic count:${value.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(model)),
    initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final) };
}
const passed = (model: PersistentSequence) => checkPersistentObservation(model, fixture(model), PERSISTENT_SOURCE_SHA256);
function fault(model: PersistentSequence, delta = 1n) {
  const wire = fixture(model), row = wire.rows.find(row => row.operation === "reject");
  if (row) row.after.next = String(BigInt(row.after.next) + delta);
  return checkPersistentObservation(model, wire, PERSISTENT_SOURCE_SHA256);
}
function restoreFault(model: PersistentSequence) {
  const wire = fixture(model);
  const row = wire.rows.find((row, index) => row.operation === "reject" && wire.rows.slice(0, index).some(prior => prior.operation === "restore" && prior.before.count !== prior.after.count && prior.after.count !== "0"));
  if (row) row.after.next = String(BigInt(row.after.next) + 1n);
  return checkPersistentObservation(model, wire, PERSISTENT_SOURCE_SHA256);
}
const json = (path: string) => JSON.parse(readFileSync(path, "utf8"));
const summaryAt = (directory: string): PersistentReductionSummary => json(resolve(directory, "summary.json"));
const caseAt = (directory: string, name: string): PersistentArtifact => validatePersistentArtifact(json(resolve(directory, name)));
function root(context: TestContext): string {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-reduction-audit-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}
async function run(directory: string, evaluator: OwnedPersistentEvaluator = async model => fault(model), options: PersistentReductionRunOptions = {}, model = input, initial = fault(model)): Promise<PersistentReductionSummary> {
  const artifact = makePersistentArtifact(model, identity, limits, initial);
  return writePersistentReductionRun(Buffer.from(JSON.stringify(artifact, null, 3) + "\n\n"), identity, directory, evaluator, options);
}
interface FileRecord { artifact: string; sha256: string; bytes: number }
function rehash(directory: string, record: FileRecord, artifact: unknown): void {
  const bytes = Buffer.from(JSON.stringify(artifact, null, 2) + "\n");
  writeFileSync(resolve(directory, record.artifact), bytes);
  record.sha256 = persistentDigest(bytes); record.bytes = bytes.length;
}
function mutate(base: string, destination: string, change: (summary: PersistentReductionSummary, directory: string) => void): void {
  cpSync(base, destination, { recursive: true });
  const summary = summaryAt(destination);
  change(summary, destination);
  writeFileSync(resolve(destination, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
}
function replayComparison(summary: PersistentReductionSummary, directory: string): void {
  const original = caseAt(directory, "input.json"), replay = caseAt(directory, "original-replay.json");
  const comparison = comparePersistentResults(original.result, replay.result);
  summary.replay = { ...comparison, matchedFailure: original.result.status === "failed" && replay.result.status === "failed" && comparison.sameStatus && comparison.sameSignature && comparison.sameObservation === true && comparison.sameCompiledJavaScript === true };
}

test("offline audit verifies saved complete synthetic reduction and fixed original-call schedule", async context => {
  const directory = resolve(root(context), "complete"), summary = await run(directory);
  const audited = auditPersistentReduction(directory);
  assert.equal(audited.scope, "offline-evidence-consistency-only"); assert.equal(audited.reductionStatus, "complete");
  assert.equal(audited.checks, 2); assert.equal(audited.changed, true); assert.deepEqual(audited.diagnostics, []);
  assert.deepEqual(summary.attempts.map(attempt => caseAt(directory, attempt.artifact).sequence.operations), [[{ kind: "inspect" }, { kind: "reject" }], [{ kind: "reject" }]]);
  assert.deepEqual(summary.attempts.map(attempt => attempt.originalRows), [[0, 1], [1]]);
  assert.deepEqual(audited.final!.sequence.operations, [{ kind: "reject" }]); assert.equal(audited.final!.result.status, "failed");
  assert.equal(audited.summarySha256, persistentDigest(readFileSync(resolve(directory, "summary.json"))));
  assert.equal(audited.verifiedFiles.length, summary.checks + 4);
  for (const file of audited.verifiedFiles) {
    const bytes = readFileSync(resolve(directory, file.file)); assert.equal(file.sha256, persistentDigest(bytes)); assert.equal(file.bytes, bytes.length);
  }
  audited.final!.sequence.operations.length = 0;
  assert.deepEqual(auditPersistentReduction(directory).final!.sequence.operations, [{ kind: "reject" }]);
});

test("audit preserves passing refusal, original drift, sticky incomplete and compiled-build drift", async context => {
  const directory = root(context);
  const passing = resolve(directory, "passing"); await run(passing, async model => passed(model), {}, input, passed(input));
  assert.deepEqual(auditPersistentReduction(passing).diagnostics, ["persistent-reduction-not-failed"]); assert.equal(auditPersistentReduction(passing).final, null);
  const drift = resolve(directory, "drift"); await run(drift, async model => fault(model, 2n));
  assert.deepEqual(auditPersistentReduction(drift).diagnostics, ["persistent-reduction-replay-drift"]); assert.equal(auditPersistentReduction(drift).checks, 0);
  let calls = 0;
  const sticky = resolve(directory, "sticky"); await run(sticky, async model => ++calls === 2 ? incompletePersistentResult("worker-output-budget", "synthetic output exhaustion") : fault(model));
  const checked = auditPersistentReduction(sticky);
  assert.equal(checked.reductionStatus, "incomplete"); assert.ok(checked.changed); assert.equal(checked.final!.result.status, "failed");
  assert.ok(checked.diagnostics.includes("persistent-reduction-evaluation-incomplete"));
  const cleaned = resolve(directory, "false-clean");
  mutate(sticky, cleaned, summary => { summary.diagnostics = []; summary.reductionStatus = "complete"; });
  assert.throws(() => auditPersistentReduction(cleaned), /missing persistent-reduction-evaluation-incomplete/);
  calls = 0;
  const code = resolve(directory, "code-drift");
  await run(code, async model => { const result = fault(model); if (++calls > 1 && result.status !== "incomplete") result.observation.compiledJavaScriptSha256 = "f".repeat(64); return result; });
  assert.ok(auditPersistentReduction(code).diagnostics.includes("persistent-reduction-build-drift"));
});

test("[timing] audit verifies finite check bounds and conservative time/interruption prefixes at the check ceiling", async context => {
  const directory = root(context), base = resolve(directory, "check");
  await run(base, async model => fault(model), { maxChecks: 1 });
  const audited = auditPersistentReduction(base);
  assert.deepEqual(audited.diagnostics, ["persistent-reduction-check-budget"]); assert.equal(audited.checks, 1); assert.equal(audited.final!.result.status, "failed");
  for (const diagnostic of ["persistent-reduction-time-budget", "persistent-reduction-interrupted"]) {
    const prefix = resolve(directory, diagnostic);
    // Offline audit cannot authenticate wall time. These explicitly synthesized
    // conservative stop labels never turn the one-check prefix into completeness.
    mutate(base, prefix, summary => { summary.diagnostics = [diagnostic]; });
    assert.equal(auditPersistentReduction(prefix).reductionStatus, "incomplete");
  }
  const inventedComplete = resolve(directory, "incomplete-schedule");
  mutate(base, inventedComplete, summary => { summary.diagnostics = []; summary.reductionStatus = "complete"; });
  assert.throws(() => auditPersistentReduction(inventedComplete), /unfinished schedule|missing persistent-reduction-check-budget/);
  const originalTimeout = resolve(directory, "original-timeout");
  await run(originalTimeout, async () => new Promise(() => {}), { maxElapsedMs: 20 });
  const timed = auditPersistentReduction(originalTimeout);
  assert.equal(timed.reductionStatus, "incomplete"); assert.equal(timed.final, null); assert.ok(timed.diagnostics.includes("persistent-reduction-time-budget"));
  let calls = 0;
  const candidateTimeout = resolve(directory, "candidate-timeout");
  await run(candidateTimeout, async model => ++calls === 1 ? fault(model) : new Promise(() => {}), { maxElapsedMs: 30 });
  const candidate = auditPersistentReduction(candidateTimeout);
  assert.equal(candidate.reductionStatus, "incomplete"); assert.equal(candidate.checks, 1); assert.equal(candidate.final!.result.status, "failed");
  assert.ok(candidate.diagnostics.includes("persistent-reduction-time-budget"));
});

test("rehashing cannot hide candidate order, original-row or slot-remapping corruption", async context => {
  const directory = root(context), base = resolve(directory, "base"); await run(base);
  const swapped = resolve(directory, "swapped");
  mutate(base, swapped, (summary, path) => {
    const other = caseAt(path, summary.attempts[1].artifact);
    rehash(path, summary.attempts[0], other);
    summary.attempts[0].sequenceSha256 = persistentDigest(JSON.stringify(other.sequence));
    summary.attempts[0].originalRows = [...summary.attempts[1].originalRows];
  });
  assert.throws(() => auditPersistentReduction(swapped), /candidate schedule\/order/);
  const mapping = resolve(directory, "mapping"); mutate(base, mapping, summary => { summary.attempts[0].originalRows = [0, 2]; });
  assert.throws(() => auditPersistentReduction(mapping), /original-row mapping/);
  const property = resolve(directory, "property"); mutate(base, property, summary => { summary.attempts[0].reductionSignature = "persistent-reduction-property-1|original-row:2|operation:reject|field:after.next"; });
  assert.throws(() => auditPersistentReduction(property), /candidate property mapping/);
  const model = sequence([{ kind: "inspect" }, { kind: "accept" }, { kind: "save", slot: 3 }, { kind: "accept" }, { kind: "restore", slot: 3 }, { kind: "reject" }, { kind: "inspect" }]);
  const slots = resolve(directory, "slots");
  const summary = await run(slots, async candidate => restoreFault(candidate), { maxChecks: 128 }, model, restoreFault(model));
  const audited = auditPersistentReduction(slots);
  assert.deepEqual(audited.final!.sequence.operations, [{ kind: "accept" }, { kind: "save", slot: 0 }, { kind: "accept" }, { kind: "restore", slot: 0 }, { kind: "reject" }]);
  const index = summary.attempts.findIndex(attempt => attempt.preserved && caseAt(slots, attempt.artifact).sequence.operations.some(operation => "slot" in operation && operation.slot === 0));
  assert.ok(index >= 0);
  const badSlots = resolve(directory, "slot-merge");
  mutate(slots, badSlots, (value, path) => {
    const record = value.attempts[index], artifact = caseAt(path, record.artifact);
    artifact.sequence.operations = artifact.sequence.operations.map(operation => "slot" in operation && operation.slot === 0 ? { ...operation, slot: 1 } : operation);
    artifact.result = restoreFault(artifact.sequence);
    rehash(path, record, artifact); record.sequenceSha256 = persistentDigest(JSON.stringify(artifact.sequence));
  });
  assert.throws(() => auditPersistentReduction(badSlots), /candidate schedule\/order/);
});

test("rehashing cannot hide worker ceilings, identities, final-case or status corruption", async context => {
  const directory = root(context), base = resolve(directory, "base"); await run(base);
  const changes: [string, (summary: PersistentReductionSummary, path: string) => void][] = [
    ["saved", summary => { summary.savedWorkerLimits.heapMiB = 128; }],
    ["heap", (summary, path) => { const row = summary.attempts[0], artifact = caseAt(path, row.artifact); row.limits.heapMiB = artifact.limits.heapMiB = 128; rehash(path, row, artifact); }],
    ["output", (summary, path) => { const row = summary.attempts[0], artifact = caseAt(path, row.artifact); row.limits.maxOutputBytes = artifact.limits.maxOutputBytes = 32768; rehash(path, row, artifact); }],
    ["timeout", (summary, path) => { const row = summary.attempts[0], artifact = caseAt(path, row.artifact); row.limits.timeoutMs = artifact.limits.timeoutMs = 1001; rehash(path, row, artifact); }],
    ["identity", (summary, path) => { const row = summary.attempts[0], artifact = caseAt(path, row.artifact); artifact.identity.node = "v0.0.0"; rehash(path, row, artifact); }],
    ["final-value", (summary, path) => { const artifact = caseAt(path, "final.json"); artifact.result = fault(artifact.sequence, 2n); rehash(path, summary.final!, artifact); }],
    ["final-source", summary => { summary.final!.sourceArtifact = "original-replay.json"; }],
    ["final-rows", summary => { summary.final!.originalRows = [0]; }],
    ["final-limits", summary => { summary.final!.limits.heapMiB = 128; }],
    ["case-status", summary => { summary.final!.caseStatus = "passed" as never; }],
    ["preserved", summary => { summary.attempts[0].preserved = false; }],
    ["changed", summary => { summary.changed = false; }],
    ["count", summary => { summary.checks--; }],
    ["labels", summary => { summary.diagnostics = ["persistent-reduction-check-budget"]; summary.reductionStatus = "incomplete"; }],
    ["signature", (summary, path) => { const row = summary.attempts[0], artifact = caseAt(path, row.artifact); artifact.result.signature = "invented"; rehash(path, row, artifact); }],
    ["path", summary => { summary.attempts[0].artifact = "../outside.json"; }],
  ];
  for (const [name, change] of changes) {
    const mutated = resolve(directory, name); mutate(base, mutated, change);
    assert.throws(() => auditPersistentReduction(mutated), name);
  }
});

test("[timing] invoked timeout records cannot exceed total or preceding allowance even with matching new case hashes", async context => {
  const directory = root(context), base = resolve(directory, "base");
  await run(base, async model => fault(model), { maxElapsedMs: 300 });
  const aboveTotal = resolve(directory, "total");
  mutate(base, aboveTotal, (summary, path) => {
    const artifact = caseAt(path, "original-replay.json");
    artifact.limits.timeoutMs = summary.originalReplay.limits.timeoutMs = 301;
    rehash(path, summary.originalReplay, artifact);
  });
  assert.throws(() => auditPersistentReduction(aboveTotal), /invoked timeout exceeds total/);
  const rising = resolve(directory, "rising");
  mutate(base, rising, (summary, path) => {
    const replay = caseAt(path, "original-replay.json"), candidate = caseAt(path, summary.attempts[0].artifact);
    replay.limits.timeoutMs = summary.originalReplay.limits.timeoutMs = 100;
    candidate.limits.timeoutMs = summary.attempts[0].limits.timeoutMs = 101;
    rehash(path, summary.originalReplay, replay); rehash(path, summary.attempts[0], candidate);
  });
  assert.throws(() => auditPersistentReduction(rising), /invoked timeout exceeds total or preceding allowance/);
});

test("uninvoked original records require matching interruption/time labels and cannot invent response streams", async context => {
  const directory = root(context), base = resolve(directory, "base"), controller = new AbortController(); controller.abort();
  await run(base, async () => assert.fail("pre-aborted evaluation"), { signal: controller.signal });
  assert.equal(summaryAt(base).originalReplay.evaluatorInvoked, false);
  assert.ok(auditPersistentReduction(base).diagnostics.includes("persistent-reduction-interrupted"));
  const missing = resolve(directory, "missing-label");
  mutate(base, missing, summary => { summary.diagnostics = summary.diagnostics.filter(label => label !== "persistent-reduction-interrupted"); });
  assert.throws(() => auditPersistentReduction(missing), /missing persistent-reduction-interrupted/);
  const streams = resolve(directory, "streams");
  mutate(base, streams, (summary, path) => {
    const artifact = caseAt(path, "original-replay.json"), empty = { bytes: 0, sha256: persistentDigest(""), prefix: "", truncated: false };
    artifact.result.diagnosticResponse = { stdout: { ...empty }, stderr: { ...empty } };
    rehash(path, summary.originalReplay, artifact);
  });
  assert.throws(() => auditPersistentReduction(streams), /uninvoked evaluator cannot have diagnostic streams/);
  const timed = resolve(directory, "synthetic-uninvoked-timeout");
  mutate(base, timed, (summary, path) => {
    const artifact = caseAt(path, "original-replay.json"); artifact.result = incompletePersistentResult("worker-timeout", "Synthetic pre-invocation deadline evidence");
    rehash(path, summary.originalReplay, artifact); replayComparison(summary, path);
    summary.diagnostics = ["persistent-reduction-original-incomplete", "persistent-reduction-time-budget"].sort();
  });
  assert.equal(auditPersistentReduction(timed).reductionStatus, "incomplete");
  const missingTime = resolve(directory, "missing-time"); mutate(timed, missingTime, summary => { summary.diagnostics = ["persistent-reduction-original-incomplete"]; });
  assert.throws(() => auditPersistentReduction(missingTime), /missing persistent-reduction-time-budget/);
});

test("worker interruption takes reason priority and uninvoked candidate timeout retains its time diagnostic", async context => {
  const directory = root(context), base = resolve(directory, "base"), controller = new AbortController(); let calls = 0;
  await run(base, async model => { if (++calls > 1) controller.abort(); return fault(model); }, { signal: controller.signal });
  const checked = auditPersistentReduction(base); assert.equal(checked.checks, 1); assert.equal(checked.reductionStatus, "incomplete");
  const wrongReason = resolve(directory, "wrong-reason");
  mutate(base, wrongReason, summary => {
    summary.attempts[0].reason = "time-budget";
    summary.diagnostics = ["persistent-reduction-evaluation-incomplete", "persistent-reduction-time-budget"].sort();
  });
  assert.throws(() => auditPersistentReduction(wrongReason), /worker interruption must take priority/);
  const uninvoked = resolve(directory, "uninvoked");
  mutate(base, uninvoked, (summary, path) => {
    const row = summary.attempts[0], artifact = caseAt(path, row.artifact);
    row.evaluatorInvoked = false;
    artifact.result = incompletePersistentResult("worker-timeout", "Synthetic deadline before candidate invocation");
    rehash(path, row, artifact);
    summary.diagnostics = ["persistent-reduction-evaluation-incomplete", "persistent-reduction-interrupted", "persistent-reduction-time-budget"].sort();
  });
  assert.equal(auditPersistentReduction(uninvoked).reductionStatus, "incomplete");
  const lost = resolve(directory, "lost-time"); mutate(uninvoked, lost, summary => { summary.diagnostics = summary.diagnostics.filter(label => label !== "persistent-reduction-time-budget"); });
  assert.throws(() => auditPersistentReduction(lost), /missing persistent-reduction-time-budget/);
  const continued = resolve(directory, "continued");
  mutate(uninvoked, continued, summary => { summary.attempts[0].reason = "incomplete-evaluation"; summary.diagnostics = ["persistent-reduction-evaluation-incomplete", "persistent-reduction-time-budget"].sort(); });
  assert.throws(() => auditPersistentReduction(continued), /uninvoked candidate must stop reduction/);
});

test("audit rejects missing, malformed, oversized, nonregular and symlinked files", async context => {
  const directory = root(context), base = resolve(directory, "base"); await run(base);
  for (const [name, change] of [
    ["missing-summary", (path: string) => rmSync(resolve(path, "summary.json"))],
    ["missing-case", (path: string) => rmSync(resolve(path, "attempt-0001.json"))],
    ["malformed", (path: string) => writeFileSync(resolve(path, "summary.json"), "{")],
    ["large-summary", (path: string) => truncateSync(resolve(path, "summary.json"), 1048577)],
    ["large-case", (path: string) => truncateSync(resolve(path, "input.json"), 1048577)],
    ["directory", (path: string) => { rmSync(resolve(path, "input.json")); mkdirSync(resolve(path, "input.json")); }],
    ["summary-symlink", (path: string) => { const target = resolve(path, "summary-copy.json"); cpSync(resolve(path, "summary.json"), target); rmSync(resolve(path, "summary.json")); symlinkSync(target, resolve(path, "summary.json")); }],
    ["case-symlink", (path: string) => { const target = resolve(path, "case-copy.json"); cpSync(resolve(path, "input.json"), target); rmSync(resolve(path, "input.json")); symlinkSync(target, resolve(path, "input.json")); }],
  ] as const) {
    const target = resolve(directory, name); cpSync(base, target, { recursive: true }); change(target);
    assert.throws(() => auditPersistentReduction(target), name);
  }
});

test("offline CLI reports consistency and remains independent of optional runtime inputs", async context => {
  const directory = root(context), complete = resolve(directory, "complete"), incomplete = resolve(directory, "incomplete");
  await run(complete); await run(incomplete, async model => passed(model), {}, input, passed(input));
  const env = { ...process.env }; delete env.COMPACTC_TEST; delete env.COMPACT_RUNTIME_TEST;
  const cli = (path: string) => spawnSync(process.execPath, [resolve("dist/tests/generative/persistent-reduction-audit.js"), "--audit", path], { encoding: "utf8", timeout: 10000, env });
  const good = cli(complete); assert.equal(good.status, 0, good.stderr); assert.equal(JSON.parse(good.stdout).scope, "offline-evidence-consistency-only");
  assert.equal(JSON.parse(good.stdout).final.status, "failed");
  const refused = cli(incomplete); assert.equal(refused.status, 2, refused.stderr); assert.equal(JSON.parse(refused.stdout).reductionStatus, "incomplete");
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
test("[timing] audit checks actual fixed-fixture nonfailure and timeout records without promoting them to successful reductions", qualified, async context => {
  assert.ok(process.env.COMPACTC_TEST, "Requires pinned compiler alongside runtime");
  const compiler = process.env.COMPACTC_TEST, runtime = process.env.COMPACT_RUNTIME_TEST!, directory = root(context);
  const measured = await runPersistentSequenceIsolated(input, compiler, runtime); assert.equal(measured.status, "passed");
  const actualIdentity = persistentBuildIdentity(compiler, runtime);
  const artifact = makePersistentArtifact(input, actualIdentity, PERSISTENT_LIMITS, measured);
  const evaluate: OwnedPersistentEvaluator = (model, bounds, signal) => runPersistentSequenceIsolated(model, compiler, runtime, bounds, signal);
  const passing = resolve(directory, "passing");
  await writePersistentReductionRun(Buffer.from(JSON.stringify(artifact)), actualIdentity, passing, evaluate);
  assert.deepEqual(auditPersistentReduction(passing).diagnostics, ["persistent-reduction-not-failed"]);
  artifact.limits.timeoutMs = 1;
  const timed = resolve(directory, "timed");
  await writePersistentReductionRun(Buffer.from(JSON.stringify(artifact)), actualIdentity, timed, evaluate);
  const audited = auditPersistentReduction(timed);
  assert.equal(audited.reductionStatus, "incomplete"); assert.equal(audited.checks, 0); assert.equal(audited.final, null);
  assert.equal(caseAt(timed, "original-replay.json").result.diagnostic, "worker-timeout");
});
