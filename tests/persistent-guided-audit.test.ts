import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test, { type TestContext } from "node:test";
import { spawnSync } from "node:child_process";
import { readAuditedPersistentGuided } from "./generative/persistent-guided-audit.js";
import { PERSISTENT_GUIDED_LIMITS, persistentGuidedCounts, persistentGuidedNames, persistentGuidedOutcome, validatePersistentGuidedConfiguration, type PersistentGuidedFileReference, type PersistentGuidedFiles, type PersistentGuidedIdentity, type PersistentGuidedInvocation, type PersistentGuidedPostIdentity, type PersistentGuidedSummary } from "./generative/persistent-guided-format.js";
import { PersistentSchedule, type PersistentDecision, type PersistentScheduleStopReason } from "./generative/persistent-schedule.js";
import { foldPersistentSchedule } from "./generative/persistent-schedule-audit.js";
import { incompletePersistentResult, makePersistentArtifact, type PersistentIdentity, type PersistentResult } from "./generative/persistent-artifacts.js";
import { checkPersistentObservation, expectedPersistentSequence, persistentDigest, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, type PersistentObservation, type PersistentSequence } from "./generative/persistent-model.js";

const identity: PersistentIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 };
const limits = { timeoutMs: 1000, heapMiB: 64, maxOutputBytes: 16384 };
const guidedIdentity: PersistentGuidedIdentity = { persistent: identity, modules: {
  feedback: { sourceSha256: "4".repeat(64), builtSha256: "5".repeat(64) }, corpus: { sourceSha256: "6".repeat(64), builtSha256: "7".repeat(64) }, schedule: { sourceSha256: "8".repeat(64), builtSha256: "9".repeat(64) },
} };

/** Synthetic schema-only evidence; these fixtures do not claim runtime execution. */
function synthetic(sequence: PersistentSequence): PersistentObservation {
  const expected = expectedPersistentSequence(sequence);
  const snapshot = (value: { count: string; next: string }) => ({ ...value, publicSha256: persistentDigest(`synthetic-public:${value.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(sequence)),
    initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final) };
}
const result = (sequence: PersistentSequence, wire = synthetic(sequence)) => checkPersistentObservation(sequence, wire, PERSISTENT_SOURCE_SHA256);
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value));
const json = (directory: string, name = "summary.json") => JSON.parse(fs.readFileSync(resolve(directory, name), "utf8"));
function root(context: TestContext): string {
  const directory = fs.realpathSync(fs.mkdtempSync(resolve(tmpdir(), "nightshade-persistent-guided-audit-")));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

interface FixtureOptions {
  configuration?: object;
  stopAfter?: number;
  stopReason?: PersistentScheduleStopReason;
  result?: (decision: PersistentDecision) => PersistentResult;
  invocation?: (value: PersistentGuidedInvocation) => void;
  returned?: (decision: PersistentDecision) => PersistentResult;
  postIdentity?: PersistentGuidedPostIdentity;
  elapsedMs?: number;
}
/** Hand-composed schema fixture uses the real pure schedule, never the campaign writer. */
function campaign(directory: string, options: FixtureOptions = {}): PersistentGuidedSummary {
  fs.mkdirSync(directory);
  const configuration = validatePersistentGuidedConfiguration({ schedule: { seed: 7, mutations: 0, maxEvaluations: 4 }, workerLimits: limits, maxElapsedMs: 10000, ...options.configuration });
  const schedule = new PersistentSchedule(identity, configuration.workerLimits, configuration.schedule, configuration.corpusBudgets);
  const originals: Buffer[] = [], files: PersistentGuidedFiles[] = [], invocations: PersistentGuidedInvocation[] = [];
  const save = (name: string, value: unknown): PersistentGuidedFileReference => {
    const data = bytes(value); fs.writeFileSync(resolve(directory, name), data, { flag: "wx" });
    return { name, sha256: persistentDigest(data), bytes: data.length };
  };
  while (options.stopAfter === undefined || originals.length < options.stopAfter) {
    const decision = schedule.next(); if (!decision) break;
    const names = persistentGuidedNames(decision.ordinal), checked = options.result?.(decision) ?? result(decision.sequence);
    const decisionRef = save(names.decision, decision), artifact = makePersistentArtifact(decision.sequence, identity, configuration.workerLimits, checked);
    const artifactRef = save(names.artifact, artifact), original = fs.readFileSync(resolve(directory, names.artifact));
    originals.push(original); schedule.record(original);
    const returned = options.returned?.(decision);
    const returnedArtifact = returned ? save(names.returnedArtifact, makePersistentArtifact(decision.sequence, identity, configuration.workerLimits, returned)) : null;
    const proposedAtMs = (decision.ordinal - 1) * 10, startedAtMs = proposedAtMs + 1;
    const invocation: PersistentGuidedInvocation = { schemaVersion: "nightshade-persistent-guided-invocation-1", ordinal: decision.ordinal, decision: decisionRef, artifact: artifactRef, returnedArtifact,
      evaluatorInvoked: true, resultOrigin: "evaluator", timing: { proposedAtMs, startedAtMs, finishedAtMs: proposedAtMs + 2, remainingMsAtLaunch: configuration.maxElapsedMs - startedAtMs }, abortCause: null,
      workerLimits: { ...configuration.workerLimits }, result: { status: checked.status, diagnostic: checked.diagnostic, signature: checked.signature } };
    options.invocation?.(invocation);
    invocations.push(invocation);
    files.push({ ordinal: decision.ordinal, decision: decisionRef, artifact: artifactRef, invocation: save(names.invocation, invocation), returnedArtifact });
  }
  const transcript = foldPersistentSchedule(identity, configuration.workerLimits, configuration.schedule, configuration.corpusBudgets, originals, options.stopReason ?? null).transcript;
  const postIdentity = options.postIdentity ?? { status: "matched" as const, identity: guidedIdentity };
  const elapsedMs = options.elapsedMs ?? (invocations.at(-1)?.timing.finishedAtMs ?? 0);
  const finalAbortCause = invocations.at(-1)?.abortCause ?? (options.stopReason === "persistent-campaign-interrupted" ? "external-signal" : elapsedMs >= configuration.maxElapsedMs ? "deadline" : null);
  const summary: PersistentGuidedSummary = { schemaVersion: "nightshade-owned-persistent-guided-1", scope: "owned-fixed-fixture-compiled-evaluation-only", identity: guidedIdentity, configuration, transcript, files, elapsedMs, finalAbortCause, postIdentity,
    outcome: persistentGuidedOutcome(transcript, invocations, elapsedMs, configuration, postIdentity, finalAbortCause), counts: persistentGuidedCounts(transcript, invocations),
    evidenceBytesBeforeSummary: files.reduce((sum, file) => sum + file.decision.bytes + file.artifact.bytes + file.invocation.bytes + (file.returnedArtifact?.bytes ?? 0), 0) };
  save("summary.json", summary);
  return summary;
}

function mutate(source: string, destination: string, change: (summary: PersistentGuidedSummary, directory: string) => void) {
  fs.cpSync(source, destination, { recursive: true });
  const summary = json(destination) as PersistentGuidedSummary;
  change(summary, destination); fs.writeFileSync(resolve(destination, "summary.json"), bytes(summary));
}
function rehash(directory: string, reference: PersistentGuidedFileReference, value: unknown): void {
  const data = bytes(value); fs.writeFileSync(resolve(directory, reference.name), data);
  reference.bytes = data.length; reference.sha256 = persistentDigest(data);
}
function editInvocation(summary: PersistentGuidedSummary, directory: string, index: number, change: (value: PersistentGuidedInvocation) => void): void {
  const reference = summary.files[index].invocation, invocation = json(directory, reference.name) as PersistentGuidedInvocation;
  change(invocation); rehash(directory, reference, invocation);
  summary.evidenceBytesBeforeSummary = summary.files.reduce((sum, file) => sum + file.decision.bytes + file.artifact.bytes + file.invocation.bytes + (file.returnedArtifact?.bytes ?? 0), 0);
}

test("disk audit reconstructs original cases and returns detached replay evidence without executing", context => {
  const base = resolve(root(context), "base"), summary = campaign(base, { configuration: { schedule: { seed: 7, mutations: 2, maxEvaluations: 6 } } });
  const audited = readAuditedPersistentGuided(base);
  assert.equal(audited.scope, "offline-evidence-consistency-only"); assert.deepEqual(audited.summary, summary);
  assert.equal(audited.summary.outcome.status, "passed"); assert.equal(audited.steps.length, 6); assert.equal(audited.verifiedFiles.length, 19);
  assert.equal(audited.summarySha256, persistentDigest(fs.readFileSync(resolve(base, "summary.json"))));
  for (const [index, step] of audited.steps.entries()) {
    assert.deepEqual(Buffer.from(step.originalBytes), fs.readFileSync(resolve(base, persistentGuidedNames(index + 1).artifact)));
    assert.deepEqual(step.decision, summary.transcript.decisions[index]); assert.deepEqual(step.invocation.artifact, summary.files[index].artifact);
    assert.equal(step.returnedArtifact, null);
  }
  audited.steps[0].originalBytes.fill(0); audited.steps[0].artifact.sequence.seed = 99; audited.summary.counts.recorded = 0;
  const again = readAuditedPersistentGuided(base);
  assert.deepEqual(again.summary, summary); assert.equal(again.steps[0].artifact.sequence.seed, 1);
  fs.rmSync(base, { recursive: true });
  assert.equal(again.steps[0].artifact.result.status, "passed", "Detached evidence survives removal of its directory");
});

test("rehashing decision files cannot replace reconstructed randomness, sequence or provenance", context => {
  const directory = root(context), base = resolve(directory, "base"); campaign(base, { configuration: { schedule: { seed: 7, mutations: 2, maxEvaluations: 6 } } });
  for (const [name, change] of [
    ["random", (decision: any) => { decision.random.words[0]++; }],
    ["parent", (decision: any) => { decision.parent.retainedIndex++; }],
    ["mutation", (decision: any) => { decision.mutation.index++; }],
    ["sequence", (decision: any) => { decision.sequence.seed++; }],
  ] as const) {
    const changed = resolve(directory, name);
    mutate(base, changed, (summary, target) => {
      const index = 4, reference = summary.files[index].decision, decision = json(target, reference.name); change(decision);
      rehash(target, reference, decision);
      editInvocation(summary, target, index, invocation => { invocation.decision = { ...reference }; });
    });
    assert.throws(() => readAuditedPersistentGuided(changed), /decision files differ/);
  }
});

test("summary identities, configuration, counts, outcome and original hashes are all checked", context => {
  const directory = root(context), base = resolve(directory, "base"); campaign(base);
  const changes: [string, (summary: any) => void][] = [
    ["schema", value => { value.schemaVersion = "invented"; }],
    ["extra", value => { value.approved = true; }],
    ["node", value => { value.identity.persistent.node = "v22.23.3"; }],
    ["module", value => { value.identity.modules.schedule.builtSha256 = "0".repeat(64); }],
    ["worker", value => { value.configuration.workerLimits.timeoutMs++; }],
    ["seed", value => { value.configuration.schedule.seed++; }],
    ["budget", value => { value.configuration.corpusBudgets.maxCases++; }],
    ["count", value => { value.counts.evaluatorInvoked--; }],
    ["features", value => { value.transcript.snapshot.corpus.features = []; }],
    ["outcome", value => { value.outcome = { status: "incomplete", diagnostics: [] }; }],
    ["elapsed", value => { value.elapsedMs = 0; }],
    ["bytes", value => { value.evidenceBytesBeforeSummary++; }],
    ["hash", value => { value.files[0].artifact.sha256 = "0".repeat(64); }],
    ["length", value => { value.files[0].artifact.bytes++; }],
    ["post", value => { value.postIdentity.status = "unavailable"; }],
    ["path", value => { value.files[0].artifact.name = "../outside.json"; }],
    ["ordinal", value => { value.files[0].ordinal = 2; }],
    ["order", value => { value.files.reverse(); }],
    ["count-bound", value => { value.files = Array(69).fill(value.files[0]); }],
  ];
  for (const [name, change] of changes) {
    const changed = resolve(directory, name); mutate(base, changed, change);
    assert.throws(() => readAuditedPersistentGuided(changed), name);
  }
});

test("rehashing invocation records cannot invent launches, deadlines, fixed limits or result classifications", context => {
  const directory = root(context), base = resolve(directory, "base"); campaign(base);
  const changes: [string, (value: any) => void][] = [
    ["schema", value => { value.schemaVersion = "invented"; }],
    ["extra", value => { value.source = "arbitrary.compact"; }],
    ["ordinal", value => { value.ordinal++; }],
    ["decision", value => { value.decision.sha256 = "0".repeat(64); }],
    ["artifact", value => { value.artifact.sha256 = "0".repeat(64); }],
    ["invoked", value => { value.evaluatorInvoked = false; }],
    ["origin", value => { value.resultOrigin = "supervisor"; }],
    ["cause", value => { value.abortCause = "external-signal"; }],
    ["unknown-cause", value => { value.abortCause = "worker-timeout"; }],
    ["limits", value => { value.workerLimits.timeoutMs--; }],
    ["remaining", value => { value.timing.remainingMsAtLaunch--; }],
    ["backwards", value => { value.timing.finishedAtMs = 0; }],
    ["negative-time", value => { value.timing.proposedAtMs = -1; }],
    ["prior-row", value => { value.timing.proposedAtMs = 0; value.timing.startedAtMs = 1; value.timing.finishedAtMs = 2; value.timing.remainingMsAtLaunch = 9999; }],
    ["result", value => { value.result.signature = "invented"; }],
  ];
  for (const [name, change] of changes) {
    const changed = resolve(directory, name); mutate(base, changed, (summary, target) => editInvocation(summary, target, 1, change));
    assert.throws(() => readAuditedPersistentGuided(changed), name);
  }
});

test("exact directory file sets reject missing, extra, duplicate and trailing evidence", context => {
  const directory = root(context), base = resolve(directory, "base"); campaign(base);
  for (const [name, change] of [
    ["missing-summary", (target: string) => fs.rmSync(resolve(target, "summary.json"))],
    ["missing-case", (target: string) => fs.rmSync(resolve(target, "0002.json"))],
    ["missing-decision", (target: string) => fs.rmSync(resolve(target, "0001-decision.json"))],
    ["missing-invocation", (target: string) => fs.rmSync(resolve(target, "0004-invocation.json"))],
    ["extra", (target: string) => fs.writeFileSync(resolve(target, "notes.txt"), "not evidence")],
    ["trailing", (target: string) => fs.copyFileSync(resolve(target, "0001.json"), resolve(target, "0005.json"))],
    ["case-copy", (target: string) => fs.copyFileSync(resolve(target, "0001.json"), resolve(target, "0001-copy.json"))],
    ["too-many", (target: string) => { for (let index = 0; index <= PERSISTENT_GUIDED_LIMITS.maxFiles; index++) fs.writeFileSync(resolve(target, `extra-${index}`), ""); }],
  ] as const) {
    const changed = resolve(directory, name); fs.cpSync(base, changed, { recursive: true }); change(changed);
    assert.throws(() => readAuditedPersistentGuided(changed), name);
  }
});

test("directory, file and parent symlinks and nonregular evidence are refused", context => {
  const directory = root(context), base = resolve(directory, "base"); campaign(base);
  const linked = resolve(directory, "linked"); fs.symlinkSync(base, linked, "dir");
  assert.throws(() => readAuditedPersistentGuided(linked), /nonsymlink/);
  const parent = resolve(directory, "parent"); fs.symlinkSync(directory, parent, "dir");
  assert.throws(() => readAuditedPersistentGuided(resolve(parent, "base")), /nonsymlink/);
  for (const name of ["summary.json", "0001.json", "0001-decision.json", "0001-invocation.json"]) {
    const changed = resolve(directory, name); fs.cpSync(base, changed, { recursive: true });
    fs.rmSync(resolve(changed, name)); fs.symlinkSync(resolve(base, name), resolve(changed, name));
    assert.throws(() => readAuditedPersistentGuided(changed), /ordinary files/);
  }
  const nonfile = resolve(directory, "nonfile"); fs.cpSync(base, nonfile, { recursive: true }); fs.rmSync(resolve(nonfile, "0001.json")); fs.mkdirSync(resolve(nonfile, "0001.json"));
  assert.throws(() => readAuditedPersistentGuided(nonfile), /ordinary files/);
  if (process.platform !== "win32") {
    const fifo = resolve(directory, "fifo"); fs.cpSync(base, fifo, { recursive: true }); fs.rmSync(resolve(fifo, "0001.json"));
    const made = spawnSync("mkfifo", [resolve(fifo, "0001.json")]);
    assert.equal(made.status, 0, "mkfifo is required for this platform fixture");
    assert.throws(() => readAuditedPersistentGuided(fifo), /ordinary files/);
  }
});

test("fatal UTF-8, malformed JSON and each per-file size ceiling are enforced before parsing", context => {
  const directory = root(context), base = resolve(directory, "base"); campaign(base);
  for (const [name, file, content] of [
    ["utf8", "summary.json", Buffer.from([0xff])],
    ["json", "summary.json", Buffer.from("{")],
    ["summary-cap", "summary.json", PERSISTENT_GUIDED_LIMITS.summaryBytes + 1],
    ["case-cap", "0001.json", PERSISTENT_GUIDED_LIMITS.caseBytes + 1],
    ["decision-cap", "0001-decision.json", PERSISTENT_GUIDED_LIMITS.decisionBytes + 1],
    ["invocation-cap", "0001-invocation.json", PERSISTENT_GUIDED_LIMITS.invocationBytes + 1],
  ] as const) {
    const changed = resolve(directory, name); fs.cpSync(base, changed, { recursive: true });
    if (typeof content === "number") fs.truncateSync(resolve(changed, file), content); else fs.writeFileSync(resolve(changed, file), content);
    assert.throws(() => readAuditedPersistentGuided(changed), /UTF-8 JSON|byte bound/);
  }
});

test("growth after descriptor stat remains bounded and the opened descriptor is closed", context => {
  const base = resolve(root(context), "base"); campaign(base);
  const originalStat = fs.fstatSync, originalClose = fs.closeSync;
  let grew = false, descriptor: number | null = null, closed = false;
  context.mock.method(fs, "fstatSync", (fd: number) => {
    const stat = originalStat(fd);
    if (!grew) { descriptor = fd; grew = true; fs.appendFileSync(resolve(base, "summary.json"), Buffer.alloc(PERSISTENT_GUIDED_LIMITS.summaryBytes)); }
    return stat;
  });
  context.mock.method(fs, "closeSync", (fd: number) => { if (fd === descriptor) closed = true; return originalClose(fd); });
  assert.throws(() => readAuditedPersistentGuided(base), /grew beyond/);
  assert.equal(grew, true); assert.equal(closed, true);
  context.mock.restoreAll();
});

test("a file swapped after lstat cannot follow a symlink at open", context => {
  const directory = root(context), base = resolve(directory, "base"); campaign(base);
  const source = resolve(base, "summary.json"), replacement = resolve(directory, "outside-summary.json");
  fs.copyFileSync(source, replacement);
  const originalOpen = fs.openSync;
  let swapped = false;
  context.mock.method(fs, "openSync", (path: fs.PathLike, flags: fs.OpenMode, mode?: fs.Mode) => {
    if (path === source && !swapped) { swapped = true; fs.rmSync(source); fs.symlinkSync(replacement, source); }
    return originalOpen(path, flags, mode);
  });
  assert.throws(() => readAuditedPersistentGuided(base));
  assert.equal(swapped, true);
  context.mock.restoreAll();
});

test("a directory entry appearing during reads invalidates the final exact file set", context => {
  const base = resolve(root(context), "base"); campaign(base);
  const originalStat = fs.fstatSync;
  let added = false;
  context.mock.method(fs, "fstatSync", (fd: number) => {
    const stat = originalStat(fd);
    if (!added) { added = true; fs.writeFileSync(resolve(base, "late-extra.json"), "{}"); }
    return stat;
  });
  assert.throws(() => readAuditedPersistentGuided(base), /file set changed/);
  assert.equal(added, true);
  context.mock.restoreAll();
});

test("between-proposal stops are consistent incomplete prefixes without fabricated invocation files", context => {
  const directory = root(context);
  for (const [index, stopReason] of (["persistent-campaign-interrupted", "persistent-campaign-time-budget", "persistent-campaign-evidence-budget"] as const).entries()) {
    const base = resolve(directory, String(index));
    const summary = campaign(base, { stopAfter: index, stopReason, elapsedMs: stopReason === "persistent-campaign-time-budget" ? 10000 : index * 10 });
    const audited = readAuditedPersistentGuided(base);
    assert.equal(audited.steps.length, index); assert.equal(audited.verifiedFiles.length, 1 + 3 * index);
    assert.equal(audited.summary.outcome.status, "incomplete"); assert.ok(audited.summary.outcome.diagnostics.includes(stopReason));
    assert.deepEqual(audited.summary, summary);
    const forged = resolve(directory, `forged-${index}`);
    mutate(base, forged, value => { value.transcript.stopReason = null; value.outcome = { status: "passed", diagnostics: [] }; });
    assert.throws(() => readAuditedPersistentGuided(forged));
  }
  const timed = resolve(directory, "timed-empty"); campaign(timed, { stopAfter: 0, stopReason: "persistent-campaign-time-budget", elapsedMs: 10000 });
  assert.equal(readAuditedPersistentGuided(timed).steps.length, 0);
  const early = resolve(directory, "early-deadline"); mutate(timed, early, summary => { summary.elapsedMs = 0; });
  assert.throws(() => readAuditedPersistentGuided(early));
});

test("uninvoked pending cancellation has explicit supervisor evidence and no measured observations", context => {
  const directory = root(context), base = resolve(directory, "base");
  campaign(base, { result: () => incompletePersistentResult("worker-interrupted", "Synthetic cancellation before launch"), invocation: value => {
    value.evaluatorInvoked = false; value.resultOrigin = "supervisor"; value.abortCause = "external-signal";
    value.timing.startedAtMs = null; value.timing.remainingMsAtLaunch = null;
  } });
  const audited = readAuditedPersistentGuided(base);
  assert.equal(audited.steps.length, 1); assert.equal(audited.summary.counts.evaluatorInvoked, 0);
  assert.equal(audited.summary.counts.proposed, 1); assert.equal(audited.summary.counts.retained, 0);
  assert.equal(audited.steps[0].artifact.result.status, "incomplete");
  assert.ok(audited.summary.outcome.diagnostics.includes("persistent-campaign-interrupted"));
  for (const [name, change] of [
    ["origin", (value: PersistentGuidedInvocation) => { value.resultOrigin = "evaluator"; }],
    ["cause", (value: PersistentGuidedInvocation) => { value.abortCause = null; }],
    ["started", (value: PersistentGuidedInvocation) => { value.timing.startedAtMs = 1; value.timing.remainingMsAtLaunch = 9999; }],
  ] as const) {
    const changed = resolve(directory, name); mutate(base, changed, (summary, target) => editInvocation(summary, target, 0, change));
    assert.throws(() => readAuditedPersistentGuided(changed), name);
  }
  const streams = resolve(directory, "streams");
  const diagnostic = incompletePersistentResult("worker-interrupted", "Synthetic supervisor with forbidden streams");
  const empty = { bytes: 0, sha256: persistentDigest(""), prefix: "", truncated: false };
  diagnostic.diagnosticResponse = { stdout: empty, stderr: empty };
  campaign(streams, { result: () => diagnostic, invocation: value => { value.resultOrigin = "supervisor"; value.abortCause = "external-signal"; } });
  assert.throws(() => readAuditedPersistentGuided(streams), /without measured streams/);
});

test("on-time worker failures preserve their original diagnostic while supervisor protocol evidence is explicit", context => {
  const directory = root(context);
  for (const diagnostic of ["worker-timeout", "worker-output-budget", "worker-interrupted"]) {
    const base = resolve(directory, diagnostic); campaign(base, { result: () => incompletePersistentResult(diagnostic, "Synthetic original worker result") });
    const audited = readAuditedPersistentGuided(base);
    assert.equal(audited.steps[0].invocation.resultOrigin, "evaluator"); assert.equal(audited.steps[0].invocation.abortCause, null);
    assert.equal(audited.steps[0].artifact.result.diagnostic, diagnostic); assert.equal(audited.summary.outcome.status, "incomplete");
  }
  const protocol = resolve(directory, "protocol");
  campaign(protocol, { result: () => incompletePersistentResult("persistent-protocol", "Synthetic rejected evaluator response"), invocation: value => { value.resultOrigin = "supervisor"; } });
  assert.equal(readAuditedPersistentGuided(protocol).steps[0].invocation.resultOrigin, "supervisor");
});

test("late settled evidence is retained separately and cannot earn novelty or a passing campaign", context => {
  const directory = root(context), base = resolve(directory, "base");
  campaign(base, { result: () => incompletePersistentResult("worker-interrupted", "Synthetic post-result deadline"), returned: decision => result(decision.sequence),
    invocation: value => { value.resultOrigin = "supervisor"; value.abortCause = "deadline"; value.timing.finishedAtMs = 10000; }, elapsedMs: 10000 });
  const audited = readAuditedPersistentGuided(base);
  assert.equal(audited.steps[0].artifact.result.status, "incomplete"); assert.equal(audited.steps[0].returnedArtifact!.result.status, "passed");
  assert.equal(audited.summary.counts.evaluatorInvoked, 1); assert.equal(audited.summary.counts.retained, 0);
  assert.equal(audited.summary.outcome.status, "incomplete"); assert.ok(audited.summary.outcome.diagnostics.includes("persistent-campaign-time-budget"));
  assert.equal(audited.verifiedFiles.length, 5);
  for (const [name, change] of [
    ["sequence", (artifact: any) => { artifact.sequence.seed = 99; artifact.result = result(artifact.sequence); }],
    ["identity", (artifact: any) => { artifact.identity.node = "v22.23.3"; }],
    ["limits", (artifact: any) => { artifact.limits.timeoutMs--; }],
  ] as const) {
    const changed = resolve(directory, name);
    mutate(base, changed, (summary, target) => {
      const reference = summary.files[0].returnedArtifact!, artifact = json(target, reference.name); change(artifact); rehash(target, reference, artifact);
      editInvocation(summary, target, 0, value => { value.returnedArtifact = { ...reference }; });
    });
    assert.throws(() => readAuditedPersistentGuided(changed), /Returned case/);
  }
  const missing = resolve(directory, "missing"); fs.cpSync(base, missing, { recursive: true }); fs.rmSync(resolve(missing, "0001-returned.json"));
  assert.throws(() => readAuditedPersistentGuided(missing), /Missing/);
  const oversized = resolve(directory, "oversized"); fs.cpSync(base, oversized, { recursive: true }); fs.truncateSync(resolve(oversized, "0001-returned.json"), PERSISTENT_GUIDED_LIMITS.caseBytes + 1);
  assert.throws(() => readAuditedPersistentGuided(oversized), /byte bound/);
});

test("post-final deadline or identity gaps invalidate the campaign without rewriting passed schedule rows", context => {
  const directory = root(context), changedIdentity = structuredClone(guidedIdentity); changedIdentity.modules.schedule.builtSha256 = "0".repeat(64);
  for (const [name, options, diagnostic] of [
    ["deadline", { elapsedMs: 10000 }, "persistent-campaign-time-budget"],
    ["drift", { postIdentity: { status: "drift", identity: changedIdentity } }, "persistent-campaign-build-drift"],
    ["unavailable", { postIdentity: { status: "unavailable", identity: null } }, "persistent-campaign-identity-unavailable"],
  ] as const) {
    const base = resolve(directory, name); campaign(base, options);
    const audited = readAuditedPersistentGuided(base);
    assert.equal(audited.summary.transcript.snapshot.outcome.status, "passed"); assert.equal(audited.summary.outcome.status, "incomplete");
    assert.ok(audited.summary.outcome.diagnostics.includes(diagnostic));
    const forged = resolve(directory, `${name}-forged`); mutate(base, forged, summary => { summary.outcome = { status: "passed", diagnostics: [] }; });
    assert.throws(() => readAuditedPersistentGuided(forged));
  }
});

test("the final corpus pre-capture budget refusal retains original case bytes outside corpus accounting", context => {
  const directory = root(context), sizing = campaign(resolve(directory, "sizing"));
  for (const [index, corpusBudgets] of [{ maxConsiderations: 1 }, { maxEvidenceBytes: sizing.files[0].artifact.bytes }].entries()) {
    const base = resolve(directory, `base-${index}`); campaign(base, { configuration: { corpusBudgets } });
    const audited = readAuditedPersistentGuided(base), last = audited.summary.transcript.rows.at(-1)!;
    assert.equal(audited.steps.length, 2); assert.equal(audited.summary.counts.proposed, 2); assert.equal(audited.summary.counts.evaluatorInvoked, 2);
    assert.equal(audited.summary.counts.corpusConsidered, 1); assert.equal(last.admission!.artifact, null); assert.equal(last.admission!.ordinal, null);
    assert.deepEqual(last.artifact, { sha256: persistentDigest(audited.steps[1].originalBytes), bytes: audited.steps[1].originalBytes.length });
    assert.ok(audited.summary.evidenceBytesBeforeSummary > audited.summary.transcript.snapshot.corpus.evidenceBytes);
    const missing = resolve(directory, `missing-${index}`); fs.cpSync(base, missing, { recursive: true }); fs.rmSync(resolve(missing, "0002.json"));
    assert.throws(() => readAuditedPersistentGuided(missing), /Missing/);
  }
});

test("qualified synthetic failure remains linked to its ordinary case for existing reduction", context => {
  const base = resolve(root(context), "base");
  campaign(base, { result: decision => {
    const wire = synthetic(decision.sequence);
    if (decision.ordinal === 3) wire.rows[0].after.next = "999"; // Deliberately injected schema-only property failure.
    return result(decision.sequence, wire);
  } });
  const audited = readAuditedPersistentGuided(base);
  assert.equal(audited.summary.outcome.status, "failed"); assert.equal(audited.steps.length, 3);
  assert.equal(audited.steps[2].artifact.result.status, "failed"); assert.equal(audited.summary.files[2].artifact.name, "0003.json");
  assert.equal(audited.summary.files[2].artifact.sha256, persistentDigest(audited.steps[2].originalBytes));
});

test("offline audit CLI reports consistency separately from saved incomplete outcome and needs no runtime pins", context => {
  const directory = root(context), base = resolve(directory, "base"); campaign(base, { stopAfter: 0, stopReason: "persistent-campaign-interrupted" });
  const env = { ...process.env }; delete env.COMPACTC_TEST; delete env.COMPACT_RUNTIME_TEST;
  const response = spawnSync(process.execPath, ["dist/tests/generative/persistent-guided-audit.js", "--audit", base], { encoding: "utf8", env });
  assert.equal(response.status, 0, response.stderr);
  const output = JSON.parse(response.stdout); assert.equal(output.scope, "offline-evidence-consistency-only"); assert.equal(output.savedOutcome.status, "incomplete");
  const invalid = spawnSync(process.execPath, ["dist/tests/generative/persistent-guided-audit.js", "--audit", base, "--execute"], { encoding: "utf8", env });
  assert.equal(invalid.status, 2);
});
