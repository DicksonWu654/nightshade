import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { digest } from "./generative/artifacts.js";
import { expectedFlagObservations, renderCase, type GeneratedCase } from "./generative/model.js";
import { checkRuntimeObservation, incompleteRuntimeResult, makeRuntimeArtifact, RUNTIME_LIMITS, type RuntimeCheckResult, type RuntimeIdentity } from "./generative/runtime-artifacts.js";
import { auditRuntimeCampaign, makeGuidedManifest, type GuidedManifest, type GuidedRow } from "./generative/runtime-guided.js";
import { DEFAULT_SCHEDULE, RuntimeSchedule, type ScheduleOptions } from "./generative/runtime-schedule.js";

const syntheticIdentity: RuntimeIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: "0".repeat(64), runtimeInputsManifestSha256: "1".repeat(64), runtimeAdapterSourceSha256: "2".repeat(64), runtimeAdapterBuildSha256: "3".repeat(64) };

/** Synthetic schema evidence only; these transcripts claim no runtime execution. */
function fixture(input: GeneratedCase): RuntimeCheckResult {
  return checkRuntimeObservation(input, { layer: "compiled-evaluation-only", source: "validated-owned-generated-model", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    generatedSourceSha256: digest(renderCase(input)), compiledJavaScriptSha256: "a".repeat(64),
    executions: expectedFlagObservations(input).map(({ flag, observations }) => ({ flag, outcome: "evaluation-success", result: observations.map(row => row.map((value, index) => ({ kind: index === 1 ? "boolean" : "integer", value }))) })) });
}
const save = (directory: string, name: string, value: unknown): string => {
  const content = JSON.stringify(value, null, 2) + "\n";
  writeFileSync(resolve(directory, name), content);
  return digest(content);
};
const load = (directory: string, name: string) => JSON.parse(readFileSync(resolve(directory, name), "utf8"));

function synthetic(options: Partial<ScheduleOptions>, check: (directory: string, manifest: GuidedManifest, schedule: RuntimeSchedule) => void,
  result: (input: GeneratedCase) => RuntimeCheckResult = fixture): void {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-synthetic-guidance-"));
  try {
    const schedule = new RuntimeSchedule({ ...DEFAULT_SCHEDULE, mutations: 4, ...options });
    const rows: GuidedRow[] = [];
    let decision;
    while ((decision = schedule.next())) {
      const prefix = String(decision.ordinal).padStart(4, "0");
      const decisionName = `${prefix}-decision.json`, artifact = `${prefix}.json`;
      const decisionSha256 = save(directory, decisionName, decision);
      const checked = result(decision.case);
      const artifactSha256 = save(directory, artifact, makeRuntimeArtifact(decision.case, syntheticIdentity, RUNTIME_LIMITS, checked));
      rows.push({ ...schedule.record(checked, artifactSha256), decision: decisionName, artifact, decisionSha256, artifactSha256 });
    }
    const manifest = makeGuidedManifest(schedule, syntheticIdentity, RUNTIME_LIMITS, rows);
    save(directory, "summary.json", manifest);
    check(directory, manifest, schedule);
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test("saved guided audit reconstructs checked admissions, parent decisions and bounded corpus", () => {
  synthetic({}, (directory, manifest) => {
    const audited = auditRuntimeCampaign(directory);
    assert.equal(audited.audit, "consistent");
    assert.equal(audited.executionReplay, false);
    assert.deepEqual(audited.manifest, manifest);
    assert.equal(manifest.rows.length, 8);
    assert.equal(manifest.outcome.status, "passed");
    const reordered = Object.fromEntries(Object.entries(manifest).reverse());
    save(directory, "summary.json", reordered);
    assert.deepEqual(auditRuntimeCampaign(directory).manifest, manifest, "JSON property order is not a scheduling input");
  });
});

test("audit rejects forged novelty, corpus, counts, identities, limits and file paths", () => {
  const corruptions: ((manifest: GuidedManifest) => void)[] = [
    manifest => manifest.rows[0].admission!.newFeatures.push("invented-execution-edge"),
    manifest => manifest.corpus.features.push("invented-execution-edge"),
    manifest => manifest.counts.passed++, manifest => manifest.planned++, manifest => manifest.completed--,
    manifest => { manifest.identity.compilerSha256 = "0".repeat(64); },
    manifest => { manifest.limits.timeoutMs = 1; },
    manifest => { manifest.rows[0].artifact = "../outside.json"; },
    manifest => { manifest.rows[0].decision = "/tmp/unrelated.json"; },
    manifest => { manifest.rows[0].artifactSha256 = "0".repeat(64); },
    manifest => { manifest.rows[0].status = "incomplete"; },
    manifest => { manifest.options.maxFeatures = 1; },
  ];
  for (const corrupt of corruptions) synthetic({}, (directory, manifest) => {
    corrupt(manifest);
    save(directory, "summary.json", manifest);
    assert.throws(() => auditRuntimeCampaign(directory));
  });
});

test("rehashing tampered decisions cannot invent parents, random words, mutations or candidate source", () => {
  for (const changed of ["parent", "parent-hash", "random", "mutation", "case", "extra"]) synthetic({}, (directory, manifest) => {
    const row = manifest.rows[4];
    const decision = load(directory, row.decision);
    if (changed === "parent") decision.parent.ordinal = 5; // Forward/self linkage.
    if (changed === "parent-hash") decision.parent.artifactSha256 = "0".repeat(64);
    if (changed === "random") decision.random.words[0] ^= 1;
    if (changed === "mutation") decision.mutation.index++;
    if (changed === "case") { decision.case.operations = []; decision.modelSha256 = digest(JSON.stringify(decision.case)); decision.sourceSha256 = digest(renderCase(decision.case)); }
    if (changed === "extra") decision.adapter = "unqualified";
    row.decisionSha256 = save(directory, row.decision, decision);
    save(directory, "summary.json", manifest);
    assert.throws(() => auditRuntimeCampaign(directory), /decision\/parent\/random/);
  });
});

test("audit checks actual case schemas and identities even after artifact hashes are replaced", () => {
  for (const changed of ["feedback", "identity", "limits", "source", "classification"]) synthetic({}, (directory, manifest) => {
    const row = manifest.rows[0];
    const artifact = load(directory, row.artifact);
    if (changed === "feedback") artifact.result.feedback.features.push("fabricated");
    if (changed === "identity") artifact.identity.node = "v22.23.3";
    if (changed === "limits") artifact.limits.timeoutMs = 1;
    if (changed === "source") artifact.source += "// injected source";
    if (changed === "classification") artifact.result.status = "failed";
    row.artifactSha256 = save(directory, row.artifact, artifact);
    save(directory, "summary.json", manifest);
    assert.throws(() => auditRuntimeCampaign(directory));
  });
});

test("audit refuses missing/extra/symlink/oversized evidence and omitted suffixes", () => {
  for (const changed of ["missing", "extra", "symlink", "oversized", "suffix", "unfinished"]) synthetic({}, (directory, manifest) => {
    const first = resolve(directory, manifest.rows[0].artifact);
    if (changed === "missing") rmSync(first);
    if (changed === "extra") writeFileSync(resolve(directory, "extra.json"), "{}");
    if (changed === "symlink") { rmSync(first); symlinkSync("summary.json", first); }
    if (changed === "oversized") truncateSync(first, 8 * 1024 * 1024 + 1);
    if (changed === "suffix") {
      manifest.rows.pop();
      manifest.completed--;
      manifest.counts.passed--;
      manifest.outcome = { status: "incomplete", category: "runtime-campaign-interrupted" };
      save(directory, "summary.json", manifest);
    }
    if (changed === "unfinished") rmSync(resolve(directory, "summary.json"));
    assert.throws(() => auditRuntimeCampaign(directory));
  });
});

test("audited budget/worker stops stay incomplete while checked property stops stay failed", () => {
  synthetic({ maxEvaluations: 2 }, (directory, manifest) => {
    assert.equal(auditRuntimeCampaign(directory).manifest.outcome.category, "runtime-evaluation-budget");
    assert.equal(manifest.completed, 2);
    assert.equal(manifest.counts.incomplete, 0, "campaign exhaustion is distinct from candidate results");
  });
  synthetic({ maxFeatures: 1 }, (directory, manifest) => {
    assert.equal(auditRuntimeCampaign(directory).manifest.outcome.category, "runtime-corpus-budget");
    assert.equal(manifest.rows[0].resultStatus, "passed");
    assert.equal(manifest.rows[0].status, "incomplete");
    assert.equal(manifest.corpus.entries.length, 0);
  });
  synthetic({}, (directory, manifest) => {
    assert.equal(auditRuntimeCampaign(directory).manifest.outcome.category, "worker-timeout");
    assert.equal(manifest.completed, 1);
  }, () => incompleteRuntimeResult("worker-timeout", "Synthetic timeout; no execution"));
  synthetic({}, (directory, manifest) => {
    assert.equal(auditRuntimeCampaign(directory).manifest.outcome.status, "failed");
    assert.equal(manifest.completed, 1);
    assert.equal(manifest.corpus.entries.length, 0);
  }, input => {
    const observation = fixture(input).observation!;
    observation.executions[0].result = [];
    return checkRuntimeObservation(input, observation);
  });
});

test("between-worker interruption is explicit and manifest builders do not invoke metadata getters", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-guidance-interrupted-"));
  try {
    const schedule = new RuntimeSchedule();
    schedule.interrupt();
    const manifest = makeGuidedManifest(schedule, syntheticIdentity, RUNTIME_LIMITS, []);
    save(directory, "summary.json", manifest);
    assert.equal(auditRuntimeCampaign(directory).manifest.outcome.category, "runtime-campaign-interrupted");
    assert.equal(manifest.completed, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
  synthetic({}, (_directory, manifest, schedule) => {
    const rows = structuredClone(manifest.rows);
    Object.defineProperty(rows[0], "artifactSha256", { enumerable: true, get() { assert.fail("metadata getter must not execute"); } });
    assert.throws(() => makeGuidedManifest(schedule, syntheticIdentity, RUNTIME_LIMITS, rows), /data field/);
  });
});

test("manifest creation rejects hidden, accessor and sparse array rows before cloning evidence", () => {
  synthetic({}, (_directory, manifest, schedule) => {
    for (const corruption of ["hidden", "accessor", "sparse"]) {
      const rows = structuredClone(manifest.rows);
      if (corruption === "hidden") Object.defineProperty(rows, "0", { value: rows[0], enumerable: false });
      if (corruption === "accessor") Object.defineProperty(rows, "0", { enumerable: true, get() { assert.fail("array row getter must not execute"); } });
      if (corruption === "sparse") delete rows[0];
      assert.throws(() => makeGuidedManifest(schedule, syntheticIdentity, RUNTIME_LIMITS, rows), /campaign row|Campaign row/, corruption);
    }
  });
});

function cli(args: string[], environment = process.env) {
  return spawnSync(process.execPath, [resolve("dist/tests/generative/runtime-guided.js"), ...args], { encoding: "utf8", timeout: 120000, maxBuffer: 1024 * 1024, env: environment });
}

test("audit CLI is read-only, needs no execution inputs, and rejects mixed/arbitrary interfaces", () => {
  synthetic({}, (directory) => {
    const audited = cli(["--audit", directory], { ...process.env, COMPACTC_TEST: "", COMPACT_RUNTIME_TEST: "" });
    assert.equal(audited.status, 0, audited.stderr || audited.stdout);
    assert.equal(JSON.parse(audited.stdout).executionReplay, false);
    assert.equal(cli(["--audit", directory, "--mutations", "1"]).status, 2);
    assert.equal(cli(["--audit", directory, "--adapter", "anything"]).status, 2);
  });
  assert.equal(cli(["--output", "/tmp/unused", "--mutations", "65"]).status, 2);
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
test("actual small guided campaigns reproduce measured decisions and retain schema-2 case replay", qualified, () => {
  assert.ok(process.env.COMPACTC_TEST && process.env.COMPACT_RUNTIME_TEST, "Runtime qualification also requires pinned COMPACTC_TEST");
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-measured-guidance-"));
  try {
    const manifests: GuidedManifest[] = [];
    for (const name of ["first", "second"]) {
      const output = resolve(directory, name);
      const executed = cli(["--output", output, "--seed", "42", "--mutations", "2"]);
      assert.equal(executed.status, 0, executed.stderr || executed.stdout);
      const audited = auditRuntimeCampaign(output);
      assert.equal(audited.executionReplay, false);
      assert.equal(audited.manifest.completed, 6);
      assert.equal(audited.manifest.counts.passed, 6);
      manifests.push(audited.manifest);
    }
    assert.deepEqual(manifests[1], manifests[0], "same-build measured campaigns must reproduce artifacts and decisions");
    const replay = spawnSync(process.execPath, [resolve("dist/tests/generative/runtime-smoke.js"), "--output", resolve(directory, "replay"), "--replay", resolve(directory, "first", "0006.json"), "--reduce-checks", "0"], { encoding: "utf8", timeout: 90000, maxBuffer: 1024 * 1024 });
    assert.equal(replay.status, 0, replay.stderr || replay.stdout);
    assert.equal(load(resolve(directory, "replay"), "summary.json").replay.matched, true);
    assert.equal(cli(["--output", resolve(directory, "first"), "--mutations", "0"]).status, 2, "existing evidence cannot be overwritten");
    const refused = resolve(directory, "refused");
    assert.equal(cli(["--output", refused, "--source", "anything"]).status, 2);
    assert.equal(existsSync(refused), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("[timing] actual guided worker timeout saves the decision/result and stops with explicit incomplete evidence", qualified, () => {
  assert.ok(process.env.COMPACTC_TEST && process.env.COMPACT_RUNTIME_TEST, "Runtime qualification also requires pinned COMPACTC_TEST");
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-guidance-timeout-"));
  try {
    const output = resolve(directory, "timed");
    const executed = cli(["--output", output, "--mutations", "2", "--timeout-ms", "1"]);
    assert.equal(executed.status, 2, executed.stderr || executed.stdout);
    const audited = auditRuntimeCampaign(output);
    assert.equal(audited.manifest.completed, 1);
    assert.equal(audited.manifest.outcome.category, "worker-timeout");
    assert.equal(audited.manifest.corpus.entries.length, 0);
    assert.equal(load(output, "0001.json").result.status, "incomplete");
    assert.equal(load(output, "0001-decision.json").ordinal, 1);
    assert.equal(cli(["--audit", output]).status, 2, "consistent incomplete audit cannot count as a passing campaign");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
