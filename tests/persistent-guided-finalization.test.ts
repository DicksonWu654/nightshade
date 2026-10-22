import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { writePersistentGuidedRun } from "./generative/persistent-guided.js";
import { readAuditedPersistentGuided } from "./generative/persistent-guided-audit.js";
import type { PersistentGuidedIdentity } from "./generative/persistent-guided-format.js";
import { checkPersistentObservation, expectedPersistentSequence, persistentDigest, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, type PersistentSequence } from "./generative/persistent-model.js";

const identity: PersistentGuidedIdentity = { persistent: { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 }, modules: {
  feedback: { sourceSha256: "4".repeat(64), builtSha256: "5".repeat(64) }, corpus: { sourceSha256: "6".repeat(64), builtSha256: "7".repeat(64) }, schedule: { sourceSha256: "8".repeat(64), builtSha256: "9".repeat(64) },
} };
/** Schema-only evaluator: this checks orchestration, never runtime semantics. */
async function synthetic(sequence: PersistentSequence) {
  const expected = expectedPersistentSequence(sequence);
  const snapshot = (value: { count: string; next: string }) => ({ ...value, publicSha256: persistentDigest(`schema-only:${value.count}`) });
  return checkPersistentObservation(sequence, { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(sequence)), initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final) }, PERSISTENT_SOURCE_SHA256);
}

for (const cause of ["external-signal", "deadline"] as const) test(`final identity check cannot hide ${cause} after the last passing row`, async context => {
  const root = realpathSync(mkdtempSync(resolve(tmpdir(), "nightshade-guided-final-"))), directory = resolve(root, "run");
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const controller = new AbortController();
  let identityCalls = 0, elapsed = 0;
  const summary = await writePersistentGuidedRun(directory, { schedule: { seed: 1, mutations: 0, maxEvaluations: 4 }, maxElapsedMs: 1000 }, synthetic, () => {
    if (++identityCalls === 2) { if (cause === "external-signal") controller.abort(); else elapsed = 1000; }
    return identity;
  }, controller.signal, () => elapsed);
  assert.equal(identityCalls, 2);
  assert.equal(summary.transcript.snapshot.outcome.status, "passed");
  assert.equal(summary.counts.evaluatorInvoked, 4);
  assert.equal(summary.outcome.status, "incomplete");
  assert.ok(summary.outcome.diagnostics.includes(cause === "deadline" ? "persistent-campaign-time-budget" : "persistent-campaign-interrupted"));
  const saved = JSON.parse(readFileSync(resolve(directory, "summary.json"), "utf8"));
  assert.equal(saved.finalAbortCause, cause);
  assert.deepEqual(readAuditedPersistentGuided(directory).summary, summary);
  // The audit checks consistency of the saved cause, not actual signal authentication.
  for (const forged of [{ ...saved, outcome: { status: "passed", diagnostics: [] } }, { ...saved, finalAbortCause: "invented" }, { ...saved, finalAbortCause: "deadline", elapsedMs: 0 }]) {
    writeFileSync(resolve(directory, "summary.json"), JSON.stringify(forged));
    assert.throws(() => readAuditedPersistentGuided(directory));
  }
});
