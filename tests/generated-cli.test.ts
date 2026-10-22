import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const command = resolve("dist/tests/generative/campaign.js");
function run(args: string[]) {
  return spawnSync(process.execPath, [command, ...args], { encoding: "utf8", timeout: 60000, maxBuffer: 1024 * 1024 });
}

test("generated campaign CLI records effective budgets and replays the same build", qualified, () => {
  withFiles({}, directory => {
    const output = resolve(directory, "campaign");
    const first = run(["--output", output, "--cases", "1", "--steps", "2", "--seed", "42"]);
    assert.equal(first.status, 0, first.stderr || first.stdout);
    const artifactPath = resolve(output, "0000-42.json");
    const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
    assert.equal(artifact.schemaVersion, "nightshade-generated-artifact-2");
    assert.deepEqual(artifact.budgets, { maxSteps: 20000, maxPaths: 256, maxValues: 50000 });
    assert.equal(artifact.result.compiler.valid, true);
    const replay = resolve(directory, "replay");
    const rerun = run(["--output", replay, "--replay", artifactPath]);
    assert.equal(rerun.status, 0, rerun.stderr || rerun.stdout);
    const summary = JSON.parse(readFileSync(resolve(replay, "summary.json"), "utf8"));
    assert.equal(summary.schemaVersion, "nightshade-generated-campaign-2");
    assert.equal(summary.replay.comparison, false);
    assert.equal(summary.replay.sameStatus, true);
    assert.equal(summary.replay.sameSignature, true);
    assert.equal(summary.replay.sameObservation, true);
    assert.equal(run(["--output", output, "--cases", "1"]).status, 2, "prior evidence must not be overwritten");
  });
});

test("generated replay requires explicit comparison after an identity change", qualified, () => {
  withFiles({}, directory => {
    const output = resolve(directory, "campaign");
    const initial = run(["--output", output, "--cases", "1", "--steps", "1", "--seed", "0"]);
    assert.equal(initial.status, 0, initial.stderr || initial.stdout);
    const artifactPath = resolve(output, "0000-0.json");
    const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
    artifact.identity.node = "v0.0.0-test-identity";
    const changed = resolve(directory, "changed.json");
    writeFileSync(changed, JSON.stringify(artifact));
    const refusedOutput = resolve(directory, "refused");
    const refused = run(["--replay", changed, "--output", refusedOutput]);
    assert.equal(refused.status, 2);
    assert.match(refused.stderr, /identity mismatch/);
    assert.equal(existsSync(refusedOutput), false);
    const comparison = resolve(directory, "comparison");
    const compared = run(["--replay", changed, "--compare-build", "--output", comparison]);
    assert.equal(compared.status, 0, compared.stderr || compared.stdout);
    assert.equal(JSON.parse(readFileSync(resolve(comparison, "summary.json"), "utf8")).replay.comparison, true);
  });
});

test("[timing] generated campaign CLI never reports worker timeout as a passing campaign", qualified, () => {
  withFiles({}, directory => {
    const output = resolve(directory, "timeout");
    const result = run(["--output", output, "--cases", "1", "--steps", "1", "--timeout-ms", "1"]);
    assert.equal(result.status, 2, result.stderr || result.stdout);
    const summary = JSON.parse(readFileSync(resolve(output, "summary.json"), "utf8"));
    assert.deepEqual(summary.counts, { passed: 0, failed: 0, incomplete: 1, unqualified: 0 });
    assert.equal(summary.rows[0].category, "worker-timeout");
  });
});
