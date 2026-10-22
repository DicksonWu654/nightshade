import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runNodeModule } from "../src/runtime/process.js";
import { expectedFlagObservations, generateCase, renderCase, validateCase } from "./generative/model.js";

const runtimeDirectory = process.env.COMPACT_RUNTIME_TEST;
const qualification = { skip: !runtimeDirectory ? "Requires pinned external COMPACT_RUNTIME_TEST" : false };
const worker = fileURLToPath(new URL("./runtime-fixtures/generated-worker.js", import.meta.url));
const fixedCases = [
  ["seed 0, one operation", generateCase(0, 1)],
  ["seed 42, twelve operations", generateCase(42, 12)],
  ["uint32 boundary seed, thirty-two operations", generateCase(0xffffffff, 32)],
  ["correlated branches with snapshots", validateCase({ schemaVersion: "nightshade-generated-case-1", seed: 1, operations: [
    { kind: "write", value: 3 }, { kind: "snapshot" }, { kind: "conditional", key: 1, value: 5 },
    { kind: "read", key: 1 }, { kind: "unrelated", value: 65535 }, { kind: "snapshot" },
    { kind: "conditional", key: 2, value: 9 }, { kind: "read", key: 1 },
  ] })],
] as const;

for (const [name, input] of fixedCases) test(`owned generated model agrees with compiled evaluation: ${name}`, qualification, async () => {
  assert.ok(process.env.COMPACTC_TEST, "COMPACT_RUNTIME_TEST also requires COMPACTC_TEST");
  const item = validateCase(input);
  const output = await runNodeModule(worker, { case: item, compiler: process.env.COMPACTC_TEST, runtimeDirectory },
    { timeoutMs: 60000, heapMiB: 256, maxOutputBytes: 1024 * 1024 });
  assert.equal(output.stderr, "");
  const observed = JSON.parse(output.stdout);
  assert.deepEqual({ layer: observed.layer, source: observed.source, compiler: observed.compiler,
    language: observed.language, runtime: observed.runtime, onchainRuntime: observed.onchainRuntime, fixedTime: observed.fixedTime },
  { layer: "compiled-evaluation-only", source: "validated-owned-generated-model", compiler: "0.34.0",
    language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000 });
  assert.equal(observed.generatedSourceSha256, createHash("sha256").update(renderCase(item)).digest("hex"));
  assert.match(observed.compiledJavaScriptSha256, /^[a-f0-9]{64}$/);
  // Preserve input association even when both inputs have identical results.
  // Check nested shape and scalar kinds as well as values; Boolean false must
  // never accidentally compare equal to integer zero or the string "false".
  assert.deepEqual(observed.executions, expectedFlagObservations(item).map(({ flag, observations }) => ({
    flag, outcome: "evaluation-success", result: observations.map(checkpoint => checkpoint.map((value, index) => ({
      kind: index === 1 ? "boolean" : "integer", value,
    }))),
  })));
});

test("generated runtime adapter rejects embedded source before loading external inputs", async () => {
  await assert.rejects(() => runNodeModule(worker, {
    case: { schemaVersion: "nightshade-generated-case-1", seed: 1, operations: [], source: "not accepted" },
    compiler: "/unavailable/compiler", runtimeDirectory: "/unavailable/runtime",
  }, { timeoutMs: 5000, heapMiB: 128, maxOutputBytes: 16384 }), /case has unexpected or missing fields/);
});
