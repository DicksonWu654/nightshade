import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runNodeModule } from "../src/runtime/process.js";

const runtimeDirectory = process.env.COMPACT_RUNTIME_TEST;
const qualification = { skip: !runtimeDirectory ? "Requires pinned external COMPACT_RUNTIME_TEST" : false };

async function evaluate(fixture: "list" | "counter" | "private-state") {
  assert.ok(process.env.COMPACTC_TEST, "COMPACT_RUNTIME_TEST also requires COMPACTC_TEST");
  const output = await runNodeModule(fileURLToPath(new URL("./runtime-fixtures/worker.js", import.meta.url)),
    { fixture, compiler: process.env.COMPACTC_TEST, runtimeDirectory },
    { timeoutMs: 60000, heapMiB: 256, maxOutputBytes: 1024 * 1024 });
  assert.equal(output.stderr, "");
  const observations = JSON.parse(output.stdout, (_key, value: unknown) => {
    if (value && typeof value === "object" && "$bigint" in value) return BigInt(String(value.$bigint));
    return value;
  });
  assert.equal(observations.layer, "compiled-evaluation-only");
  assert.equal(observations.compiler, "0.34.0");
  assert.equal(observations.language, "0.26.0");
  assert.equal(observations.runtime, "0.19.0");
  assert.equal(observations.onchainRuntime, "4.0.0-rc.3");
  assert.equal(observations.fixture, fixture);
  assert.equal(observations.fixedTime, 1700000000);
  return observations;
}

const success = (call: string, result: unknown = [], next = 7n, privateTranscriptOutputs = 0) => ({
  call, outcome: "evaluation-success", result, privateState: { next }, transcriptCircuit: call,
  privateTranscriptOutputs, events: 0,
});
const rejection = (call: string, message: string, next = 7n) => ({
  call, outcome: "evaluation-rejection", privateState: { next }, error: { name: "CompactError", message },
});
const noHead = { is_some: false, value: 0n };

test("qualified compiled evaluation: List ordering and empty-pop outcomes", qualification, async () => {
  const observed = await evaluate("list");
  assert.deepEqual(observed.initial, { length: 0n, head: noHead, values: [], empty: true });
  assert.deepEqual(observed.final, observed.initial);
  assert.deepEqual(observed.witnessCalls, []);
  assert.deepEqual(observed.observations, [
    success("inspect", [true, 0n, noHead]), success("push"), success("push"),
    { ledger: { length: 2n, head: { is_some: true, value: 9n }, values: [9n, 3n], empty: false } },
    success("inspect", [false, 2n, { is_some: true, value: 9n }]), success("pop"),
    success("inspect", [false, 1n, { is_some: true, value: 3n }]), success("reset"),
    success("inspect", [true, 0n, noHead]),
    // Release 0.19.0's tail replacement succeeds here; the later query fails.
    // This records evaluation semantics, not transaction validity or an exploit.
    success("pop"),
    rejection("inspect", "Error: invalid operation for type: tried to idx, only map, array, and bmt are supported"),
    success("reset"), success("inspect", [true, 0n, noHead]),
  ]);
});

test("qualified compiled evaluation: Counter updates and fixed injected boundary representations", qualification, async () => {
  const observed = await evaluate("counter");
  assert.deepEqual(observed.initial, { count: 0n });
  assert.deepEqual(observed.final, { count: 0n });
  assert.deepEqual(observed.witnessCalls, []);
  assert.deepEqual(observed.observations, [
    success("inspect", [0n, true]), success("increment"), success("decrement"),
    success("inspect", [3n, false]), rejection("decrement", "Error: arithmetic overflow"),
    success("inspect", [3n, true]), success("reset"), success("inspect", [0n, true]),
    rejection("decrement", "Error: arithmetic overflow"), success("inspect", [0n, true]),
  ]);
  const boundary = observed.counterBoundaryQualification;
  assert.equal(boundary.layer, "compiled-evaluation-from-fixed-injected-representations");
  assert.equal(boundary.transactionReachability, "not-established");
  assert.equal(boundary.storageType, "Uint<64>");
  assert.equal(boundary.amountType, "Uint<16>");
  assert.deepEqual(boundary.storagePath, [0]);
  assert.deepEqual(boundary.alignment, [{ tag: "atom", value: { tag: "bytes", length: 8 } }]);
  assert.match(boundary.sourceSha256, /^[a-f0-9]{64}$/);
  assert.match(boundary.compiledJavaScriptSha256, /^[a-f0-9]{64}$/);
  const maximum = 18446744073709551615n;
  const expected = [
    [maximum - 1n, "increment", 1n, maximum], [maximum, "increment", 0n, maximum],
    [maximum, "increment", 1n, null], [maximum - 65535n, "increment", 65535n, maximum],
    [maximum - 65534n, "increment", 65535n, null], [maximum, "decrement", 0n, maximum],
    [maximum, "decrement", 65535n, maximum - 65535n], [65535n, "decrement", 65535n, 0n],
    [0n, "decrement", 0n, 0n], [0n, "decrement", 1n, null],
  ] as const;
  assert.deepEqual(boundary.cases, expected.map(([initial, operation, amount, result]) => ({
    initial, operation, amount, observations: [
      success("inspect", [initial, initial < maximum]),
      result === null ? rejection(operation, "Error: arithmetic overflow") : success(operation),
      success("inspect", [result ?? initial, (result ?? initial) < maximum]),
      success("reset"), success("inspect", [0n, true]),
    ],
  })));
});

test("qualified compiled evaluation: deterministic private-state success and rejection", qualification, async () => {
  const observed = await evaluate("private-state");
  assert.deepEqual(observed.initial, { count: 0n });
  assert.deepEqual(observed.final, { count: 2n });
  assert.deepEqual(observed.witnessCalls, [7n, 8n, 8n]);
  assert.deepEqual(observed.observations, [
    success("accept", 7n, 8n, 1),
    rejection("reject", "failed assert: owned fixture rejection", 8n),
    success("accept", 8n, 9n, 1),
  ]);
});
