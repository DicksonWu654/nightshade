import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runNodeModule } from "../src/runtime/process.js";

const worker = fileURLToPath(new URL("./runtime-fixtures/list-guarded-worker.js", import.meta.url));
const source = fileURLToPath(new URL("../../tests/runtime-fixtures/list-guarded.compact", import.meta.url));
const sourcePin = "562f52cbe14267ad837e49a2a4724689872f0c5a020122a32848ef7eda2f7135";
const runtimeDirectory = process.env.COMPACT_RUNTIME_TEST;
const qualification = { skip: !runtimeDirectory ? "Requires pinned external COMPACT_RUNTIME_TEST" : false };
const limits = { timeoutMs: 60000, heapMiB: 256, maxOutputBytes: 1048576 };
const sha256 = /^[a-f0-9]{64}$/;

interface Snapshot {
  empty: boolean; length: bigint; head: { is_some: boolean; value: bigint }; values: bigint[];
  publicSha256: string; privateState: { next: bigint };
}
interface Row {
  index: number; call: string; args: bigint[]; outcome: string; result: unknown;
  error: null | { name: string; message: string };
  transcript: null | { circuit: string; privateOutputs: number; events: number };
  before: Snapshot; after: Snapshot;
}
interface Execution { name: string; initial: Snapshot; rows: Row[]; final: Snapshot }
const snapshot = (values: bigint[]) => ({ empty: values.length === 0, length: BigInt(values.length), head: { is_some: values.length !== 0, value: values[0] ?? 0n }, values, privateState: { next: 7n } });
const withoutHash = ({ publicSha256, ...value }: Snapshot) => value;

test("guarded List runtime qualification pins its separate owned source", () => {
  assert.equal(createHash("sha256").update(readFileSync(source)).digest("hex"), sourcePin);
});

test("guarded List worker rejects source, state, adapter, saved code and sequence overrides before external access", async () => {
  for (const [field, value] of Object.entries({ source: "not accepted", state: {}, adapter: "/not/accepted.js", savedCode: "not accepted", sequence: [], fixture: "list" })) {
    await assert.rejects(() => runNodeModule(worker, { compiler: "/unavailable/compiler", runtimeDirectory: "/unavailable/runtime", [field]: value },
      { timeoutMs: 5000, heapMiB: 128, maxOutputBytes: 16384 }), /list-guarded-protocol/);
  }
});

test("qualified guarded List pop preserves typed tails and rejects empty state without advancing accepted snapshots", qualification, async () => {
  assert.ok(process.env.COMPACTC_TEST, "COMPACT_RUNTIME_TEST also requires pinned COMPACTC_TEST");
  const result = await runNodeModule(worker, { compiler: process.env.COMPACTC_TEST, runtimeDirectory }, limits);
  assert.equal(result.stderr, "");
  const observed = JSON.parse(result.stdout, (_key, value: unknown) => {
    if (value && typeof value === "object" && "$bigint" in value) {
      assert.deepEqual(Object.keys(value), ["$bigint"]);
      assert.equal(typeof value.$bigint, "string");
      assert.match(value.$bigint as string, /^(0|[1-9][0-9]*)$/);
      return BigInt(value.$bigint as string);
    }
    return value;
  });
  assert.deepEqual({ schemaVersion: observed.schemaVersion, layer: observed.layer, fixture: observed.fixture, stateOrigin: observed.stateOrigin,
    compiler: observed.compiler, language: observed.language, runtime: observed.runtime, onchainRuntime: observed.onchainRuntime, fixedTime: observed.fixedTime },
  { schemaVersion: "nightshade-list-guarded-runtime-1", layer: "compiled-evaluation-only", fixture: "owned-typed-guarded-list", stateOrigin: "fresh-constructor-and-prior-accepted-typed-calls",
    compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000 });
  assert.equal(observed.identity.sourceSha256, sourcePin);
  assert.equal(observed.identity.runtimeLockSha256, "2fb51a5192161882aecfe1f72bed96339fcba2d76eed52db00dadc0dc44ea901");
  assert.equal(observed.identity.runtimeManifestSha256, "2e87598d12b5051ee24b1134a871302e1505a937ecc14d3d5608db48d2c2dead");
  for (const key of ["compiledJavaScriptSha256", "compilerSha256", "workerSourceSha256", "workerBuildSha256"]) assert.match(observed.identity[key], sha256);
  assert.deepEqual(observed.identity.compilerDistribution.map((item: { file: string }) => item.file), ["compactc.bin", "zkir", "zkir-v3"]);
  for (const item of observed.identity.compilerDistribution) assert.match(item.sha256, sha256);
  assert.deepEqual(observed.identity.runtimeVersions, {
    "@midnight-ntwrk/compact-runtime": "0.19.0", "@midnightntwrk/onchain-runtime-v4": "4.0.0-rc.3",
    "@noble/curves": "2.3.0", "@noble/hashes": "2.3.0", "@types/object-inspect": "1.13.0", "object-inspect": "1.13.4",
  });

  // Expectations are fixed typed stack values, independent of analyzer domains,
  // transfer functions and the worker's generated ledger accessor.
  type Expected = [call: string, args: bigint[], before: bigint[], after: bigint[], rejected?: boolean];
  const expectations: { name: string; rows: Expected[] }[] = [
    { name: "one-cell", rows: [
      ["inspect", [], [3n], [3n]], ["guardedPop", [], [3n], []], ["inspect", [], [], []],
    ] },
    { name: "multiple-cells", rows: [
      ["push", [9n], [3n], [9n, 3n]], ["push", [17n], [9n, 3n], [17n, 9n, 3n]], ["inspect", [], [17n, 9n, 3n], [17n, 9n, 3n]],
      ["guardedPop", [], [17n, 9n, 3n], [9n, 3n]], ["inspect", [], [9n, 3n], [9n, 3n]], ["guardedPop", [], [9n, 3n], [3n]],
      ["inspect", [], [3n], [3n]], ["guardedPop", [], [3n], []], ["inspect", [], [], []],
    ] },
    { name: "empty-guard-and-recovery", rows: [
      ["guardedPop", [], [3n], []], ["inspect", [], [], []], ["guardedPop", [], [], [], true], ["inspect", [], [], []],
      ["push", [9n], [], [9n]], ["inspect", [], [9n], [9n]], ["guardedPop", [], [9n], []], ["inspect", [], [], []],
    ] },
  ];
  const executions = observed.executions as Execution[];
  assert.deepEqual(executions.map(execution => execution.name), expectations.map(execution => execution.name));
  assert.equal(observed.retainedSnapshotsChecked, 22);
  for (const [caseIndex, expected] of expectations.entries()) {
    const execution = executions[caseIndex];
    assert.deepEqual(withoutHash(execution.initial), snapshot([3n]));
    assert.match(execution.initial.publicSha256, sha256);
    assert.equal(execution.initial.publicSha256, executions[0].initial.publicSha256, "fresh constructors must begin with equivalent state");
    assert.equal(execution.rows.length, expected.rows.length);
    let previous = execution.initial;
    for (const [index, [call, args, before, after, rejected = false]] of expected.rows.entries()) {
      const row = execution.rows[index];
      assert.match(row.before.publicSha256, sha256); assert.match(row.after.publicSha256, sha256);
      assert.deepEqual(row.before, previous, "The call must use the previously accepted snapshot");
      assert.deepEqual({ ...row, before: withoutHash(row.before), after: withoutHash(row.after) }, {
        index, call, args, outcome: rejected ? "evaluation-rejection" : "evaluation-success",
        result: rejected ? null : call === "inspect" ? [before.length === 0, BigInt(before.length), snapshot(before).head] : [],
        error: rejected ? { name: "CompactError", message: "failed assert: owned guarded List requires nonempty" } : null,
        transcript: rejected ? null : { circuit: call, privateOutputs: 0, events: 0 }, before: snapshot(before), after: snapshot(after),
      });
      if (rejected || call === "inspect") assert.equal(row.after.publicSha256, row.before.publicSha256, "Rejection or inspection advanced accepted public state");
      else assert.notEqual(row.after.publicSha256, row.before.publicSha256, "Accepted List mutation did not change public state");
      previous = row.after;
    }
    assert.deepEqual(execution.final, previous);
    assert.deepEqual(withoutHash(execution.final), snapshot([]));
  }
});
