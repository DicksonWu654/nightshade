// Fixed owned compiled-evaluation qualification; no source/state/sequence API.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const sourcePin = "562f52cbe14267ad837e49a2a4724689872f0c5a020122a32848ef7eda2f7135";
const lockPin = "2fb51a5192161882aecfe1f72bed96339fcba2d76eed52db00dadc0dc44ea901";
const manifestPin = "2e87598d12b5051ee24b1134a871302e1505a937ecc14d3d5608db48d2c2dead";
const rejectionMessage = "failed assert: owned guarded List requires nonempty";
const digest = (bytes: string | Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const chunks: Buffer[] = [];
let inputBytes = 0;
for await (const chunk of process.stdin) {
  const bytes = Buffer.from(chunk);
  if ((inputBytes += bytes.length) > 1048576) throw new Error("list-guarded-input-budget: request exceeds 1 MiB");
  chunks.push(bytes);
}
const input: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
assert.ok(input && typeof input === "object" && !Array.isArray(input), "list-guarded-protocol: expected an object");
assert.deepEqual(Object.keys(input).sort(), ["compiler", "runtimeDirectory"], "list-guarded-protocol: accepts only compiler/runtime paths, no source, state, adapter or saved code");
const request = input as { compiler: unknown; runtimeDirectory: unknown };
assert.equal(typeof request.compiler, "string");
assert.equal(typeof request.runtimeDirectory, "string");
const compilerPath = resolve(request.compiler as string);
const runtimeDirectory = resolve(request.runtimeDirectory as string);
const fixtures = fileURLToPath(new URL("../../../tests/runtime-fixtures/", import.meta.url));
const source = resolve(fixtures, "list-guarded.compact");
assert.equal(digest(readFileSync(source)), sourcePin, "list-guarded-input-identity: fixed fixture mismatch");
assert.equal(digest(readFileSync(resolve(fixtures, "runtime-inputs.json"))), manifestPin, "list-guarded-input-identity: runtime manifest mismatch");
assert.equal(digest(readFileSync(resolve(fixtures, "qualification-inputs/package-lock.json"))), lockPin, "list-guarded-input-identity: repository runtime lock mismatch");
assert.equal(digest(readFileSync(resolve(runtimeDirectory, "package-lock.json"))), lockPin, "list-guarded-input-identity: restored runtime lock mismatch");

function compiler(args: string[]): string {
  const result = spawnSync(compilerPath, args, { encoding: "utf8", timeout: 30000, maxBuffer: 1048576, killSignal: "SIGKILL" });
  assert.equal(result.status, 0, `list-guarded-compiler: ${String(result.error ?? result.stderr)}`);
  assert.equal(result.stderr, "", "list-guarded-compiler: unexpected stderr");
  return result.stdout.trim();
}
assert.equal(compiler(["--version"]), "0.34.0");
assert.equal(compiler(["--language-version"]), "0.26.0");
assert.equal(compiler(["--runtime-version"]), "0.19.0");
const modules = resolve(runtimeDirectory, "node_modules");
const runtimeVersions = {
  "@midnight-ntwrk/compact-runtime": "0.19.0", "@midnightntwrk/onchain-runtime-v4": "4.0.0-rc.3",
  "@noble/curves": "2.3.0", "@noble/hashes": "2.3.0", "@types/object-inspect": "1.13.0", "object-inspect": "1.13.4",
};
for (const [name, version] of Object.entries(runtimeVersions)) assert.equal(JSON.parse(readFileSync(resolve(modules, name, "package.json"), "utf8")).version, version, name);
// Version/lock provenance does not attest all installed package bytes.
const runtime = await import(pathToFileURL(resolve(modules, "@midnight-ntwrk/compact-runtime/dist/index.js")).href);
assert.equal(runtime.versionString, "0.19.0");

type Private = Readonly<{ next: bigint }>;
interface LedgerView { empty: boolean; length: bigint; head: { is_some: boolean; value: bigint }; values: bigint[] }
interface View extends LedgerView { publicSha256: string; privateState: Private }
interface Snapshot { container: any; serialized: Uint8Array; text: string; privateState: Private; observation: View }
type Operation = { call: "inspect" | "guardedPop"; args: [] } | { call: "push"; args: [bigint] };
const inspect = (): Operation => ({ call: "inspect", args: [] });
const pop = (): Operation => ({ call: "guardedPop", args: [] });
const push = (value: bigint): Operation => ({ call: "push", args: [value] });
const scenarios = [
  { name: "one-cell", operations: [inspect(), pop(), inspect()] },
  { name: "multiple-cells", operations: [push(9n), push(17n), inspect(), pop(), inspect(), pop(), inspect(), pop(), inspect()] },
  { name: "empty-guard-and-recovery", operations: [pop(), inspect(), pop(), inspect(), push(9n), inspect(), pop(), inspect()] },
];
const fixedTime = 1700000000;
const directory = mkdtempSync(resolve(tmpdir(), "nightshade-list-guarded-runtime-"));
try {
  writeFileSync(resolve(directory, "package.json"), '{"private":true,"type":"module"}\n');
  symlinkSync(modules, resolve(directory, "node_modules"), process.platform === "win32" ? "junction" : "dir");
  const compiled = resolve(directory, "compiled");
  compiler(["--skip-zk", source, compiled]);
  const compiledPath = resolve(compiled, "contract/index.js");
  const contractModule = await import(pathToFileURL(compiledPath).href);
  const retained: Snapshot[] = [];
  const contexts = new Set<unknown>();
  const readLedger = (state: any): LedgerView => {
    const values = contractModule.ledger(state).values;
    const empty: unknown = values.isEmpty(), length: unknown = values.length(), head: unknown = values.head();
    const elements: unknown[] = [...values];
    assert.equal(typeof empty, "boolean"); assert.equal(typeof length, "bigint");
    assert.ok(head && typeof head === "object");
    assert.deepEqual(Object.keys(head).sort(), ["is_some", "value"]);
    const maybe = head as { is_some: unknown; value: unknown };
    assert.equal(typeof maybe.is_some, "boolean"); assert.equal(typeof maybe.value, "bigint");
    assert.ok(elements.every(value => typeof value === "bigint"));
    return { empty: empty as boolean, length: length as bigint, head: { is_some: maybe.is_some as boolean, value: maybe.value as bigint }, values: elements as bigint[] };
  };
  const retain = (container: any, privateState: Private): Snapshot => {
    assert.ok(Object.isFrozen(privateState), "Immutable private state required");
    assert.deepEqual(privateState, { next: 7n }, "This fixture has no witnesses or private-state updates");
    const serialized = Uint8Array.from(container.serialize());
    const copy = runtime.ContractState.deserialize(serialized.slice());
    const text = copy.data.toString();
    assert.equal(text, container.data.toString(), "Constructor/accepted container serialization changed public state");
    assert.deepEqual(Uint8Array.from(copy.serialize()), serialized, "Container serialization is not stable");
    const savedPrivate = Object.freeze({ next: privateState.next });
    const observation: View = { ...readLedger(copy.data), publicSha256: digest(serialized), privateState: savedPrivate };
    const snapshot = { container: copy, serialized, text, privateState: savedPrivate, observation };
    retained.push(snapshot);
    return snapshot;
  };
  const validateRetained = (): void => {
    for (const snapshot of retained) {
      assert.equal(snapshot.container.data.toString(), snapshot.text, "Retained public state changed");
      assert.deepEqual(Uint8Array.from(snapshot.container.serialize()), snapshot.serialized, "Retained public bytes changed");
      assert.equal(digest(snapshot.serialized), snapshot.observation.publicSha256);
      assert.deepEqual(readLedger(snapshot.container.data), (({ publicSha256, privateState, ...ledger }) => ledger)(snapshot.observation));
      assert.ok(Object.isFrozen(snapshot.privateState));
      assert.deepEqual(snapshot.privateState, { next: 7n }, "Retained private state changed");
    }
  };
  const executions: unknown[] = [];
  for (const scenario of scenarios) {
    // A fresh constructor and immutable private object per fixed scenario.
    const contract = new contractModule.Contract({});
    const privateState = Object.freeze({ next: 7n });
    const initialized = await contract.initialState(runtime.createConstructorContext(privateState, "0".repeat(64)));
    assert.equal(initialized.currentPrivateState, privateState);
    let current = retain(initialized.currentContractState, initialized.currentPrivateState);
    const initial = current.observation;
    const rows: unknown[] = [];
    for (const [index, operation] of scenario.operations.entries()) {
      const accepted = current;
      const context = runtime.createCircuitContext(operation.call, runtime.dummyContractAddress(), "0".repeat(64), accepted.container.data, accepted.privateState, undefined, undefined, undefined, fixedTime);
      assert.ok(!contexts.has(context), "A circuit context was reused"); contexts.add(context);
      let evaluated: any;
      let error: null | { name: "CompactError"; message: string } = null;
      try { evaluated = await contract.circuits[operation.call](context, ...operation.args); }
      catch (caught) {
        // Only the exact fixture guard rejection is an observation. Infrastructure
        // assertions, unexpected runtime errors and errors from other calls fail.
        if (operation.call !== "guardedPop" || !(caught instanceof runtime.CompactError) || !(caught instanceof Error) || caught.name !== "CompactError" || caught.message !== rejectionMessage) throw caught;
        error = { name: "CompactError", message: caught.message };
      }
      assert.equal(context.callContext.currentQueryContext.state.toString(), accepted.text, "Call changed its input public snapshot");
      assert.equal(context.callContext.currentPrivateState, accepted.privateState, "Call replaced its input private snapshot");
      let result: unknown = null;
      let transcript: null | { circuit: string; privateOutputs: number; events: number } = null;
      if (evaluated !== undefined) {
        result = evaluated.result;
        if (operation.call === "inspect") {
          assert.ok(Array.isArray(result) && result.length === 3);
          assert.equal(typeof result[0], "boolean"); assert.equal(typeof result[1], "bigint");
          assert.ok(result[2] && typeof result[2] === "object");
          assert.deepEqual(Object.keys(result[2]).sort(), ["is_some", "value"]);
          assert.equal(typeof result[2].is_some, "boolean"); assert.equal(typeof result[2].value, "bigint");
        } else assert.deepEqual(result, []);
        assert.equal(evaluated.context.callProofDataTrace.length, 1);
        const trace = evaluated.context.callProofDataTrace[0];
        assert.equal(trace.circuitId, operation.call);
        assert.equal(trace.privateTranscriptOutputs.length, 0);
        assert.equal(evaluated.context.events.length, 0);
        transcript = { circuit: trace.circuitId, privateOutputs: trace.privateTranscriptOutputs.length, events: evaluated.context.events.length };
        const container = runtime.ContractState.deserialize(accepted.serialized.slice());
        container.data = evaluated.context.callContext.currentQueryContext.state;
        current = retain(container, evaluated.context.callContext.currentPrivateState);
      } else {
        assert.ok(error, "No evaluation result or qualified rejection");
        assert.equal(current, accepted, "Rejected call advanced the accepted snapshot");
      }
      validateRetained();
      rows.push({ index, ...operation, outcome: error ? "evaluation-rejection" : "evaluation-success", result, error, transcript, before: accepted.observation, after: current.observation });
    }
    executions.push({ name: scenario.name, initial, rows, final: current.observation });
  }
  validateRetained();
  process.stdout.write(JSON.stringify({ schemaVersion: "nightshade-list-guarded-runtime-1", layer: "compiled-evaluation-only", fixture: "owned-typed-guarded-list", stateOrigin: "fresh-constructor-and-prior-accepted-typed-calls", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime,
    identity: { sourceSha256: digest(readFileSync(source)), compiledJavaScriptSha256: digest(readFileSync(compiledPath)), runtimeLockSha256: lockPin, runtimeManifestSha256: manifestPin,
      compilerSha256: digest(readFileSync(compilerPath)), compilerDistribution: ["compactc.bin", "zkir", "zkir-v3"].map(file => ({ file, sha256: digest(readFileSync(resolve(dirname(compilerPath), file))) })),
      workerSourceSha256: digest(readFileSync(resolve(fixtures, "list-guarded-worker.ts"))), workerBuildSha256: digest(readFileSync(fileURLToPath(import.meta.url))), runtimeVersions },
    retainedSnapshotsChecked: retained.length, executions }, (_key, value: unknown) => typeof value === "bigint" ? { $bigint: String(value) } : value));
} finally { rmSync(directory, { recursive: true, force: true }); }
