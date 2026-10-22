// Fixed owned fixtures only. This is a test adapter, not a contract runner API.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

type Fixture = "list" | "counter" | "private-state";
const fixtureNames = new Set<Fixture>(["list", "counter", "private-state"]);
const chunks: Buffer[] = [];
let inputBytes = 0;
for await (const chunk of process.stdin) {
  const bytes = Buffer.from(chunk);
  inputBytes += bytes.length;
  if (inputBytes > 1024 * 1024) throw new Error("fixed-runtime-input-budget: request exceeds 1 MiB");
  chunks.push(bytes);
}
const request = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
  fixture: Fixture; compiler: string; runtimeDirectory: string;
};
assert.deepEqual(Object.keys(request).sort(), ["compiler", "fixture", "runtimeDirectory"], "Fixed fixtures do not accept source or state inputs");
assert.ok(fixtureNames.has(request.fixture), "Only fixed owned runtime fixtures are allowed");
assert.equal(typeof request.compiler, "string");
assert.equal(typeof request.runtimeDirectory, "string");

function compiler(args: string[]): string {
  const result = spawnSync(request.compiler, args, {
    encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024, killSignal: "SIGKILL",
  });
  assert.equal(result.status, 0, String(result.error ?? result.stderr));
  return result.stdout.trim();
}

assert.equal(compiler(["--version"]), "0.34.0");
assert.equal(compiler(["--language-version"]), "0.26.0");
assert.equal(compiler(["--runtime-version"]), "0.19.0");
const modules = resolve(request.runtimeDirectory, "node_modules");
const runtimePackage = resolve(modules, "@midnight-ntwrk/compact-runtime");
for (const [name, version] of Object.entries({
  "@midnight-ntwrk/compact-runtime": "0.19.0", "@midnightntwrk/onchain-runtime-v4": "4.0.0-rc.3",
  "@noble/curves": "2.3.0", "@noble/hashes": "2.3.0", "@types/object-inspect": "1.13.0", "object-inspect": "1.13.4",
})) assert.equal(JSON.parse(readFileSync(resolve(modules, name, "package.json"), "utf8")).version, version, name);
// Imports remain external qualification inputs; no runtime dependency is added to nightshade.
const runtime = await import(pathToFileURL(resolve(runtimePackage, "dist/index.js")).href);
assert.equal(runtime.versionString, "0.19.0");

const directory = mkdtempSync(resolve(tmpdir(), "nightshade-runtime-fixture-"));
try {
  writeFileSync(resolve(directory, "package.json"), '{"private":true,"type":"module"}\n');
  symlinkSync(modules, resolve(directory, "node_modules"), process.platform === "win32" ? "junction" : "dir");
  const source = fileURLToPath(new URL(`../../../tests/runtime-fixtures/${request.fixture}.compact`, import.meta.url));
  const compiled = resolve(directory, "compiled");
  compiler(["--skip-zk", source, compiled]);
  const contractModule = await import(pathToFileURL(resolve(compiled, "contract/index.js")).href);
  const witnessCalls: bigint[] = [];
  const contract = new contractModule.Contract(request.fixture === "private-state" ? {
    next: ({ privateState }: { privateState: { next: bigint } }) => {
      witnessCalls.push(privateState.next);
      return [Object.freeze({ next: privateState.next + 1n }), privateState.next];
    },
  } : {});
  const initialPrivate = Object.freeze({ next: 7n });
  const initialized = await contract.initialState(runtime.createConstructorContext(initialPrivate, "0".repeat(64)));
  const restored = runtime.ContractState.deserialize(initialized.currentContractState.serialize());
  assert.equal(restored.data.toString(), initialized.currentContractState.data.toString());
  let state = restored.data;
  let privateState = initialized.currentPrivateState;
  const initialState = state;
  const fixedTime = 1700000000;
  const fixedAddress = runtime.dummyContractAddress();
  const fixedKey = "0".repeat(64);
  const observations: unknown[] = [];
  let counterBoundaryQualification: unknown;

  // Each call begins a fresh evaluation context over the accepted snapshot. The
  // fixtures have no coins, time queries or external contracts. This does not
  // assemble, prove, or apply a ledger transaction.
  async function call(name: string, ...args: unknown[]): Promise<void> {
    const context = runtime.createCircuitContext(name, fixedAddress, fixedKey, state, privateState,
      undefined, undefined, undefined, fixedTime);
    const beforeState = state.toString();
    const beforePrivate = privateState;
    try {
      const evaluated = await contract.circuits[name](context, ...args);
      assert.equal(context.callContext.currentQueryContext.state.toString(), beforeState, "input public snapshot changed");
      assert.equal(context.callContext.currentPrivateState, beforePrivate, "input private snapshot changed");
      state = evaluated.context.callContext.currentQueryContext.state;
      privateState = evaluated.context.callContext.currentPrivateState;
      assert.equal(evaluated.context.callProofDataTrace.length, 1, "one local call transcript expected");
      observations.push({ call: name, outcome: "evaluation-success", result: evaluated.result, privateState,
        transcriptCircuit: evaluated.context.callProofDataTrace[0].circuitId,
        privateTranscriptOutputs: evaluated.context.callProofDataTrace[0].privateTranscriptOutputs.length,
        events: evaluated.context.events.length });
    } catch (error) {
      // Assertions about the harness itself are infrastructure failures.
      if (error instanceof assert.AssertionError) throw error;
      assert.equal(context.callContext.currentQueryContext.state.toString(), beforeState, "rejected call changed input public snapshot");
      assert.equal(context.callContext.currentPrivateState, beforePrivate, "rejected call changed input private snapshot");
      observations.push({ call: name, outcome: "evaluation-rejection", privateState,
        error: error instanceof Error ? { name: error.name, message: error.message } : { name: "non-error", message: String(error) } });
    }
  }

  function ledgerSnapshot(): unknown {
    const ledger = contractModule.ledger(state);
    return request.fixture === "list"
      ? { length: ledger.items.length(), head: ledger.items.head(), values: [...ledger.items], empty: ledger.items.isEmpty() }
      : { count: ledger.count };
  }

  const initial = ledgerSnapshot();
  if (request.fixture === "list") {
    await call("inspect");
    await call("push", 3n);
    await call("push", 9n);
    observations.push({ ledger: ledgerSnapshot() });
    await call("inspect");
    await call("pop");
    await call("inspect");
    await call("reset");
    await call("inspect");
    await call("pop");
    // An empty pop and subsequent read are separate outcomes; no assumed no-op
    // or immediate rejection semantics are hidden in the adapter.
    await call("inspect");
    await call("reset");
    await call("inspect");
  } else if (request.fixture === "counter") {
    await call("inspect", 1n);
    await call("increment", 5n);
    await call("decrement", 2n);
    await call("inspect", 3n);
    await call("decrement", 4n);
    await call("inspect", 4n);
    await call("reset");
    await call("inspect", 1n);
    await call("decrement", 1n);
    await call("inspect", 1n);
    // Compiler release midnight-ledger.ss:587-620 declares Counter's cell as
    // eight-byte-aligned Uint64, with Uint16 update arguments. Establish that the
    // compiled fixed fixture has exactly this layout before creating any state.
    const maximum = (1n << 64n) - 1n;
    const uint64 = new runtime.CompactTypeUnsignedInteger(maximum, 8);
    const initialFields = initialState.state.asArray();
    assert.ok(initialFields && initialFields.length === 1, "fixed Counter fixture must have one root slot");
    assert.equal(initialFields[0].type(), "cell");
    assert.deepEqual(initialFields[0].asCell().alignment, uint64.alignment());
    assert.equal(uint64.fromValue(initialFields[0].asCell().value), 0n);
    assert.equal(contractModule.ledger(initialState).count, 0n);
    const boundaries = [
      { initial: maximum - 1n, operation: "increment", amount: 1n },
      { initial: maximum, operation: "increment", amount: 0n },
      { initial: maximum, operation: "increment", amount: 1n },
      { initial: maximum - 65535n, operation: "increment", amount: 65535n },
      { initial: maximum - 65534n, operation: "increment", amount: 65535n },
      { initial: maximum, operation: "decrement", amount: 0n },
      { initial: maximum, operation: "decrement", amount: 65535n },
      { initial: 65535n, operation: "decrement", amount: 65535n },
      { initial: 0n, operation: "decrement", amount: 0n },
      { initial: 0n, operation: "decrement", amount: 1n },
    ];
    const boundaryObservations: unknown[] = [];
    for (const boundary of boundaries) {
      const value = uint64.toValue(boundary.initial);
      assert.equal(uint64.fromValue(value.map((bytes: Uint8Array) => bytes.slice())), boundary.initial);
      const cell = runtime.StateValue.newCell({ value, alignment: uint64.alignment() });
      const synthetic = runtime.ContractState.deserialize(initialized.currentContractState.serialize());
      synthetic.data = new runtime.ChargedState(runtime.StateValue.newArray().arrayPush(cell));
      const roundtrip = runtime.ContractState.deserialize(synthetic.serialize());
      assert.equal(roundtrip.data.toString(), synthetic.data.toString(), "injected representation did not roundtrip");
      state = roundtrip.data;
      assert.equal(contractModule.ledger(state).count, boundary.initial, "compiled ledger accessor disagrees with injected representation");
      const snapshot = state;
      const snapshotText = snapshot.toString();
      const observationStart = observations.length;
      await call("inspect", maximum);
      await call(boundary.operation, boundary.amount);
      await call("inspect", maximum);
      await call("reset");
      await call("inspect", 1n);
      assert.equal(snapshot.toString(), snapshotText, "retained injected snapshot changed");
      assert.equal(contractModule.ledger(snapshot).count, boundary.initial);
      boundaryObservations.push({ ...boundary, observations: observations.splice(observationStart) });
    }
    const digest = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");
    counterBoundaryQualification = {
      layer: "compiled-evaluation-from-fixed-injected-representations", transactionReachability: "not-established",
      storageType: "Uint<64>", amountType: "Uint<16>", storagePath: [0], alignment: uint64.alignment(),
      sourceSha256: digest(source), compiledJavaScriptSha256: digest(resolve(compiled, "contract/index.js")),
      cases: boundaryObservations,
    };
  } else {
    await call("accept");
    await call("reject");
    await call("accept");
  }
  const final = ledgerSnapshot();
  const savedState = state;
  state = initialState;
  assert.deepEqual(ledgerSnapshot(), initial, "retained constructor snapshot changed");
  state = savedState;
  process.stdout.write(JSON.stringify({ fixture: request.fixture,
    layer: "compiled-evaluation-only", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0",
    onchainRuntime: "4.0.0-rc.3", fixedTime, initial, final, observations, witnessCalls,
    ...(counterBoundaryQualification ? { counterBoundaryQualification } : {}) },
  (_key, value: unknown) => typeof value === "bigint" ? { $bigint: value.toString() } : value));
} finally {
  rmSync(directory, { recursive: true, force: true });
}
