// Test-only adapter for one fixed owned fixture; no arbitrary source/state API.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PERSISTENT_LOCK_SHA256, PERSISTENT_REJECTION, PERSISTENT_SOURCE_SHA256, persistentDigest, validatePersistentSequence, type PersistentObservation, type PersistentRow, type PersistentSnapshot } from "../generative/persistent-model.js";

const chunks: Buffer[] = [];
let bytes = 0;
for await (const chunk of process.stdin) {
  const buffer = Buffer.from(chunk);
  if ((bytes += buffer.length) > 1048576) throw new Error("persistent-input-budget: request exceeds 1 MiB");
  chunks.push(buffer);
}
const request: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
assert.ok(request && typeof request === "object" && !Array.isArray(request), "persistent-protocol: request must be an object");
assert.deepEqual(Object.keys(request).sort(), ["compiler", "runtimeDirectory", "sequence"], "persistent-protocol: fixed adapter accepts no source or state");
const configuration = request as { sequence: unknown; compiler: unknown; runtimeDirectory: unknown };
// Validate the complete bounded model before launching or loading external code.
const sequence = validatePersistentSequence(configuration.sequence);
assert.equal(typeof configuration.compiler, "string");
assert.equal(typeof configuration.runtimeDirectory, "string");
const compilerPath = configuration.compiler as string;
const runtimeDirectory = configuration.runtimeDirectory as string;
const fixtures = fileURLToPath(new URL("../../../tests/runtime-fixtures/", import.meta.url));
const source = resolve(fixtures, "persistent.compact");
assert.equal(persistentDigest(readFileSync(source)), PERSISTENT_SOURCE_SHA256, "persistent-input-identity: fixed fixture mismatch");
const manifest = JSON.parse(readFileSync(resolve(fixtures, "runtime-inputs.json"), "utf8"));
assert.equal(manifest.restoration.packageLockSha256, PERSISTENT_LOCK_SHA256, "persistent-input-identity: manifest lock pin changed");
const runtimeLockSha256 = persistentDigest(readFileSync(resolve(runtimeDirectory, "package-lock.json")));
assert.equal(runtimeLockSha256, PERSISTENT_LOCK_SHA256, "persistent-input-identity: runtime restoration lock mismatch");
function compiler(args: string[]): string {
  const result = spawnSync(compilerPath, args, { encoding: "utf8", timeout: 30000, maxBuffer: 1048576, killSignal: "SIGKILL" });
  assert.equal(result.status, 0, `persistent-compiler: ${String(result.error ?? result.stderr)}`);
  assert.equal(result.stderr, "", "persistent-compiler: unexpected compiler stderr");
  return result.stdout.trim();
}
assert.equal(compiler(["--version"]), "0.34.0");
assert.equal(compiler(["--language-version"]), "0.26.0");
assert.equal(compiler(["--runtime-version"]), "0.19.0");
const modules = resolve(runtimeDirectory, "node_modules");
for (const [name, version] of Object.entries({
  "@midnight-ntwrk/compact-runtime": "0.19.0", "@midnightntwrk/onchain-runtime-v4": "4.0.0-rc.3",
  "@noble/curves": "2.3.0", "@noble/hashes": "2.3.0", "@types/object-inspect": "1.13.0", "object-inspect": "1.13.4",
})) assert.equal(JSON.parse(readFileSync(resolve(modules, name, "package.json"), "utf8")).version, version, name);
// Versions/lock identity are recorded provenance, not installed-byte attestation.
const runtime = await import(pathToFileURL(resolve(modules, "@midnight-ntwrk/compact-runtime/dist/index.js")).href);
assert.equal(runtime.versionString, "0.19.0");
const directory = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-runtime-"));
try {
  writeFileSync(resolve(directory, "package.json"), '{"private":true,"type":"module"}\n');
  symlinkSync(modules, resolve(directory, "node_modules"), process.platform === "win32" ? "junction" : "dir");
  const compiled = resolve(directory, "compiled");
  compiler(["--skip-zk", source, compiled]);
  const compiledPath = resolve(compiled, "contract/index.js");
  const contractModule = await import(pathToFileURL(compiledPath).href);
  type Private = Readonly<{ next: bigint }>;
  const witnesses: bigint[] = [];
  const contract = new contractModule.Contract({ next: ({ privateState }: { privateState: Private }) => {
    assert.ok(Object.isFrozen(privateState), "Witness requires an immutable private snapshot");
    assert.equal(typeof privateState.next, "bigint");
    witnesses.push(privateState.next);
    return [Object.freeze({ next: privateState.next + 1n }), privateState.next];
  } });
  const initialized = await contract.initialState(runtime.createConstructorContext(Object.freeze({ next: 7n }), "0".repeat(64)));
  // Runtime types are external optional qualification inputs. Containers are
  // represented with the actual release object, never analyzer state objects.
  interface Snapshot { container: any; privateState: Private; serialized: Uint8Array; text: string; count: bigint; next: bigint; digest: string }
  const retained: Snapshot[] = [];
  const retain = (container: any, privateState: Private): Snapshot => {
    assert.ok(Object.isFrozen(privateState));
    assert.deepEqual(Object.keys(privateState), ["next"]);
    assert.equal(typeof privateState.next, "bigint");
    const serialized = Uint8Array.from(container.serialize());
    const copy = runtime.ContractState.deserialize(serialized.slice());
    assert.equal(copy.data.toString(), container.data.toString(), "Public container roundtrip mismatch");
    const count: unknown = contractModule.ledger(copy.data).count;
    assert.equal(typeof count, "bigint");
    const snapshot: Snapshot = { container: copy, privateState: Object.freeze({ next: privateState.next }), serialized, text: copy.data.toString(), count: count as bigint, next: privateState.next, digest: persistentDigest(serialized) };
    retained.push(snapshot);
    return snapshot;
  };
  const validateRetained = () => {
    for (const snapshot of retained) {
      assert.equal(snapshot.container.data.toString(), snapshot.text, "Retained public snapshot changed");
      assert.equal(contractModule.ledger(snapshot.container.data).count, snapshot.count);
      assert.deepEqual(Uint8Array.from(snapshot.container.serialize()), snapshot.serialized, "Retained serialized container changed");
      assert.equal(persistentDigest(snapshot.serialized), snapshot.digest, "Retained bytes changed");
      assert.ok(Object.isFrozen(snapshot.privateState));
      assert.equal(snapshot.privateState.next, snapshot.next, "Retained private snapshot changed");
    }
  };
  const view = (snapshot: Snapshot): PersistentSnapshot => ({ count: String(contractModule.ledger(snapshot.container.data).count), next: String(snapshot.privateState.next), publicSha256: persistentDigest(snapshot.container.serialize()) });
  const copy = (snapshot: Snapshot): Snapshot => retain(runtime.ContractState.deserialize(snapshot.serialized.slice()), Object.freeze({ next: snapshot.privateState.next }));
  let current = retain(initialized.currentContractState, initialized.currentPrivateState);
  const initial = view(current);
  const slots = Array.from({ length: 4 }, () => copy(current));
  const rows: PersistentRow[] = [];
  const contexts = new Set<unknown>();
  const fixedTime = 1700000000;
  for (const [index, operation] of sequence.operations.entries()) {
    const before = view(current);
    const witnessStart = witnesses.length;
    let result: string | null = null;
    let outcome: PersistentRow["outcome"] = "evaluation-success";
    let error: PersistentRow["error"] = null;
    if (operation.kind === "save") { slots[operation.slot] = copy(current); outcome = "saved"; }
    else if (operation.kind === "restore") { current = copy(slots[operation.slot]); outcome = "restored"; }
    else {
      const input = current;
      const context = runtime.createCircuitContext(operation.kind, runtime.dummyContractAddress(), "0".repeat(64), input.container.data, input.privateState, undefined, undefined, undefined, fixedTime);
      assert.ok(!contexts.has(context), "Circuit context was reused");
      contexts.add(context);
      let evaluated: any;
      try { evaluated = await contract.circuits[operation.kind](context); }
      catch (caught) {
        // A rejected call is recognized only by the exact qualified runtime
        // class/name/message. Harness assertions and other exceptions escape.
        if (operation.kind !== "reject" || !(caught instanceof runtime.CompactError) || !(caught instanceof Error) || caught.name !== "CompactError" || caught.message !== PERSISTENT_REJECTION) throw caught;
        outcome = "evaluation-rejection";
        error = { name: "CompactError", message: caught.message };
      }
      assert.equal(context.callContext.currentQueryContext.state.toString(), input.text, "Call mutated its input public state");
      assert.equal(context.callContext.currentPrivateState, input.privateState, "Call replaced its input private snapshot");
      if (evaluated !== undefined) {
        assert.equal(evaluated.context.callProofDataTrace.length, 1);
        const transcript = evaluated.context.callProofDataTrace[0];
        assert.equal(transcript.circuitId, operation.kind);
        assert.equal(transcript.privateTranscriptOutputs.length, operation.kind === "inspect" ? 0 : 1);
        assert.equal(evaluated.context.events.length, 0);
        // A successful reject is a measured property violation, not an expected
        // rejection. Its empty return remains distinguishable in the wire.
        if (Array.isArray(evaluated.result) && evaluated.result.length === 0) result = null;
        else { assert.equal(typeof evaluated.result, "bigint"); result = String(evaluated.result); }
        const acceptedContainer = runtime.ContractState.deserialize(input.serialized.slice());
        acceptedContainer.data = evaluated.context.callContext.currentQueryContext.state;
        current = retain(acceptedContainer, evaluated.context.callContext.currentPrivateState);
      }
    }
    validateRetained();
    rows.push({ index, operation: operation.kind, slot: "slot" in operation ? operation.slot : null, outcome, result, witnesses: witnesses.slice(witnessStart).map(String), error, before, after: view(current), slots: slots.map(view) });
  }
  validateRetained();
  const observation: PersistentObservation = { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime,
    runtimeLockSha256, sourceSha256: persistentDigest(readFileSync(source)), compiledJavaScriptSha256: persistentDigest(readFileSync(compiledPath)), sequenceSha256: persistentDigest(JSON.stringify(sequence)), initial, rows, final: view(current) };
  process.stdout.write(JSON.stringify(observation));
} finally { rmSync(directory, { recursive: true, force: true }); }
