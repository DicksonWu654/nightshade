// Fixed owned List adapter. No arbitrary source, initial state or executable adapter input.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PERSISTENT_LIST_LOCK_SHA256, PERSISTENT_LIST_MANIFEST_SHA256, PERSISTENT_LIST_OBSERVATION_LIMITS, PERSISTENT_LIST_REJECTION, PERSISTENT_LIST_SOURCE_SHA256, validatePersistentListSequence, type PersistentListMaybe, type PersistentListObservation, type PersistentListRow, type PersistentListSnapshot, type PersistentListValue } from "../generative/persistent-list-model.js";

const digest = (value: string | Uint8Array): string => createHash("sha256").update(value).digest("hex");
const fixedTime = 1700000000;
const serializationBytes = 65536;
const retainedLimit = 37;

class AdapterFailure extends Error {
  constructor(readonly diagnostic: string, message: string) { super(message); }
}
function protocol(condition: unknown, message: string): asserts condition {
  if (!condition) throw new AdapterFailure("persistent-list-protocol", message);
}
function budget(condition: unknown, message: string): asserts condition {
  if (!condition) throw new AdapterFailure("persistent-list-observation-budget", message);
}
function pinned(path: string, expected: string): void {
  try { if (digest(readFileSync(path)) === expected) return; }
  catch { /* Missing qualification inputs are identity failures too. */ }
  throw new AdapterFailure("persistent-list-input-identity", "Fixed fixture or runtime restoration input differs from its pin");
}
function decimal(value: unknown): string {
  protocol(typeof value === "bigint", "Expected a native bigint scalar");
  const text = String(value);
  budget(text.length <= PERSISTENT_LIST_OBSERVATION_LIMITS.maxScalarChars, "Measured scalar exceeds bounded decimal representation");
  return text;
}
function serialize(container: any): Uint8Array {
  const value: unknown = container.serialize();
  protocol(value instanceof Uint8Array, "Expected serialized public container bytes");
  budget(value.byteLength <= serializationBytes, "Serialized public container exceeds 64 KiB");
  return value.slice();
}

function dataRecord(value: unknown, fields: string[]): Record<string, unknown> {
  protocol(value && typeof value === "object" && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)), "Expected ordinary runtime data record");
  assert.deepEqual(Reflect.ownKeys(value).sort(), [...fields].sort(), "Unexpected runtime data fields");
  for (const field of fields) {
    const entry = Object.getOwnPropertyDescriptor(value, field)!;
    protocol("value" in entry && entry.enumerable, "Expected runtime data fields without accessors");
  }
  return value as Record<string, unknown>;
}
function maybe(value: unknown): PersistentListMaybe {
  const raw = dataRecord(value, ["is_some", "value"]);
  protocol(typeof raw.is_some === "boolean", "Expected typed Maybe presence");
  return { is_some: raw.is_some, value: decimal(raw.value) };
}
function callResult(value: unknown): PersistentListValue {
  protocol(Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype, "Expected typed circuit result tuple");
  protocol(Reflect.ownKeys(value).length === value.length + 1 && (value.length === 0 || value.length === 3), "Expected bounded empty or inspect result");
  if (!value.length) return [];
  protocol(typeof value[0] === "boolean", "Expected Boolean inspection result");
  return [value[0], decimal(value[1]), maybe(value[2])];
}
function count(value: unknown): number {
  protocol(Array.isArray(value), "Expected runtime transcript/event array");
  budget(value.length <= 64, "Runtime transcript/event count exceeds 64");
  return value.length;
}

async function main(): Promise<PersistentListObservation> {
  const chunks: Buffer[] = [];
  let inputBytes = 0;
  for await (const chunk of process.stdin) {
    const data = Buffer.from(chunk);
    if ((inputBytes += data.length) > 1048576) throw new AdapterFailure("worker-input-budget", "Request exceeds 1 MiB");
    chunks.push(data);
  }
  const request = dataRecord(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))), ["compiler", "runtimeDirectory", "sequence"]);
  // The only model function the worker imports is the pure bounded grammar validator.
  let sequence: ReturnType<typeof validatePersistentListSequence>;
  try { sequence = validatePersistentListSequence(request.sequence); }
  catch (error) {
    const code = error && typeof error === "object" ? Object.getOwnPropertyDescriptor(error, "code") : undefined;
    throw new AdapterFailure(code && "value" in code && code.value === "persistent-list-sequence-budget" ? "persistent-list-sequence-budget" : "persistent-list-protocol", "Invalid bounded persistent List sequence");
  }
  protocol(typeof request.compiler === "string" && request.compiler.length > 0 && typeof request.runtimeDirectory === "string" && request.runtimeDirectory.length > 0, "Expected compiler/runtime paths");
  const compilerPath = resolve(request.compiler), runtimeDirectory = resolve(request.runtimeDirectory);
  const fixtures = fileURLToPath(new URL("../../../tests/runtime-fixtures/", import.meta.url));
  const source = resolve(fixtures, "list-guarded.compact"), manifest = resolve(fixtures, "runtime-inputs.json"), repositoryLock = resolve(fixtures, "qualification-inputs/package-lock.json"), restoredLock = resolve(runtimeDirectory, "package-lock.json");
  const checkInputs = () => { pinned(source, PERSISTENT_LIST_SOURCE_SHA256); pinned(manifest, PERSISTENT_LIST_MANIFEST_SHA256); pinned(repositoryLock, PERSISTENT_LIST_LOCK_SHA256); pinned(restoredLock, PERSISTENT_LIST_LOCK_SHA256); };
  checkInputs();
  const compilerInputs = [compilerPath, ...["compactc.bin", "zkir", "zkir-v3"].map(name => resolve(dirname(compilerPath), name))];
  const readCompilerHashes = () => {
    try { return compilerInputs.map(path => digest(readFileSync(path))); }
    catch { throw new AdapterFailure("persistent-list-compiler", "Cannot read fixed compiler qualification inputs"); }
  };
  const compilerHashes = readCompilerHashes();
  function compiler(args: string[]): string {
    const result = spawnSync(compilerPath, args, { encoding: "utf8", timeout: 30000, maxBuffer: 1048576, killSignal: "SIGKILL" });
    if (result.status !== 0 || result.error || result.stderr) throw new AdapterFailure("persistent-list-compiler", `Fixed-source compiler qualification failed: ${result.error?.message ?? result.stderr ?? result.signal ?? result.status}`.slice(0, 4000));
    return result.stdout.trim();
  }
  for (const [flag, expected] of [["--version", "0.34.0"], ["--language-version", "0.26.0"], ["--runtime-version", "0.19.0"]]) {
    if (compiler([flag]) !== expected) throw new AdapterFailure("persistent-list-input-identity", "Compiler release/language/runtime pin mismatch");
  }
  const modules = resolve(runtimeDirectory, "node_modules");
  const runtimeVersions = { "@midnight-ntwrk/compact-runtime": "0.19.0", "@midnightntwrk/onchain-runtime-v4": "4.0.0-rc.3", "@noble/curves": "2.3.0", "@noble/hashes": "2.3.0", "@types/object-inspect": "1.13.0", "object-inspect": "1.13.4" };
  const checkVersions = () => {
    for (const [name, version] of Object.entries(runtimeVersions)) if (JSON.parse(readFileSync(resolve(modules, name, "package.json"), "utf8")).version !== version) throw new AdapterFailure("persistent-list-input-identity", "Installed runtime package version mismatch");
  };
  checkVersions();
  // These locks and versions are provenance checks, not installed-byte attestation.
  const runtime = await import(pathToFileURL(resolve(modules, "@midnight-ntwrk/compact-runtime/dist/index.js")).href);
  if (runtime.versionString !== "0.19.0") throw new AdapterFailure("persistent-list-input-identity", "Imported runtime version mismatch");
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-persistent-list-runtime-"));
  try {
    writeFileSync(resolve(directory, "package.json"), '{"private":true,"type":"module"}\n');
    symlinkSync(modules, resolve(directory, "node_modules"), process.platform === "win32" ? "junction" : "dir");
    const compiled = resolve(directory, "compiled"); compiler(["--skip-zk", source, compiled]);
    const compiledPath = resolve(compiled, "contract/index.js"), compiledJavaScriptSha256 = digest(readFileSync(compiledPath));
    const contractModule = await import(pathToFileURL(compiledPath).href), contract = new contractModule.Contract({});
    type Private = Readonly<{ next: bigint }>;
    interface Snapshot { container: any; serialized: Uint8Array; privateState: Private; observation: PersistentListSnapshot }
    const retained: Snapshot[] = [], contexts = new Set<unknown>();
    const privateState = (value: unknown): Private => {
      const raw = dataRecord(value, ["next"]); decimal(raw.next);
      return Object.freeze({ next: raw.next as bigint });
    };
    const readLedger = (state: any): Omit<PersistentListSnapshot, "next" | "publicSha256"> => {
      const ledger = contractModule.ledger(state).values;
      const empty: unknown = ledger.isEmpty(), length: unknown = ledger.length(), head: unknown = ledger.head();
      protocol(typeof empty === "boolean", "Expected Boolean List empty flag");
      const iterator = ledger[Symbol.iterator]();
      const values: string[] = [];
      try {
        while (true) {
          const step = iterator.next();
          protocol(step && typeof step === "object" && typeof step.done === "boolean", "Malformed List iterator result");
          if (step.done) break;
          budget(values.length < PERSISTENT_LIST_OBSERVATION_LIMITS.maxValues, "List iterator exceeds measured value bound");
          values.push(decimal(step.value));
        }
      } finally { if (typeof iterator.return === "function") iterator.return(); }
      return { values, length: decimal(length), empty, head: maybe(head) };
    };
    const retain = (container: any, suppliedPrivate: unknown): Snapshot => {
      budget(retained.length < retainedLimit, "Retained snapshot budget exhausted");
      const serialized = serialize(container), copy = runtime.ContractState.deserialize(serialized.slice());
      protocol(copy !== container && !retained.some(snapshot => snapshot.container === copy), "Deserialization reused an accepted public container");
      assert.deepEqual(serialize(copy), serialized, "Public container roundtrip changed serialized state");
      const frozen = privateState(suppliedPrivate);
      const snapshot = { container: copy, serialized, privateState: frozen, observation: { ...readLedger(copy.data), next: decimal(frozen.next), publicSha256: digest(serialized) } };
      retained.push(snapshot); return snapshot;
    };
    const copy = (snapshot: Snapshot) => retain(runtime.ContractState.deserialize(snapshot.serialized.slice()), snapshot.privateState);
    // Observation views are separately capped below. These immutability checks
    // make at most 37 retained reads per boundary, over at most 33 boundaries.
    const validateRetained = () => {
      for (const snapshot of retained) {
        assert.deepEqual(serialize(snapshot.container), snapshot.serialized, "Retained public container changed");
        assert.equal(digest(snapshot.serialized), snapshot.observation.publicSha256, "Retained serialized bytes changed");
        assert.deepEqual(readLedger(snapshot.container.data), (({ next: _next, publicSha256: _public, ...ledger }) => ledger)(snapshot.observation), "Retained ledger view changed");
        protocol(Object.isFrozen(snapshot.privateState), "Retained private snapshot is mutable");
        assert.equal(decimal(snapshot.privateState.next), snapshot.observation.next, "Retained private snapshot changed");
      }
    };
    let views = 0, totalValues = 0;
    const view = (snapshot: Snapshot): PersistentListSnapshot => {
      budget(++views <= PERSISTENT_LIST_OBSERVATION_LIMITS.maxViews, "Measured view count exceeds bound");
      budget((totalValues += snapshot.observation.values.length) <= PERSISTENT_LIST_OBSERVATION_LIMITS.maxTotalValues, "Measured total List values exceed bound");
      return structuredClone(snapshot.observation);
    };
    const initialized = await contract.initialState(runtime.createConstructorContext(Object.freeze({ next: 7n }), "0".repeat(64)));
    let current = retain(initialized.currentContractState, initialized.currentPrivateState);
    const initial = view(current), slots = Array.from({ length: 4 }, () => copy(current));
    const rows: PersistentListRow[] = [];
    for (const [index, operation] of sequence.operations.entries()) {
      const before = view(current);
      let outcome: PersistentListRow["outcome"] = "evaluation-success", result: PersistentListValue = null;
      let error: PersistentListRow["error"] = null, transcript: PersistentListRow["transcript"] = null;
      if (operation.kind === "save") { slots[operation.slot] = copy(current); outcome = "saved"; }
      else if (operation.kind === "restore") { current = copy(slots[operation.slot]); outcome = "restored"; }
      else {
        const accepted = current, inputBytes = serialize(accepted.container);
        const context = runtime.createCircuitContext(operation.kind, runtime.dummyContractAddress(), "0".repeat(64), accepted.container.data, accepted.privateState, undefined, undefined, undefined, fixedTime);
        protocol(!contexts.has(context), "Circuit context was reused"); contexts.add(context);
        let evaluated: any;
        try { evaluated = operation.kind === "push" ? await contract.circuits.push(context, BigInt(operation.value)) : await contract.circuits[operation.kind](context); }
        catch (caught) {
          // Classification is solely the actual fixed runtime class/name/message,
          // independent of predicted list length or the concrete oracle.
          if (operation.kind !== "guardedPop" || !(caught instanceof runtime.CompactError) || !(caught instanceof Error) || caught.name !== "CompactError" || caught.message !== PERSISTENT_LIST_REJECTION) throw new AdapterFailure("persistent-list-unqualified-rejection", "Unrecognized runtime exception from the fixed List circuit");
          outcome = "evaluation-rejection"; error = { name: "CompactError", message: caught.message };
        }
        assert.deepEqual(serialize(accepted.container), inputBytes, "Call mutated input public container");
        const inputContextContainer = runtime.ContractState.deserialize(accepted.serialized.slice());
        inputContextContainer.data = context.callContext.currentQueryContext.state;
        assert.deepEqual(serialize(inputContextContainer), inputBytes, "Call mutated input public context");
        assert.equal(context.callContext.currentPrivateState, accepted.privateState, "Call replaced its input private state");
        if (evaluated !== undefined) {
          result = callResult(evaluated.result);
          const traceCount = count(evaluated.context.callProofDataTrace);
          protocol(traceCount === 1, "Expected exactly one successful circuit transcript");
          const trace = evaluated.context.callProofDataTrace[0];
          protocol(typeof trace.circuitId === "string" && trace.circuitId.length > 0, "Expected circuit identity text");
          budget(trace.circuitId.length <= PERSISTENT_LIST_OBSERVATION_LIMITS.maxCircuitChars, "Measured circuit identity exceeds text bound");
          transcript = { circuit: trace.circuitId, privateOutputs: count(trace.privateTranscriptOutputs), events: count(evaluated.context.events) };
          const container = runtime.ContractState.deserialize(accepted.serialized.slice());
          container.data = evaluated.context.callContext.currentQueryContext.state;
          current = retain(container, evaluated.context.callContext.currentPrivateState);
        } else protocol(error !== null, "Missing circuit result and qualified rejection");
      }
      validateRetained();
      rows.push({ index, operation: { ...operation }, outcome, result, error, transcript, before, after: view(current), slots: slots.map(view) });
    }
    validateRetained(); checkInputs(); checkVersions();
    if (readCompilerHashes().some((hash, index) => hash !== compilerHashes[index])) throw new AdapterFailure("persistent-list-input-identity", "Compiler inputs changed during evaluation");
    if (digest(readFileSync(compiledPath)) !== compiledJavaScriptSha256) throw new AdapterFailure("persistent-list-input-identity", "Compiled JavaScript changed during evaluation");
    return { schemaVersion: "nightshade-persistent-list-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-guarded-list", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime,
      runtimeLockSha256: PERSISTENT_LIST_LOCK_SHA256, runtimeInputsManifestSha256: PERSISTENT_LIST_MANIFEST_SHA256, sourceSha256: PERSISTENT_LIST_SOURCE_SHA256, compiledJavaScriptSha256, sequenceSha256: digest(JSON.stringify(sequence)), initial, rows, final: view(current) };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

try {
  const observation = await main(), output = JSON.stringify(observation);
  budget(Buffer.byteLength(output) <= PERSISTENT_LIST_OBSERVATION_LIMITS.maxBytes, "Serialized measured observation exceeds 1 MiB");
  process.stdout.write(output);
} catch (error) {
  const diagnostic = error instanceof AdapterFailure ? error.diagnostic : "persistent-list-protocol";
  const message = error instanceof Error && error.message ? error.message.slice(0, 4000) : "Unreadable fixed List worker failure";
  process.stdout.write(JSON.stringify({ schemaVersion: "nightshade-persistent-list-worker-error-1", diagnostic, message }));
}
