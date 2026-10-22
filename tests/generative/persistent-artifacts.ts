import { closeSync, constants, fstatSync, openSync, readFileSync, readSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { executionLimits, runNodeModule, WorkerFailure, type ExecutionLimits } from "../../src/runtime/process.js";
import { buildIdentity, type BuildIdentity } from "./artifacts.js";
import { checkPersistentObservation, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, persistentDigest, validatePersistentSequence, type PersistentCheck, type PersistentSequence } from "./persistent-model.js";

export interface PersistentIdentity extends BuildIdentity {
  runtimeLockSha256: string;
  runtimeInputsManifestSha256: string;
  persistentWorkerSourceSha256: string;
  persistentWorkerBuildSha256: string;
  persistentFixtureSha256: string;
}
interface StreamRecord { bytes: number; sha256: string; prefix: string; truncated: boolean }
export type PersistentResult = PersistentCheck & { diagnosticResponse?: { stdout: StreamRecord; stderr: StreamRecord } };
export interface PersistentArtifact {
  schemaVersion: "nightshade-owned-persistent-case-1";
  purpose: "owned-fixture-persistent-correctness";
  identity: PersistentIdentity;
  limits: Required<ExecutionLimits>;
  sequence: PersistentSequence;
  result: PersistentResult;
}
export const PERSISTENT_FILE_BYTES = 1048576;
const incompleteDiagnostics = ["persistent-protocol", "persistent-sequence-budget", "persistent-observation-budget", "persistent-unqualified-rejection", "persistent-input-identity", "worker-input-budget", "worker-interrupted", "worker-timeout", "worker-output-budget", "worker-launch", "worker-failed", "worker-input"];
const identityKeys = ["analyzerSourceSha256", "harnessSourceSha256", "builtJavaScriptSha256", "parserRuntimeSha256", "compilerSha256", "compilerDistributionSha256", "semanticProfile", "node", "platform", "arch", "runtimeLockSha256", "runtimeInputsManifestSha256", "persistentWorkerSourceSha256", "persistentWorkerBuildSha256", "persistentFixtureSha256"];
const sha = (path: string) => persistentDigest(readFileSync(path));

function record(value: unknown, required: string[], optional: string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error(`Invalid ${label}`);
  if (required.some(key => !Object.hasOwn(value, key)) || Reflect.ownKeys(value).some(key => typeof key !== "string" || ![...required, ...optional].includes(key))) throw new Error(`Invalid ${label} fields`);
  for (const key of Reflect.ownKeys(value)) {
    const entry = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in entry) || !entry.enumerable) throw new Error(`Invalid ${label} accessor/hidden field`);
  }
  return value as Record<string, unknown>;
}

// Expected is a newly derived bounded tree, so untrusted extra data is not walked.
function equalData(actual: unknown, expected: unknown): boolean {
  if (!expected || typeof expected !== "object") return Object.is(actual, expected);
  if (!actual || typeof actual !== "object" || Array.isArray(actual) !== Array.isArray(expected)) return false;
  if (Array.isArray(actual) ? Object.getPrototypeOf(actual) !== Array.prototype : ![Object.prototype, null].includes(Object.getPrototypeOf(actual))) return false;
  const keys = Reflect.ownKeys(expected);
  if (Reflect.ownKeys(actual).length !== keys.length) return false;
  return keys.every(key => {
    const entry = Object.getOwnPropertyDescriptor(actual, key);
    const wanted = Object.getOwnPropertyDescriptor(expected, key)!;
    return entry && "value" in entry && entry.enumerable === wanted.enumerable && equalData(entry.value, wanted.value);
  });
}

export function validatePersistentLimits(value: unknown): Required<ExecutionLimits> {
  const raw = record(value, ["timeoutMs", "heapMiB", "maxOutputBytes"], [], "persistent limits");
  const limits = executionLimits(raw);
  for (const key of Object.keys(PERSISTENT_LIMITS) as (keyof typeof limits)[]) if (limits[key] > PERSISTENT_LIMITS[key]) throw new Error(`Persistent ${key} exceeds owned replay bound`);
  return limits;
}

/** Fixed schema-1 source expectation is independent of any artifact claims. */
export function persistentBuildIdentity(compiler: string, runtimeDirectory: string): PersistentIdentity {
  const persistentFixtureSha256 = sha("tests/runtime-fixtures/persistent.compact");
  const runtimeLockSha256 = sha(resolve(runtimeDirectory, "package-lock.json"));
  const manifest = JSON.parse(readFileSync("tests/runtime-fixtures/runtime-inputs.json", "utf8"));
  if (persistentFixtureSha256 !== PERSISTENT_SOURCE_SHA256 || runtimeLockSha256 !== PERSISTENT_LOCK_SHA256 || manifest.restoration.packageLockSha256 !== PERSISTENT_LOCK_SHA256) throw new Error("Persistent fixed fixture/runtime identity mismatch");
  return { ...buildIdentity(compiler), runtimeLockSha256, persistentFixtureSha256,
    runtimeInputsManifestSha256: sha("tests/runtime-fixtures/runtime-inputs.json"),
    persistentWorkerSourceSha256: sha("tests/runtime-fixtures/persistent-worker.ts"),
    persistentWorkerBuildSha256: sha("dist/tests/runtime-fixtures/persistent-worker.js") };
}

/** Open once and cap every read; a changed file cannot cause unbounded allocation. */
export function readPersistentFile(path: string): Buffer {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile()) throw new Error("Persistent input must be a regular file");
    if (stat.size > PERSISTENT_FILE_BYTES) throw new Error("Persistent input exceeds 1 MiB");
    const data = Buffer.alloc(PERSISTENT_FILE_BYTES + 1);
    let size = 0;
    while (size < data.length) {
      const count = readSync(descriptor, data, size, data.length - size, null);
      if (!count) break;
      size += count;
    }
    if (size > PERSISTENT_FILE_BYTES) throw new Error("Persistent input exceeds 1 MiB");
    return data.subarray(0, size);
  } finally { closeSync(descriptor); }
}

export function incompletePersistentResult(diagnostic: string, message: string): PersistentResult {
  if (!incompleteDiagnostics.includes(diagnostic)) diagnostic = "persistent-protocol";
  return { status: "incomplete", diagnostic, signature: diagnostic, message: message.slice(0, 4000) || "Incomplete persistent evidence" };
}

function streamRecord(value: string): StreamRecord {
  return { bytes: Buffer.byteLength(value), sha256: persistentDigest(value), prefix: value.slice(0, 4096), truncated: value.length > 4096 };
}

/** The supervisor supplies decoded text; these hashes describe its UTF-8 encoding. */
export function checkPersistentResponse(input: PersistentSequence, stdout: string, stderr: string): PersistentResult {
  let result: PersistentResult;
  if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > PERSISTENT_LIMITS.maxOutputBytes) result = incompletePersistentResult("worker-output-budget", "Persistent response exceeds owned output bound");
  else if (stderr) result = incompletePersistentResult("persistent-protocol", "Unexpected persistent worker stderr");
  else {
    try { result = checkPersistentObservation(input, JSON.parse(stdout), PERSISTENT_SOURCE_SHA256); }
    catch (error) { result = incompletePersistentResult("persistent-protocol", error instanceof Error ? error.message : String(error)); }
  }
  if (result.status === "incomplete") {
    result = incompletePersistentResult(result.diagnostic, result.message);
    result.diagnosticResponse = { stdout: streamRecord(stdout), stderr: streamRecord(stderr) };
  }
  return result;
}

function validateStream(value: unknown): StreamRecord {
  const raw = record(value, ["bytes", "sha256", "prefix", "truncated"], [], "diagnostic stream");
  if (typeof raw.bytes !== "number" || !Number.isSafeInteger(raw.bytes) || raw.bytes < 0 || Object.is(raw.bytes, -0)
    || typeof raw.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(raw.sha256) || typeof raw.prefix !== "string" || raw.prefix.length > 4096 || typeof raw.truncated !== "boolean") throw new Error("Invalid diagnostic stream values");
  if (!raw.truncated && (raw.bytes !== Buffer.byteLength(raw.prefix) || raw.sha256 !== persistentDigest(raw.prefix))) throw new Error("Invalid complete diagnostic stream identity");
  if (raw.truncated && (raw.prefix.length !== 4096 || raw.bytes <= Buffer.byteLength(raw.prefix))) throw new Error("Invalid truncated diagnostic stream");
  return { bytes: raw.bytes, sha256: raw.sha256, prefix: raw.prefix, truncated: raw.truncated };
}

/** Stored successful/failed status and signature are always rederived. */
export function validatePersistentResult(input: PersistentSequence, value: unknown): PersistentResult {
  const model = validatePersistentSequence(input);
  const raw = record(value, ["status", "diagnostic", "signature"], ["message", "observation", "diagnosticResponse"], "persistent result");
  if (raw.status === "incomplete") {
    if (typeof raw.diagnostic !== "string" || !incompleteDiagnostics.includes(raw.diagnostic) || raw.signature !== raw.diagnostic || typeof raw.message !== "string" || !raw.message || raw.message.length > 4000 || Object.hasOwn(raw, "observation")) throw new Error("Invalid incomplete persistent result");
    const result = incompletePersistentResult(raw.diagnostic, raw.message);
    if (Object.hasOwn(raw, "diagnosticResponse")) {
      const response = record(raw.diagnosticResponse, ["stdout", "stderr"], [], "diagnostic response");
      result.diagnosticResponse = { stdout: validateStream(response.stdout), stderr: validateStream(response.stderr) };
    }
    return result;
  }
  if (raw.status !== "passed" && raw.status !== "failed" || Object.hasOwn(raw, "diagnosticResponse")) throw new Error("Invalid persistent result status/evidence");
  const checked = checkPersistentObservation(model, raw.observation, PERSISTENT_SOURCE_SHA256);
  if (checked.status === "incomplete" || !equalData(raw, checked)) throw new Error("Persistent result qualification/signature mismatch");
  return checked;
}

export async function runPersistentSequenceIsolated(input: PersistentSequence, compiler: string, runtimeDirectory: string, limits: Required<ExecutionLimits> = PERSISTENT_LIMITS, signal?: AbortSignal): Promise<PersistentResult> {
  const model = validatePersistentSequence(input);
  const bounded = validatePersistentLimits(limits);
  try {
    if (signal?.aborted) return incompletePersistentResult("worker-interrupted", "Persistent sequence evaluation was interrupted before launch");
    if (sha("tests/runtime-fixtures/persistent.compact") !== PERSISTENT_SOURCE_SHA256) return incompletePersistentResult("persistent-input-identity", "Fixed persistent fixture digest mismatch");
    const output = await runNodeModule(fileURLToPath(new URL("../runtime-fixtures/persistent-worker.js", import.meta.url)), { sequence: model, compiler, runtimeDirectory }, bounded, signal);
    return checkPersistentResponse(model, output.stdout, output.stderr);
  } catch (error) {
    return incompletePersistentResult(error instanceof WorkerFailure ? error.code : "persistent-protocol", error instanceof Error ? error.message : String(error));
  }
}

export function makePersistentArtifact(sequence: PersistentSequence, identity: PersistentIdentity, limits: Required<ExecutionLimits>, result: PersistentResult): PersistentArtifact {
  return validatePersistentArtifact({ schemaVersion: "nightshade-owned-persistent-case-1", purpose: "owned-fixture-persistent-correctness", identity, limits, sequence, result });
}

/** Strict detached identity validation shared by saved artifacts and corpus admission. */
export function validatePersistentIdentity(value: unknown): PersistentIdentity {
  const identity = record(value, identityKeys, [], "persistent identity");
  for (const [key, entry] of Object.entries(identity)) if (typeof entry !== "string" || !entry || entry.length > 256 || key.endsWith("Sha256") && !/^[a-f0-9]{64}$/.test(entry)) throw new Error(`Invalid persistent identity ${key}`);
  if (identity.semanticProfile !== "compact-0.34.0-zkir2" || !/^v\d+\.\d+\.\d+$/.test(identity.node as string)) throw new Error("Invalid persistent profile/Node identity");
  if (identity.persistentFixtureSha256 !== PERSISTENT_SOURCE_SHA256 || identity.runtimeLockSha256 !== PERSISTENT_LOCK_SHA256) throw new Error("Unqualified persistent fixed fixture/runtime identity");
  return { ...identity } as unknown as PersistentIdentity;
}

export function validatePersistentArtifact(value: unknown): PersistentArtifact {
  const raw = record(value, ["schemaVersion", "purpose", "identity", "limits", "sequence", "result"], [], "persistent artifact");
  if (raw.schemaVersion !== "nightshade-owned-persistent-case-1" || raw.purpose !== "owned-fixture-persistent-correctness") throw new Error("Unsupported persistent artifact schema/purpose");
  const sequence = validatePersistentSequence(raw.sequence);
  const identity = validatePersistentIdentity(raw.identity);
  return { schemaVersion: "nightshade-owned-persistent-case-1", purpose: "owned-fixture-persistent-correctness", identity,
    limits: validatePersistentLimits(raw.limits), sequence, result: validatePersistentResult(sequence, raw.result) };
}

export function persistentIdentityChanges(before: PersistentIdentity, after: PersistentIdentity): string[] {
  return identityKeys.filter(key => before[key as keyof PersistentIdentity] !== after[key as keyof PersistentIdentity]);
}

export function comparePersistentResults(before: PersistentResult, after: PersistentResult) {
  const observationHash = (result: PersistentResult) => result.status === "incomplete" ? undefined : persistentDigest(JSON.stringify({ initial: result.observation.initial, rows: result.observation.rows, final: result.observation.final }));
  const beforeHash = observationHash(before), afterHash = observationHash(after);
  return { sameStatus: before.status === after.status, sameSignature: before.signature === after.signature,
    sameObservation: beforeHash && afterHash ? beforeHash === afterHash : null,
    sameCompiledJavaScript: before.status !== "incomplete" && after.status !== "incomplete" ? before.observation.compiledJavaScriptSha256 === after.observation.compiledJavaScriptSha256 : null,
    previousObservationSha256: beforeHash, currentObservationSha256: afterHash };
}
