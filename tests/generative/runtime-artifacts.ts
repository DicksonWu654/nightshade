import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { executionLimits, runNodeModule, WorkerFailure, type ExecutionLimits } from "../../src/runtime/process.js";
import { buildIdentity, digest, type BuildIdentity } from "./artifacts.js";
import { renderCase, validateCase, type GeneratedCase } from "./model.js";
import { runtimeFeedback, RuntimeModelMismatch, validateRuntimeObservation, type RuntimeFeedback, type RuntimeObservation } from "./runtime-feedback.js";

export interface RuntimeIdentity extends BuildIdentity {
  runtimeLockSha256: string;
  runtimeInputsManifestSha256: string;
  runtimeAdapterSourceSha256: string;
  runtimeAdapterBuildSha256: string;
}
interface StreamRecord { bytes: number; sha256: string; prefix: string; truncated: boolean }
export interface RuntimeCheckResult {
  status: "passed" | "failed" | "incomplete";
  category: string;
  signature: string;
  message?: string;
  observation?: RuntimeObservation;
  feedback?: RuntimeFeedback;
  diagnosticResponse?: { stdout: StreamRecord; stderr: StreamRecord };
}
export interface RuntimeCaseArtifact {
  schemaVersion: "nightshade-owned-runtime-case-2";
  purpose: "owned-fixture-runtime-correctness";
  identity: RuntimeIdentity;
  limits: Required<ExecutionLimits>;
  case: GeneratedCase;
  source: string;
  sourceSha256: string;
  result: RuntimeCheckResult;
}
export const RUNTIME_LIMITS = Object.freeze({ timeoutMs: 60000, heapMiB: 256, maxOutputBytes: 1048576 });
const incompleteCategories = ["runtime-protocol", "worker-input-budget", "worker-interrupted", "worker-timeout", "worker-output-budget", "worker-launch", "worker-failed", "worker-input"];
const identityKeys = ["analyzerSourceSha256", "harnessSourceSha256", "builtJavaScriptSha256", "parserRuntimeSha256", "compilerSha256", "compilerDistributionSha256", "semanticProfile", "node", "platform", "arch", "runtimeLockSha256", "runtimeInputsManifestSha256", "runtimeAdapterSourceSha256", "runtimeAdapterBuildSha256"];
const sha = (path: string) => digest(readFileSync(path));

function record(value: unknown, required: string[], optional: string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error(`Invalid ${label}`);
  if (required.some(key => !Object.hasOwn(value, key)) || Reflect.ownKeys(value).some(key => typeof key !== "string" || ![...required, ...optional].includes(key))) throw new Error(`Invalid ${label} fields`);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor) || !descriptor.enumerable) throw new Error(`Invalid ${label} accessor/hidden field`);
  }
  return value as Record<string, unknown>;
}

// Compare against a bounded, freshly derived tree without invoking accessors or
// traversing attacker-supplied extra structure. JSON key order is immaterial.
function equalData(actual: unknown, expected: unknown): boolean {
  if (!expected || typeof expected !== "object") return Object.is(actual, expected);
  if (!actual || typeof actual !== "object" || Array.isArray(actual) !== Array.isArray(expected)) return false;
  if (Array.isArray(actual) ? Object.getPrototypeOf(actual) !== Array.prototype : ![Object.prototype, null].includes(Object.getPrototypeOf(actual))) return false;
  const keys = Reflect.ownKeys(expected);
  if (Reflect.ownKeys(actual).length !== keys.length) return false;
  return keys.every(key => {
    const entry = Object.getOwnPropertyDescriptor(actual, key);
    return entry && "value" in entry && equalData(entry.value, (expected as Record<PropertyKey, unknown>)[key]);
  });
}

export function validateRuntimeLimits(value: unknown): Required<ExecutionLimits> {
  const raw = record(value, ["timeoutMs", "heapMiB", "maxOutputBytes"], [], "runtime limits");
  const limits = executionLimits(raw);
  for (const key of Object.keys(RUNTIME_LIMITS) as (keyof typeof limits)[]) if (limits[key] > RUNTIME_LIMITS[key]) throw new Error(`Runtime ${key} exceeds owned campaign bound`);
  return limits;
}

/** Run from repository root. Hashes record inputs, not installed-byte attestation. */
export function runtimeBuildIdentity(compiler: string, runtimeDirectory: string): RuntimeIdentity {
  const manifest = JSON.parse(readFileSync("tests/runtime-fixtures/runtime-inputs.json", "utf8"));
  const runtimeLockSha256 = sha(resolve(runtimeDirectory, "package-lock.json"));
  if (runtimeLockSha256 !== manifest.restoration.packageLockSha256) throw new Error("Runtime restoration lock identity mismatch");
  return { ...buildIdentity(compiler), runtimeLockSha256,
    runtimeInputsManifestSha256: sha("tests/runtime-fixtures/runtime-inputs.json"),
    runtimeAdapterSourceSha256: sha("tests/runtime-fixtures/generated-worker.ts"),
    runtimeAdapterBuildSha256: sha("dist/tests/runtime-fixtures/generated-worker.js") };
}

export function incompleteRuntimeResult(category: string, message: string): RuntimeCheckResult {
  if (!incompleteCategories.includes(category)) category = "runtime-protocol";
  return { status: "incomplete", category, signature: category, message: message.slice(0, 4000) };
}

/** A complete measured return can fail a layout, scalar-kind or value property. */
export function checkRuntimeObservation(input: GeneratedCase, value: unknown): RuntimeCheckResult {
  let observation: RuntimeObservation;
  try { observation = validateRuntimeObservation(input, value); }
  catch (error) { return incompleteRuntimeResult("runtime-protocol", error instanceof Error ? error.message : String(error)); }
  try {
    const feedback = runtimeFeedback(input, observation);
    return { status: "passed", category: "runtime-model-checked", signature: "runtime-model-checked", observation, feedback };
  } catch (error) {
    if (error instanceof RuntimeModelMismatch) return { status: "failed", category: "runtime-model-disagreement", signature: error.signature, message: error.message, observation };
    return incompleteRuntimeResult("runtime-protocol", error instanceof Error ? error.message : String(error));
  }
}

function streamRecord(value: string): StreamRecord {
  // UTF-16 prefix length is bounded separately from actual UTF-8 byte count.
  return { bytes: Buffer.byteLength(value), sha256: digest(value), prefix: value.slice(0, 4096), truncated: value.length > 4096 };
}

/** Keep bounded protocol evidence without ever treating stderr as clean output. */
export function checkRuntimeResponse(input: GeneratedCase, stdout: string, stderr: string): RuntimeCheckResult {
  let result: RuntimeCheckResult;
  if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > RUNTIME_LIMITS.maxOutputBytes) result = incompleteRuntimeResult("worker-output-budget", "Runtime response exceeds owned campaign output bound");
  else if (stderr) result = incompleteRuntimeResult("runtime-protocol", "Unexpected runtime worker stderr");
  else {
    try { result = checkRuntimeObservation(input, JSON.parse(stdout)); }
    catch (error) { result = incompleteRuntimeResult("runtime-protocol", error instanceof Error ? error.message : String(error)); }
  }
  if (result.status === "incomplete") result.diagnosticResponse = { stdout: streamRecord(stdout), stderr: streamRecord(stderr) };
  return result;
}

function validateStream(value: unknown): StreamRecord {
  const raw = record(value, ["bytes", "sha256", "prefix", "truncated"], [], "diagnostic stream");
  if (typeof raw.bytes !== "number" || !Number.isSafeInteger(raw.bytes) || raw.bytes < 0 || Object.is(raw.bytes, -0)
    || typeof raw.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(raw.sha256) || typeof raw.prefix !== "string" || raw.prefix.length > 4096 || typeof raw.truncated !== "boolean") throw new Error("Invalid diagnostic stream values");
  if (!raw.truncated && (raw.bytes !== Buffer.byteLength(raw.prefix) || raw.sha256 !== digest(raw.prefix))) throw new Error("Invalid complete diagnostic stream identity");
  if (raw.truncated && (raw.prefix.length !== 4096 || raw.bytes <= Buffer.byteLength(raw.prefix))) throw new Error("Invalid truncated diagnostic stream");
  return { bytes: raw.bytes, sha256: raw.sha256, prefix: raw.prefix, truncated: raw.truncated };
}

/** Recompute qualification and failure signatures, rather than trusting labels. */
export function validateRuntimeResult(input: GeneratedCase, value: unknown): RuntimeCheckResult {
  const raw = record(value, ["status", "category", "signature"], ["message", "observation", "feedback", "diagnosticResponse"], "runtime result");
  if (raw.status === "incomplete") {
    if (typeof raw.category !== "string" || !incompleteCategories.includes(raw.category) || raw.signature !== raw.category || typeof raw.message !== "string" || !raw.message || raw.message.length > 4000 || Object.hasOwn(raw, "observation") || Object.hasOwn(raw, "feedback")) throw new Error("Invalid incomplete runtime result");
    const result = incompleteRuntimeResult(raw.category, raw.message);
    if (Object.hasOwn(raw, "diagnosticResponse")) {
      const response = record(raw.diagnosticResponse, ["stdout", "stderr"], [], "diagnostic response");
      result.diagnosticResponse = { stdout: validateStream(response.stdout), stderr: validateStream(response.stderr) };
    }
    return result;
  }
  if (raw.status !== "passed" && raw.status !== "failed" || Object.hasOwn(raw, "diagnosticResponse")) throw new Error("Invalid runtime result status/evidence");
  const checked = checkRuntimeObservation(input, raw.observation);
  // Copying through the qualified decoder detaches all nested observations.
  if (checked.status === "incomplete" || !equalData(raw, checked)) throw new Error("Runtime result qualification/signature mismatch");
  return checked;
}

export async function runRuntimeCaseIsolated(input: GeneratedCase, compiler: string, runtimeDirectory: string, limits: Required<ExecutionLimits> = RUNTIME_LIMITS): Promise<RuntimeCheckResult> {
  const model = validateCase(input);
  validateRuntimeLimits(limits);
  try {
    const output = await runNodeModule(fileURLToPath(new URL("../runtime-fixtures/generated-worker.js", import.meta.url)), { case: model, compiler, runtimeDirectory }, limits);
    return checkRuntimeResponse(model, output.stdout, output.stderr);
  } catch (error) {
    return incompleteRuntimeResult(error instanceof WorkerFailure ? error.code : "runtime-protocol", error instanceof Error ? error.message : String(error));
  }
}

export function makeRuntimeArtifact(input: GeneratedCase, identity: RuntimeIdentity, limits: Required<ExecutionLimits>, result: RuntimeCheckResult): RuntimeCaseArtifact {
  const model = validateCase(input);
  const source = renderCase(model);
  return validateRuntimeArtifact({ schemaVersion: "nightshade-owned-runtime-case-2", purpose: "owned-fixture-runtime-correctness", identity, limits, case: model, source, sourceSha256: digest(source), result });
}

/** Stored source is checked against the bounded model and is never executed. */
export function validateRuntimeArtifact(value: unknown): RuntimeCaseArtifact {
  const raw = record(value, ["schemaVersion", "purpose", "identity", "limits", "case", "source", "sourceSha256", "result"], [], "runtime artifact");
  if (raw.schemaVersion !== "nightshade-owned-runtime-case-2" || raw.purpose !== "owned-fixture-runtime-correctness") throw new Error("Unsupported runtime artifact schema/purpose; historical schema 1 is not replayable by schema 2");
  const model = validateCase(raw.case);
  const source = renderCase(model);
  if (raw.source !== source || raw.sourceSha256 !== digest(source)) throw new Error("Runtime artifact source/model integrity mismatch");
  const identity = record(raw.identity, identityKeys, [], "runtime identity");
  for (const [key, entry] of Object.entries(identity)) if (typeof entry !== "string" || !entry || entry.length > 256 || key.endsWith("Sha256") && !/^[a-f0-9]{64}$/.test(entry)) throw new Error(`Invalid runtime identity ${key}`);
  if (identity.semanticProfile !== "compact-0.34.0-zkir2" || !/^v\d+\.\d+\.\d+$/.test(identity.node as string)) throw new Error("Invalid runtime profile/Node identity");
  return { schemaVersion: "nightshade-owned-runtime-case-2", purpose: "owned-fixture-runtime-correctness", identity: { ...identity } as unknown as RuntimeIdentity,
    limits: validateRuntimeLimits(raw.limits), case: model, source, sourceSha256: digest(source), result: validateRuntimeResult(model, raw.result) };
}

export function runtimeIdentityChanges(before: RuntimeIdentity, after: RuntimeIdentity): string[] {
  return identityKeys.filter(key => before[key as keyof RuntimeIdentity] !== after[key as keyof RuntimeIdentity]);
}

export function compareRuntimeResults(before: RuntimeCheckResult, after: RuntimeCheckResult) {
  const observationHash = (result: RuntimeCheckResult) => result.observation ? digest(JSON.stringify(result.observation.executions)) : undefined;
  const beforeHash = observationHash(before), afterHash = observationHash(after);
  return { sameStatus: before.status === after.status, sameSignature: before.signature === after.signature,
    sameObservation: beforeHash && afterHash ? beforeHash === afterHash : null,
    sameCompiledJavaScript: before.observation && after.observation ? before.observation.compiledJavaScriptSha256 === after.observation.compiledJavaScriptSha256 : null,
    previousObservationSha256: beforeHash, currentObservationSha256: afterHash };
}
