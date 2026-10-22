/** Fixed owned List worker transport and observation qualification; no arbitrary source/state API. */
import { fileURLToPath } from "node:url";
import { executionLimits, runNodeModule, WorkerFailure, type ExecutionLimits } from "../../src/runtime/process.js";
import { checkPersistentListObservation, incompletePersistentListResult, PERSISTENT_LIST_INCOMPLETE_DIAGNOSTICS, PERSISTENT_LIST_LIMITS, validatePersistentListSequence, type PersistentListResult, type PersistentListSequence } from "./persistent-list-model.js";

function dataRecord(value: unknown, fields: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error("Expected ordinary List runtime data record");
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || keys.some(key => typeof key !== "string" || !fields.includes(key))) throw new Error("Unexpected List runtime fields");
  for (const key of fields) { const descriptor = Object.getOwnPropertyDescriptor(value, key)!; if (!("value" in descriptor) || !descriptor.enumerable) throw new Error("Expected enumerable runtime data fields"); }
  return value as Record<string, unknown>;
}

export function validatePersistentListLimits(value: unknown = PERSISTENT_LIST_LIMITS): Required<ExecutionLimits> {
  const raw = dataRecord(value, ["timeoutMs", "heapMiB", "maxOutputBytes"]);
  const limits = executionLimits(raw);
  for (const key of Object.keys(PERSISTENT_LIST_LIMITS) as (keyof typeof limits)[]) if (limits[key] > PERSISTENT_LIST_LIMITS[key] || Object.is(limits[key], -0)) throw new Error(`Persistent List ${key} exceeds fixed replay bound`);
  return limits;
}

/** Worker errors have their own closed transport schema; they are never observations. */
export function checkPersistentListResponse(sequence: PersistentListSequence, stdout: string, stderr: string): PersistentListResult {
  let input: PersistentListSequence;
  try { input = validatePersistentListSequence(sequence); }
  catch { return checkPersistentListObservation(sequence, null); }
  if (typeof stdout !== "string" || typeof stderr !== "string") return incompletePersistentListResult("persistent-list-protocol", "Expected worker text response");
  if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > PERSISTENT_LIST_LIMITS.maxOutputBytes) return incompletePersistentListResult("worker-output-budget", "Persistent List response exceeds 1 MiB");
  if (stderr) return incompletePersistentListResult("persistent-list-protocol", "Unexpected List worker stderr");
  let response: unknown;
  try { response = JSON.parse(stdout); }
  catch { return incompletePersistentListResult("persistent-list-protocol", "Invalid List worker JSON response"); }
  if (response && typeof response === "object" && !Array.isArray(response) && Object.hasOwn(response, "schemaVersion") && (response as { schemaVersion: unknown }).schemaVersion === "nightshade-persistent-list-worker-error-1") {
    try {
      const raw = dataRecord(response, ["schemaVersion", "diagnostic", "message"]);
      if (typeof raw.diagnostic !== "string" || !PERSISTENT_LIST_INCOMPLETE_DIAGNOSTICS.includes(raw.diagnostic as never) || typeof raw.message !== "string" || !raw.message || raw.message.length > 4000) throw new Error("Invalid List worker error envelope");
      return incompletePersistentListResult(raw.diagnostic, raw.message);
    } catch { return incompletePersistentListResult("persistent-list-protocol", "Malformed List worker error envelope"); }
  }
  return checkPersistentListObservation(input, response);
}

export async function runPersistentListSequenceIsolated(sequence: PersistentListSequence, compiler: string, runtimeDirectory: string, limits: Required<ExecutionLimits> = PERSISTENT_LIST_LIMITS, signal?: AbortSignal): Promise<PersistentListResult> {
  // Complete grammar and limit validation precedes serialization, filesystem work or launch.
  let input: PersistentListSequence;
  try { input = validatePersistentListSequence(sequence); }
  catch { return checkPersistentListObservation(sequence, null); }
  const bounded = validatePersistentListLimits(limits);
  if (typeof compiler !== "string" || !compiler || typeof runtimeDirectory !== "string" || !runtimeDirectory || signal !== undefined && !(signal instanceof AbortSignal)) throw new Error("Invalid fixed List runtime arguments");
  try {
    const output = await runNodeModule(fileURLToPath(new URL("../runtime-fixtures/persistent-list-worker.js", import.meta.url)), { sequence: input, compiler, runtimeDirectory }, bounded, signal);
    return checkPersistentListResponse(input, output.stdout, output.stderr);
  } catch (error) {
    return incompletePersistentListResult(error instanceof WorkerFailure ? error.code : "persistent-list-protocol", error instanceof Error ? error.message : "Unreadable List worker failure");
  }
}
