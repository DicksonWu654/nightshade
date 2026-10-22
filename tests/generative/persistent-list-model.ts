/**
 * Bounded independent array oracle for one owned, fixed guarded-List fixture.
 * This self-authored specification imports no analyzer or runtime semantics and
 * does not constitute independent review or proof/transaction qualification.
 */
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

export const PERSISTENT_LIST_SOURCE_SHA256 = "562f52cbe14267ad837e49a2a4724689872f0c5a020122a32848ef7eda2f7135";
export const PERSISTENT_LIST_LOCK_SHA256 = "2fb51a5192161882aecfe1f72bed96339fcba2d76eed52db00dadc0dc44ea901";
export const PERSISTENT_LIST_MANIFEST_SHA256 = "2e87598d12b5051ee24b1134a871302e1505a937ecc14d3d5608db48d2c2dead";
export const PERSISTENT_LIST_REJECTION = "failed assert: owned guarded List requires nonempty";
export const PERSISTENT_LIST_LIMITS = Object.freeze({ timeoutMs: 60000, heapMiB: 256, maxOutputBytes: 1048576 });
export const PERSISTENT_LIST_OBSERVATION_LIMITS = Object.freeze({ maxRows: 32, maxViews: 200, maxValues: 64, maxTotalValues: 12800, maxScalarChars: 80, maxCircuitChars: 64, maxBytes: 1048576 });
export const PERSISTENT_LIST_GENERATOR = "owned-persistent-list-lcg-1";
export const PERSISTENT_LIST_INCOMPLETE_DIAGNOSTICS = Object.freeze([
  "persistent-list-protocol", "persistent-list-sequence-budget", "persistent-list-observation-budget",
  "persistent-list-unqualified-rejection", "persistent-list-input-identity", "persistent-list-compiler",
  "worker-input-budget", "worker-interrupted", "worker-timeout", "worker-output-budget", "worker-launch", "worker-failed", "worker-input",
] as const);
export type PersistentListIncompleteDiagnostic = typeof PERSISTENT_LIST_INCOMPLETE_DIAGNOSTICS[number];
export const persistentListDigest = (value: string | Uint8Array): string => createHash("sha256").update(value).digest("hex");

export type PersistentListOperation = { kind: "push"; value: number } | { kind: "guardedPop" | "inspect" } | { kind: "save" | "restore"; slot: number };
export interface PersistentListSequence { schemaVersion: "nightshade-persistent-list-sequence-1"; seed: number; operations: PersistentListOperation[] }
export interface PersistentListMaybe { is_some: boolean; value: string }
export interface PersistentListState { values: string[]; length: string; empty: boolean; head: PersistentListMaybe; next: string }
export interface PersistentListSnapshot extends PersistentListState { publicSha256: string }
export type PersistentListValue = null | [] | [boolean, string, PersistentListMaybe];
export interface PersistentListTranscript { circuit: string; privateOutputs: number; events: number }
export interface ExpectedPersistentListRow {
  index: number; operation: PersistentListOperation;
  outcome: "evaluation-success" | "evaluation-rejection" | "saved" | "restored";
  result: PersistentListValue; error: null | { name: "CompactError"; message: string }; transcript: PersistentListTranscript | null;
  before: PersistentListState; after: PersistentListState; slots: PersistentListState[];
}
export interface PersistentListRow extends Omit<ExpectedPersistentListRow, "before" | "after" | "slots"> {
  before: PersistentListSnapshot; after: PersistentListSnapshot; slots: PersistentListSnapshot[];
}
export interface PersistentListObservation {
  schemaVersion: "nightshade-persistent-list-observation-1"; layer: "compiled-evaluation-only"; fixture: "owned-persistent-guarded-list";
  compiler: "0.34.0"; language: "0.26.0"; runtime: "0.19.0"; onchainRuntime: "4.0.0-rc.3"; fixedTime: 1700000000;
  runtimeLockSha256: string; runtimeInputsManifestSha256: string; sourceSha256: string; compiledJavaScriptSha256: string; sequenceSha256: string;
  initial: PersistentListSnapshot; rows: PersistentListRow[]; final: PersistentListSnapshot;
}
export type PersistentListResult =
  | { status: "passed"; diagnostic: "persistent-list-model-checked"; signature: "persistent-list-model-checked"; observation: PersistentListObservation }
  | { status: "failed"; diagnostic: "persistent-list-model-disagreement"; signature: string; message: string; observation: PersistentListObservation }
  | { status: "incomplete"; diagnostic: PersistentListIncompleteDiagnostic; signature: PersistentListIncompleteDiagnostic; message: string };

class ProtocolError extends Error {
  constructor(readonly code: PersistentListIncompleteDiagnostic, message: string) { super(`${code}: ${message}`); }
}
function invalid(message: string): never { throw new ProtocolError("persistent-list-protocol", message); }
function budget(message: string): never { throw new ProtocolError("persistent-list-observation-budget", message); }
function record(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return invalid(`Invalid ${label}`);
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some(key => typeof key !== "string" || !keys.includes(key))) return invalid(`Invalid ${label} fields`);
  // Inspect descriptors before reading any field; never call a supplied getter.
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor) || !descriptor.enumerable) return invalid(`Invalid ${label} data field`);
  }
  return value as Record<string, unknown>;
}
function array(value: unknown, maximum: number, sequence = false): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return invalid("Expected a dense plain array");
  if (value.length > maximum) throw new ProtocolError(sequence ? "persistent-list-sequence-budget" : "persistent-list-observation-budget", `Array exceeds ${maximum} entries`);
  if (Reflect.ownKeys(value).length !== value.length + 1) return invalid("Unexpected array fields or holes");
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) return invalid("Array entries must be enumerable data fields");
  }
  return value;
}
function integer(value: unknown, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0) || value < 0 || value > maximum) return invalid(`Expected an integer in 0..${maximum}`);
  return value;
}
function scalar(value: unknown): string {
  if (typeof value !== "string") return invalid("Invalid integer observation type");
  if (value.length > PERSISTENT_LIST_OBSERVATION_LIMITS.maxScalarChars) return budget("Measured scalar exceeds bounded decimal representation");
  if (!/^(?:0|-?[1-9][0-9]*)$/.test(value)) return invalid("Invalid canonical integer observation");
  return value;
}
function boolean(value: unknown): boolean { if (typeof value !== "boolean") return invalid("Invalid Boolean observation"); return value; }
function hash(value: unknown): string { if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) return invalid("Invalid digest"); return value; }
function maybe(value: unknown): PersistentListMaybe {
  const raw = record(value, ["is_some", "value"], "Maybe observation");
  return { is_some: boolean(raw.is_some), value: scalar(raw.value) };
}
function operation(value: unknown): PersistentListOperation {
  if (!value || typeof value !== "object") return invalid("Invalid operation");
  const descriptor = Object.getOwnPropertyDescriptor(value, "kind");
  if (!descriptor || !("value" in descriptor)) return invalid("Missing operation kind data field");
  const kind: unknown = descriptor.value;
  if (kind === "push") { const raw = record(value, ["kind", "value"], "push operation"); return { kind, value: integer(raw.value, 255) }; }
  if (kind === "guardedPop" || kind === "inspect") { record(value, ["kind"], "operation"); return { kind }; }
  if (kind === "save" || kind === "restore") { const raw = record(value, ["kind", "slot"], "slot operation"); return { kind, slot: integer(raw.slot, 3) }; }
  return invalid("Unsupported persistent List operation");
}

/** Validate and detach before external tools/files are accessed. */
export function validatePersistentListSequence(value: unknown): PersistentListSequence {
  const raw = record(value, ["schemaVersion", "seed", "operations"], "persistent List sequence");
  if (raw.schemaVersion !== "nightshade-persistent-list-sequence-1") return invalid("Unsupported persistent List sequence schema");
  return { schemaVersion: "nightshade-persistent-list-sequence-1", seed: integer(raw.seed, 0xffffffff), operations: array(raw.operations, 32, true).map(operation) };
}

/** Versioned uint32 LCG; exactly three words per operation, including keyless calls. */
export function generatePersistentListSequence(seed: number, steps = 32): PersistentListSequence {
  let state = integer(seed, 0xffffffff);
  integer(steps, 32);
  const next = () => state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
  const kinds = ["push", "guardedPop", "inspect", "save", "restore"] as const;
  const boundaries = [0, 1, 254, 255];
  const operations = Array.from({ length: steps }, (): PersistentListOperation => {
    const kindWord = next(), operandWord = next(), boundaryWord = next();
    const kind = kinds[(kindWord >>> 16) % kinds.length];
    if (kind === "push") return { kind, value: boundaryWord % 2 === 0 ? boundaries[(operandWord >>> 16) % boundaries.length] : (operandWord >>> 16) % 256 };
    return kind === "save" || kind === "restore" ? { kind, slot: (operandWord >>> 16) % 4 } : { kind };
  });
  return { schemaVersion: "nightshade-persistent-list-sequence-1", seed, operations };
}

/** Ordinary copied arrays specify only the initialized, typed owned fixture. */
export function expectedPersistentListSequence(input: PersistentListSequence): { initial: PersistentListState; rows: ExpectedPersistentListRow[]; final: PersistentListState } {
  const model = validatePersistentListSequence(input);
  let current = [3];
  const slots = Array.from({ length: 4 }, () => current.slice());
  const view = (values: number[]): PersistentListState => ({ values: values.map(String), length: String(values.length), empty: values.length === 0, head: { is_some: values.length !== 0, value: String(values[0] ?? 0) }, next: "7" });
  const initial = view(current);
  const rows = model.operations.map((op, index): ExpectedPersistentListRow => {
    const before = view(current);
    let result: PersistentListValue = [], error: ExpectedPersistentListRow["error"] = null;
    let outcome: ExpectedPersistentListRow["outcome"] = "evaluation-success";
    let transcript: PersistentListTranscript | null = { circuit: op.kind, privateOutputs: 0, events: 0 };
    if (op.kind === "push") current = [op.value, ...current];
    else if (op.kind === "guardedPop") {
      if (current.length) current = current.slice(1);
      else { outcome = "evaluation-rejection"; result = null; transcript = null; error = { name: "CompactError", message: PERSISTENT_LIST_REJECTION }; }
    } else if (op.kind === "inspect") result = [before.empty, before.length, { ...before.head }];
    else {
      result = null; transcript = null;
      if (op.kind === "save") { slots[op.slot] = current.slice(); outcome = "saved"; }
      else if (op.kind === "restore") { current = slots[op.slot].slice(); outcome = "restored"; }
    }
    return { index, operation: { ...op }, outcome, result, error, transcript, before, after: view(current), slots: slots.map(view) };
  });
  return { initial, rows, final: view(current) };
}

/** Shape and bounds only: readable semantic disagreements must reach the oracle. */
export function validatePersistentListObservation(input: PersistentListSequence, value: unknown): PersistentListObservation {
  const model = validatePersistentListSequence(input);
  const raw = record(value, ["schemaVersion", "layer", "fixture", "compiler", "language", "runtime", "onchainRuntime", "fixedTime", "runtimeLockSha256", "runtimeInputsManifestSha256", "sourceSha256", "compiledJavaScriptSha256", "sequenceSha256", "initial", "rows", "final"], "persistent List observation");
  const constants = { schemaVersion: "nightshade-persistent-list-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-guarded-list", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000, runtimeLockSha256: PERSISTENT_LIST_LOCK_SHA256, runtimeInputsManifestSha256: PERSISTENT_LIST_MANIFEST_SHA256, sourceSha256: PERSISTENT_LIST_SOURCE_SHA256 } as const;
  for (const [key, wanted] of Object.entries(constants)) if (raw[key] !== wanted) throw new ProtocolError("persistent-list-input-identity", `Unqualified ${key}`);
  if (raw.sequenceSha256 !== persistentListDigest(JSON.stringify(model))) throw new ProtocolError("persistent-list-input-identity", "Sequence identity mismatch");
  let views = 0, totalValues = 0;
  const snapshot = (value: unknown): PersistentListSnapshot => {
    if (++views > PERSISTENT_LIST_OBSERVATION_LIMITS.maxViews) return budget("Snapshot view budget exhausted");
    const state = record(value, ["values", "length", "empty", "head", "next", "publicSha256"], "snapshot");
    const values = array(state.values, PERSISTENT_LIST_OBSERVATION_LIMITS.maxValues);
    if ((totalValues += values.length) > PERSISTENT_LIST_OBSERVATION_LIMITS.maxTotalValues) return budget("Observed value budget exhausted");
    return { values: values.map(scalar), length: scalar(state.length), empty: boolean(state.empty), head: maybe(state.head), next: scalar(state.next), publicSha256: hash(state.publicSha256) };
  };
  const initial = snapshot(raw.initial);
  const rows = array(raw.rows, PERSISTENT_LIST_OBSERVATION_LIMITS.maxRows).map((entry): PersistentListRow => {
    const row = record(entry, ["index", "operation", "outcome", "result", "error", "transcript", "before", "after", "slots"], "observation row");
    const op = operation(row.operation);
    if (typeof row.outcome !== "string" || !["evaluation-success", "evaluation-rejection", "saved", "restored"].includes(row.outcome)) return invalid("Invalid operation outcome");
    let error: PersistentListRow["error"] = null;
    if (row.error !== null) {
      const reject = record(row.error, ["name", "message"], "rejection");
      if (op.kind !== "guardedPop" || reject.name !== "CompactError" || reject.message !== PERSISTENT_LIST_REJECTION) throw new ProtocolError("persistent-list-unqualified-rejection", "Unexpected error is not a qualified guard rejection");
      error = { name: "CompactError", message: PERSISTENT_LIST_REJECTION };
    }
    if ((row.outcome === "evaluation-rejection") !== (error !== null)) return invalid("Missing rejection evidence or rejection attached to another outcome");
    let result: PersistentListValue = null;
    if (row.result !== null) {
      const tuple = array(row.result, 3);
      if (tuple.length === 0) result = [];
      else if (tuple.length === 3) result = [boolean(tuple[0]), scalar(tuple[1]), maybe(tuple[2])];
      else return invalid("Invalid result tuple");
    }
    let transcript: PersistentListTranscript | null = null;
    if (row.transcript !== null) {
      const trace = record(row.transcript, ["circuit", "privateOutputs", "events"], "circuit transcript");
      if (typeof trace.circuit !== "string" || !trace.circuit) return invalid("Invalid transcript circuit");
      if (trace.circuit.length > PERSISTENT_LIST_OBSERVATION_LIMITS.maxCircuitChars) return budget("Measured circuit identity exceeds representation bound");
      transcript = { circuit: trace.circuit, privateOutputs: integer(trace.privateOutputs, 0xffffffff), events: integer(trace.events, 0xffffffff) };
    }
    const before = snapshot(row.before), after = snapshot(row.after), slots = array(row.slots, 4).map(snapshot);
    if (slots.length !== 4) return invalid("Missing saved slots");
    return { index: integer(row.index, 31), operation: op, outcome: row.outcome as PersistentListRow["outcome"], result, error, transcript, before, after, slots };
  });
  if (rows.length !== model.operations.length) return invalid("Missing or extra operation observations");
  const observation: PersistentListObservation = { ...constants, compiledJavaScriptSha256: hash(raw.compiledJavaScriptSha256), sequenceSha256: hash(raw.sequenceSha256), initial, rows, final: snapshot(raw.final) };
  if (Buffer.byteLength(JSON.stringify(observation)) > PERSISTENT_LIST_OBSERVATION_LIMITS.maxBytes) return budget("Observation wire budget exhausted");
  return observation;
}

// Both arguments have been constructed by bounded decoders/oracles.
function firstDifference(actual: unknown, expected: unknown, path = ""): string | undefined {
  if (isDeepStrictEqual(actual, expected)) return undefined;
  if (!expected || typeof expected !== "object" || !actual || typeof actual !== "object") return path;
  for (const [key, wanted] of Object.entries(expected)) {
    const found = firstDifference((actual as Record<string, unknown>)[key], wanted, path ? `${path}.${key}` : key);
    if (found !== undefined) return found;
  }
  return path;
}
export function incompletePersistentListResult(diagnostic: string, message: string): Extract<PersistentListResult, { status: "incomplete" }> {
  const code = (PERSISTENT_LIST_INCOMPLETE_DIAGNOSTICS as readonly string[]).includes(diagnostic) ? diagnostic as PersistentListIncompleteDiagnostic : "persistent-list-protocol";
  return { status: "incomplete", diagnostic: code, signature: code, message: message.slice(0, 4000) || "Incomplete persistent List evidence" };
}

/** Checks detached evidence; this function cannot authenticate that execution occurred. */
export function checkPersistentListObservation(input: PersistentListSequence, value: unknown): PersistentListResult {
  try {
    const model = validatePersistentListSequence(input), observation = validatePersistentListObservation(model, value);
    const failure = (property: string, message: string): PersistentListResult => ({ status: "failed", diagnostic: "persistent-list-model-disagreement", signature: `persistent-list-model|${property}`, message, observation });
    const plain = ({ publicSha256, ...state }: PersistentListSnapshot): PersistentListState => state;
    const measured = { initial: plain(observation.initial), rows: observation.rows.map(row => ({ ...row, before: plain(row.before), after: plain(row.after), slots: row.slots.map(plain) })), final: plain(observation.final) };
    const difference = firstDifference(measured, expectedPersistentListSequence(model));
    if (difference !== undefined) {
      const row = /^rows\.(\d+)\.(.*)$/.exec(difference);
      const property = row ? `row:${row[1]}|operation:${model.operations[Number(row[1])].kind}|field:${row[2]}` : `field:${difference}`;
      return failure(property, `Owned persistent List model disagreement at ${difference}`);
    }
    let currentHash = observation.initial.publicSha256;
    const slotHashes = Array<string>(4).fill(currentHash);
    for (const row of observation.rows) {
      const property = (field: string) => `row:${row.index}|operation:${row.operation.kind}|field:${field}`;
      if (row.before.publicSha256 !== currentHash) return failure(property("before.publicSha256"), "Predecessor public snapshot identity mismatch");
      let wanted = currentHash;
      if (row.operation.kind === "restore") wanted = slotHashes[row.operation.slot];
      if (row.operation.kind === "save") slotHashes[row.operation.slot] = currentHash;
      const mutation = row.operation.kind === "push" || row.operation.kind === "guardedPop" && row.outcome === "evaluation-success";
      if (mutation ? row.after.publicSha256 === currentHash : row.after.publicSha256 !== wanted) return failure(property("after.publicSha256"), "Accepted mutation did not change public identity, or rejection/inspection/save/restoration changed its prescribed snapshot identity");
      const slot = row.slots.findIndex((state, index) => state.publicSha256 !== slotHashes[index]);
      if (slot >= 0) return failure(property(`slots.${slot}.publicSha256`), "Saved public snapshot identity mismatch");
      currentHash = row.after.publicSha256;
    }
    if (observation.final.publicSha256 !== currentHash) return failure("field:final.publicSha256", "Final public snapshot identity mismatch");
    return { status: "passed", diagnostic: "persistent-list-model-checked", signature: "persistent-list-model-checked", observation };
  } catch (error) {
    return incompletePersistentListResult(error instanceof ProtocolError ? error.code : "persistent-list-protocol", error instanceof Error ? error.message : "Unreadable persistent List evidence");
  }
}

/** Stored labels/signatures are never trusted; complete results are rederived. */
export function validatePersistentListResult(input: PersistentListSequence, value: unknown): PersistentListResult {
  const model = validatePersistentListSequence(input);
  if (!value || typeof value !== "object") return invalid("Invalid persistent List result");
  const statusField = Object.getOwnPropertyDescriptor(value, "status");
  if (!statusField || !("value" in statusField)) return invalid("Missing result status data field");
  const status: unknown = statusField.value;
  if (status === "incomplete") {
    const raw = record(value, ["status", "diagnostic", "signature", "message"], "incomplete result");
    if (typeof raw.diagnostic !== "string" || !(PERSISTENT_LIST_INCOMPLETE_DIAGNOSTICS as readonly string[]).includes(raw.diagnostic) || raw.signature !== raw.diagnostic || typeof raw.message !== "string" || !raw.message || raw.message.length > 4000) return invalid("Invalid incomplete result fields");
    return incompletePersistentListResult(raw.diagnostic, raw.message);
  }
  if (status !== "passed" && status !== "failed") return invalid("Invalid result status");
  const raw = record(value, status === "passed" ? ["status", "diagnostic", "signature", "observation"] : ["status", "diagnostic", "signature", "message", "observation"], "complete result");
  const checked = checkPersistentListObservation(model, raw.observation);
  if (checked.status !== status || raw.diagnostic !== checked.diagnostic || raw.signature !== checked.signature || checked.status === "failed" && raw.message !== checked.message) return invalid("Result qualification/signature mismatch");
  return checked;
}
