/**
 * Self-authored, test-only oracle for one owned Counter/witness fixture. This is
 * independent of compiled output and analyzer transfers, not independent review.
 * No source, initial state, target, witness code or adapter is accepted as input.
 */
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

export type PersistentOperation = { kind: "accept" | "reject" | "inspect" } | { kind: "save" | "restore"; slot: number };
export interface PersistentSequence { schemaVersion: "nightshade-persistent-sequence-1"; seed: number; operations: PersistentOperation[] }
export const PERSISTENT_LOCK_SHA256 = "2fb51a5192161882aecfe1f72bed96339fcba2d76eed52db00dadc0dc44ea901";
export const PERSISTENT_SOURCE_SHA256 = "f7c6ba8a08db97e7900ee9579f7173114463958ce0aae7bad2a083ba602d349d";
export const PERSISTENT_REJECTION = "failed assert: owned persistent rejection";
export const PERSISTENT_LIMITS = Object.freeze({ timeoutMs: 60000, heapMiB: 256, maxOutputBytes: 1048576 });
export const persistentDigest = (value: string | Uint8Array): string => createHash("sha256").update(value).digest("hex");

class ProtocolError extends Error {
  constructor(readonly code: "persistent-protocol" | "persistent-sequence-budget" | "persistent-observation-budget" | "persistent-unqualified-rejection", message: string) { super(`${code}: ${message}`); }
}
function invalid(message: string): never { throw new ProtocolError("persistent-protocol", message); }
function record(value: unknown, keys: string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return invalid(`Invalid ${label}`);
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some(key => typeof key !== "string" || !keys.includes(key))) return invalid(`Invalid ${label} fields`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor) || !descriptor.enumerable) return invalid(`Invalid ${label} data field`);
  }
  return value as Record<string, unknown>;
}
function array(value: unknown, maximum: number, sequence = false): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return invalid("Expected a dense array");
  if (value.length > maximum) throw new ProtocolError(sequence ? "persistent-sequence-budget" : "persistent-observation-budget", `Array exceeds ${maximum} entries`);
  if (Reflect.ownKeys(value).length !== value.length + 1) return invalid("Unexpected array fields");
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
  if (typeof value !== "string" || value.length > 80 || !/^(?:0|-?[1-9][0-9]*)$/.test(value)) return invalid("Invalid integer observation");
  return value;
}
function hash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) return invalid("Invalid digest");
  return value;
}

export function validatePersistentSequence(value: unknown): PersistentSequence {
  const raw = record(value, ["schemaVersion", "seed", "operations"], "persistent sequence");
  if (raw.schemaVersion !== "nightshade-persistent-sequence-1") return invalid("Unsupported persistent sequence schema");
  const operations = array(raw.operations, 32, true).map((entry): PersistentOperation => {
    if (!entry || typeof entry !== "object") return invalid("Invalid operation");
    const descriptor = Object.getOwnPropertyDescriptor(entry, "kind");
    if (!descriptor || !("value" in descriptor)) return invalid("Missing operation kind data field");
    const kind = descriptor.value;
    if (kind === "accept" || kind === "reject" || kind === "inspect") { record(entry, ["kind"], "operation"); return { kind }; }
    if (kind === "save" || kind === "restore") { const op = record(entry, ["kind", "slot"], "operation"); return { kind, slot: integer(op.slot, 3) }; }
    return invalid("Unsupported persistent operation");
  });
  return { schemaVersion: "nightshade-persistent-sequence-1", seed: integer(raw.seed, 0xffffffff), operations };
}

export function generatePersistentSequence(seed: number, steps = 32): PersistentSequence {
  let state = integer(seed, 0xffffffff);
  integer(steps, 32);
  const next = () => state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
  const kinds = ["accept", "reject", "inspect", "save", "restore"] as const;
  const operations = Array.from({ length: steps }, (): PersistentOperation => {
    const kind = kinds[(next() >>> 16) % kinds.length];
    return kind === "save" || kind === "restore" ? { kind, slot: (next() >>> 16) % 4 } : { kind };
  });
  return { schemaVersion: "nightshade-persistent-sequence-1", seed, operations };
}

export interface PersistentState { count: string; next: string }
export interface PersistentSnapshot extends PersistentState { publicSha256: string }
interface ExpectedRow {
  index: number; operation: PersistentOperation["kind"]; slot: number | null;
  outcome: "evaluation-success" | "evaluation-rejection" | "saved" | "restored";
  result: string | null; witnesses: string[];
  error: { name: "CompactError"; message: string } | null;
  before: PersistentState; after: PersistentState; slots: PersistentState[];
}
export interface PersistentRow extends Omit<ExpectedRow, "before" | "after" | "slots"> { before: PersistentSnapshot; after: PersistentSnapshot; slots: PersistentSnapshot[] }
export interface PersistentObservation {
  schemaVersion: "nightshade-persistent-observation-1";
  layer: "compiled-evaluation-only"; fixture: "owned-persistent-counter-witness";
  compiler: "0.34.0"; language: "0.26.0"; runtime: "0.19.0"; onchainRuntime: "4.0.0-rc.3";
  fixedTime: 1700000000; runtimeLockSha256: string; sourceSha256: string; compiledJavaScriptSha256: string; sequenceSha256: string;
  initial: PersistentSnapshot; rows: PersistentRow[]; final: PersistentSnapshot;
}

/** Concrete bigint semantics of the small owned schedule, with copied slots. */
export function expectedPersistentSequence(input: PersistentSequence) {
  const model = validatePersistentSequence(input);
  let current = { count: 0n, next: 7n };
  const slots = Array.from({ length: 4 }, () => ({ ...current }));
  const view = (state: typeof current): PersistentState => ({ count: String(state.count), next: String(state.next) });
  const initial = view(current);
  const rows: ExpectedRow[] = model.operations.map((op, index) => {
    const before = view(current);
    let result: string | null = null;
    const witnesses: string[] = [];
    let outcome: ExpectedRow["outcome"] = "evaluation-success";
    let error: ExpectedRow["error"] = null;
    if (op.kind === "accept") { result = String(current.next); witnesses.push(result); current = { count: current.count + 1n, next: current.next + 1n }; }
    else if (op.kind === "reject") { witnesses.push(String(current.next)); outcome = "evaluation-rejection"; error = { name: "CompactError", message: PERSISTENT_REJECTION }; }
    else if (op.kind === "inspect") result = String(current.count);
    else if (op.kind === "save") { slots[op.slot] = { ...current }; outcome = "saved"; }
    else if (op.kind === "restore") { current = { ...slots[op.slot] }; outcome = "restored"; }
    return { index, operation: op.kind, slot: "slot" in op ? op.slot : null, outcome, result, witnesses, error, before, after: view(current), slots: slots.map(view) };
  });
  return { initial, rows, final: view(current) };
}

export type PersistentCheck = { status: "passed"; diagnostic: "persistent-model-checked"; signature: "persistent-model-checked"; observation: PersistentObservation }
  | { status: "failed"; diagnostic: "persistent-model-disagreement"; signature: string; message: string; observation: PersistentObservation }
  | { status: "incomplete"; diagnostic: string; signature: string; message: string };

/** Decode detached bounded evidence; completeness does not authenticate execution. */
export function validatePersistentObservation(input: PersistentSequence, value: unknown, expectedSourceSha256: string): PersistentObservation {
  const model = validatePersistentSequence(input);
  const raw = record(value, ["schemaVersion", "layer", "fixture", "compiler", "language", "runtime", "onchainRuntime", "fixedTime", "runtimeLockSha256", "sourceSha256", "compiledJavaScriptSha256", "sequenceSha256", "initial", "rows", "final"], "persistent observation");
  const constants = { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000, runtimeLockSha256: PERSISTENT_LOCK_SHA256 } as const;
  for (const [key, constant] of Object.entries(constants)) if (raw[key] !== constant) return invalid(`Unqualified ${key}`);
  if (raw.sourceSha256 !== hash(expectedSourceSha256) || raw.sequenceSha256 !== persistentDigest(JSON.stringify(model))) return invalid("Source or sequence identity mismatch");
  let nodes = 0;
  const snapshot = (value: unknown): PersistentSnapshot => {
    if (++nodes > 200) throw new ProtocolError("persistent-observation-budget", "Snapshot representation budget exhausted");
    const state = record(value, ["count", "next", "publicSha256"], "snapshot");
    return { count: scalar(state.count), next: scalar(state.next), publicSha256: hash(state.publicSha256) };
  };
  const initial = snapshot(raw.initial);
  const rows = array(raw.rows, 32).map((value): PersistentRow => {
    const row = record(value, ["index", "operation", "slot", "outcome", "result", "witnesses", "error", "before", "after", "slots"], "observation row");
    if (typeof row.operation !== "string" || !["accept", "reject", "inspect", "save", "restore"].includes(row.operation) || typeof row.outcome !== "string" || !["evaluation-success", "evaluation-rejection", "saved", "restored"].includes(row.outcome)) return invalid("Invalid operation/outcome");
    let error: ExpectedRow["error"] = null;
    if (row.error !== null) {
      const entry = record(row.error, ["name", "message"], "rejection");
      if (entry.name !== "CompactError" || entry.message !== PERSISTENT_REJECTION) throw new ProtocolError("persistent-unqualified-rejection", "Unexpected error is not an expected rejection");
      error = { name: "CompactError", message: PERSISTENT_REJECTION };
    }
    if ((row.outcome === "evaluation-rejection") !== (error !== null)) return invalid("Rejection evidence missing or attached to success");
    const slots = array(row.slots, 4).map(snapshot);
    if (slots.length !== 4) return invalid("Missing saved snapshots");
    return { index: integer(row.index, 31), operation: row.operation as PersistentOperation["kind"], slot: row.slot === null ? null : integer(row.slot, 3), outcome: row.outcome as ExpectedRow["outcome"], result: row.result === null ? null : scalar(row.result), witnesses: array(row.witnesses, 2).map(scalar), error, before: snapshot(row.before), after: snapshot(row.after), slots };
  });
  if (rows.length !== model.operations.length) return invalid("Missing or extra operation observations");
  const final = snapshot(raw.final);
  const observation: PersistentObservation = { ...constants, sourceSha256: hash(raw.sourceSha256), compiledJavaScriptSha256: hash(raw.compiledJavaScriptSha256), sequenceSha256: hash(raw.sequenceSha256), initial, rows, final };
  return observation;
}

// Both trees were constructed by bounded decoders/oracles before comparison.
function firstDifference(actual: unknown, expected: unknown, path = ""): string | undefined {
  if (isDeepStrictEqual(actual, expected)) return undefined;
  if (!expected || typeof expected !== "object" || !actual || typeof actual !== "object") return path;
  for (const [key, wanted] of Object.entries(expected)) {
    const found = firstDifference((actual as Record<string, unknown>)[key], wanted, path ? `${path}.${key}` : key);
    if (found !== undefined) return found;
  }
  return path;
}

/** Bounded structural evidence checks do not authenticate that a runtime ran. */
export function checkPersistentObservation(input: PersistentSequence, value: unknown, expectedSourceSha256: string): PersistentCheck {
  try {
    const model = validatePersistentSequence(input);
    const observation = validatePersistentObservation(model, value, expectedSourceSha256);
    const { initial, rows, final } = observation;
    const failure = (property: string, message: string): PersistentCheck => ({ status: "failed", diagnostic: "persistent-model-disagreement", signature: `persistent-model|${property}`, message, observation });
    const expected = expectedPersistentSequence(model);
    const withoutHash = ({ count, next }: PersistentSnapshot): PersistentState => ({ count, next });
    const measured = { initial: withoutHash(initial), rows: rows.map(row => ({ ...row, before: withoutHash(row.before), after: withoutHash(row.after), slots: row.slots.map(withoutHash) })), final: withoutHash(final) };
    const difference = firstDifference(measured, expected);
    if (difference !== undefined) {
      const row = /^rows\.(\d+)\.(.*)$/.exec(difference);
      const property = row ? `row:${row[1]}|operation:${model.operations[Number(row[1])].kind}|field:${row[2]}` : `field:${difference}`;
      return failure(property, `Owned persistent model disagreement at ${difference}`);
    }
    let currentHash = initial.publicSha256;
    const slotHashes = Array(4).fill(currentHash) as string[];
    for (const row of rows) {
      const property = (field: string) => `row:${row.index}|operation:${row.operation}|field:${field}`;
      let wanted = currentHash;
      if (row.operation === "restore") wanted = slotHashes[row.slot!];
      if (row.operation === "save") slotHashes[row.slot!] = currentHash;
      if (row.before.publicSha256 !== currentHash) return failure(property("before.publicSha256"), "Predecessor public snapshot identity mismatch");
      if (row.operation === "accept" ? row.after.publicSha256 === currentHash : row.after.publicSha256 !== wanted) return failure(property("after.publicSha256"), "Public snapshot identity changed across rejection, inspection, save or restoration, or failed to change after acceptance");
      const slot = row.slots.findIndex((value, index) => value.publicSha256 !== slotHashes[index]);
      if (slot >= 0) return failure(property(`slots.${slot}.publicSha256`), "Saved public snapshot identity mismatch");
      currentHash = row.after.publicSha256;
    }
    if (final.publicSha256 !== currentHash) return failure("field:final.publicSha256", "Final snapshot identity mismatch");
    return { status: "passed", diagnostic: "persistent-model-checked", signature: "persistent-model-checked", observation };
  } catch (error) {
    const diagnostic = error instanceof ProtocolError ? error.code : "persistent-protocol";
    return { status: "incomplete", diagnostic, signature: diagnostic, message: error instanceof Error ? error.message : "Unreadable persistent evidence" };
  }
}
