/** Pure reconstruction from original bounded case bytes; consistency is not execution attestation. */
import type { ExecutionLimits } from "../../src/runtime/process.js";
import type { PersistentIdentity } from "./persistent-artifacts.js";
import { auditPersistentCorpus, type PersistentCorpusAdmission, type PersistentCorpusBudgets } from "./persistent-corpus.js";
import { PersistentSchedule, PERSISTENT_SCHEDULE_MAX_SLOTS, PERSISTENT_SCHEDULE_STOP_REASONS, type PersistentDecision, type PersistentScheduleOptions, type PersistentScheduleRow, type PersistentScheduleSnapshot, type PersistentScheduleStopReason } from "./persistent-schedule.js";

export interface PersistentScheduleTranscript {
  schemaVersion: "nightshade-persistent-schedule-transcript-1";
  identity: PersistentIdentity;
  workerLimits: Required<ExecutionLimits>;
  options: PersistentScheduleOptions;
  corpusBudgets: PersistentCorpusBudgets;
  decisions: PersistentDecision[];
  rows: PersistentScheduleRow[];
  stopReason: PersistentScheduleStopReason | null;
  snapshot: PersistentScheduleSnapshot;
}
export interface PersistentScheduleFold {
  scope: "offline-evidence-consistency-only";
  transcript: PersistentScheduleTranscript;
}

function invalid(message: string): never { throw new Error(`persistent-schedule-audit-protocol: ${message}`); }
function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return invalid("Expected plain data record");
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some(key => typeof key !== "string" || !keys.includes(key))) return invalid("Unexpected transcript fields");
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor) || !descriptor.enumerable) return invalid("Transcript fields must be enumerable data");
  }
  return value as Record<string, unknown>;
}
function array(value: unknown): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > PERSISTENT_SCHEDULE_MAX_SLOTS) return invalid("Expected bounded ordinary array");
  if (Reflect.ownKeys(value).length !== value.length + 1) return invalid("Decorated or sparse array");
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) return invalid("Array elements must be enumerable data");
  }
  return value;
}
/** Only expected bounded descendants drive recursion; untrusted accessors are never read. */
function equalData(actual: unknown, expected: unknown): boolean {
  if (!expected || typeof expected !== "object") return Object.is(actual, expected);
  if (!actual || typeof actual !== "object" || Array.isArray(actual) !== Array.isArray(expected)) return false;
  if (Array.isArray(actual) ? Object.getPrototypeOf(actual) !== Array.prototype : ![Object.prototype, null].includes(Object.getPrototypeOf(actual))) return false;
  const keys = Reflect.ownKeys(expected);
  if (Reflect.ownKeys(actual).length !== keys.length) return false;
  return keys.every(key => {
    const found = Object.getOwnPropertyDescriptor(actual, key), wanted = Object.getOwnPropertyDescriptor(expected, key)!;
    return found && "value" in found && found.enumerable === wanted.enumerable && equalData(found.value, wanted.value);
  });
}
function externalStop(value: unknown): PersistentScheduleStopReason | null {
  if (value === null) return null;
  if (typeof value !== "string" || !PERSISTENT_SCHEDULE_STOP_REASONS.includes(value as PersistentScheduleStopReason)) return invalid("Unknown external stop reason");
  return value as PersistentScheduleStopReason;
}

function reconstruct(identity: unknown, workerLimits: unknown, options: unknown, corpusBudgets: unknown, orderedArtifactBytes: unknown, stopReason: unknown,
  expected?: { decisions: unknown[]; rows: unknown[] }): PersistentScheduleFold {
  const inputs = array(orderedArtifactBytes), stop = externalStop(stopReason);
  if (expected && (expected.decisions.length !== inputs.length || expected.rows.length !== inputs.length)) return invalid("Saved decision/row count differs from original artifacts");
  const schedule = new PersistentSchedule(identity, workerLimits, options, corpusBudgets);
  const decisions: PersistentDecision[] = [], rows: PersistentScheduleRow[] = [];
  // Original byte references are reused only during this synchronous, callback-free fold.
  // They are ordinary byte data; this is not an in-process sandbox against proxies.
  const consideredInputs: unknown[] = [], admissions: PersistentCorpusAdmission[] = [];
  for (const [index, input] of inputs.entries()) {
    if (schedule.snapshot().outcome.status !== "running") return invalid("Trailing original artifacts after terminal schedule");
    const decision = schedule.next();
    if (!decision) return invalid("Original artifact has no corresponding proposed decision");
    if (expected && !equalData(expected.decisions[index], decision)) return invalid("Saved decision differs from original-artifact reconstruction");
    decisions.push(decision);
    const row = schedule.record(input);
    if (expected && !equalData(expected.rows[index], row)) return invalid("Saved row differs from original-artifact reconstruction");
    rows.push(row);
    if (row.admission !== null) { consideredInputs.push(input); admissions.push(row.admission); }
  }
  if (stop !== null) {
    if (schedule.snapshot().outcome.status !== "running") return invalid("External stop cannot replace a completed or failed outcome");
    schedule.stop(stop);
  }
  const snapshot = schedule.snapshot();
  // Prevalidation failures never reached consider(). Include its final pre-capture budget refusal when it did.
  auditPersistentCorpus(snapshot.corpus, consideredInputs, admissions);
  return { scope: "offline-evidence-consistency-only", transcript: {
    schemaVersion: "nightshade-persistent-schedule-transcript-1", identity: snapshot.corpus.identity, workerLimits: snapshot.corpus.workerLimits,
    options: snapshot.options, corpusBudgets: snapshot.corpus.budgets, decisions, rows, stopReason: stop, snapshot,
  } };
}

/** Running prefixes are allowed for composition; finalization is checked separately by audit. */
export function foldPersistentSchedule(identity: unknown, workerLimits: unknown, options: unknown, corpusBudgets: unknown, orderedArtifactBytes: unknown, stopReason: unknown = null): PersistentScheduleFold {
  return reconstruct(identity, workerLimits, options, corpusBudgets, orderedArtifactBytes, stopReason);
}

/** A finalized transcript must match fresh decisions, admissions and state from every original input. */
export function auditPersistentSchedule(savedTranscript: unknown, orderedArtifactBytes: unknown): PersistentScheduleFold {
  const saved = record(savedTranscript, ["schemaVersion", "identity", "workerLimits", "options", "corpusBudgets", "decisions", "rows", "stopReason", "snapshot"]);
  if (saved.schemaVersion !== "nightshade-persistent-schedule-transcript-1") return invalid("Unsupported transcript schema");
  const decisions = array(saved.decisions), rows = array(saved.rows);
  const expected = reconstruct(saved.identity, saved.workerLimits, saved.options, saved.corpusBudgets, orderedArtifactBytes, saved.stopReason, { decisions, rows });
  if (expected.transcript.snapshot.outcome.status === "running" || expected.transcript.snapshot.pending !== null) return invalid("Finalized audit requires a terminal schedule without a pending proposal");
  if (!equalData(savedTranscript, expected.transcript)) return invalid("Saved transcript differs from original-artifact reconstruction");
  return expected;
}
