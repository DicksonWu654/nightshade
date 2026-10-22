/** Exact data format shared by the owned campaign writer, offline audit and replay. */
import { readFileSync } from "node:fs";
import type { ExecutionLimits } from "../../src/runtime/process.js";
import { persistentBuildIdentity, validatePersistentIdentity, validatePersistentLimits, type PersistentIdentity } from "./persistent-artifacts.js";
import { validatePersistentCorpusBudgets, type PersistentCorpusBudgets } from "./persistent-corpus.js";
import { PERSISTENT_FEEDBACK_DIAGNOSTICS } from "./persistent-feedback.js";
import { PERSISTENT_LIMITS, persistentDigest } from "./persistent-model.js";
import { PERSISTENT_SCHEDULE_DEFAULTS, validatePersistentScheduleOptions, type PersistentScheduleOptions } from "./persistent-schedule.js";
import type { PersistentScheduleTranscript } from "./persistent-schedule-audit.js";

export const PERSISTENT_GUIDED_LIMITS = Object.freeze({ archiveBytes: 80 * 1024 * 1024, caseBytes: 1048576, decisionBytes: 32768, invocationBytes: 32768, summaryBytes: 4 * 1024 * 1024, maxSlots: 68, maxFiles: 206 });
export const PERSISTENT_GUIDED_DIAGNOSTICS = Object.freeze([...PERSISTENT_FEEDBACK_DIAGNOSTICS, "persistent-model-disagreement", "persistent-corpus-budget", "persistent-corpus-consideration-budget", "persistent-corpus-evidence-budget", "persistent-corpus-identity", "persistent-corpus-compiled-build-drift", "persistent-corpus-protocol", "persistent-schedule-protocol", "persistent-schedule-input-budget", "persistent-evaluation-budget", "persistent-campaign-interrupted", "persistent-campaign-time-budget", "persistent-campaign-evidence-budget", "persistent-campaign-build-drift", "persistent-campaign-identity-unavailable", "persistent-campaign-protocol"] as const);
export interface PersistentGuidedIdentity { persistent: PersistentIdentity; modules: { feedback: { sourceSha256: string; builtSha256: string }; corpus: { sourceSha256: string; builtSha256: string }; schedule: { sourceSha256: string; builtSha256: string } } }
export interface PersistentGuidedConfiguration { schedule: PersistentScheduleOptions; workerLimits: Required<ExecutionLimits>; corpusBudgets: PersistentCorpusBudgets; maxElapsedMs: number }
export interface PersistentGuidedFileReference { name: string; sha256: string; bytes: number }
export interface PersistentGuidedFiles { ordinal: number; decision: PersistentGuidedFileReference; artifact: PersistentGuidedFileReference; invocation: PersistentGuidedFileReference; returnedArtifact: PersistentGuidedFileReference | null }
export interface PersistentGuidedInvocation {
  schemaVersion: "nightshade-persistent-guided-invocation-1";
  ordinal: number;
  decision: PersistentGuidedFileReference;
  artifact: PersistentGuidedFileReference;
  returnedArtifact: PersistentGuidedFileReference | null;
  evaluatorInvoked: boolean;
  resultOrigin: "evaluator" | "supervisor";
  timing: { proposedAtMs: number; startedAtMs: number | null; finishedAtMs: number; remainingMsAtLaunch: number | null };
  abortCause: null | "deadline" | "external-signal";
  workerLimits: Required<ExecutionLimits>;
  result: { status: "passed" | "failed" | "incomplete"; diagnostic: string; signature: string };
}
export type PersistentGuidedPostIdentity = { status: "matched" | "drift"; identity: PersistentGuidedIdentity } | { status: "unavailable"; identity: null };
export interface PersistentGuidedSummary {
  schemaVersion: "nightshade-owned-persistent-guided-1";
  scope: "owned-fixed-fixture-compiled-evaluation-only";
  identity: PersistentGuidedIdentity;
  configuration: PersistentGuidedConfiguration;
  transcript: PersistentScheduleTranscript;
  files: PersistentGuidedFiles[];
  elapsedMs: number;
  finalAbortCause: PersistentGuidedInvocation["abortCause"];
  postIdentity: PersistentGuidedPostIdentity;
  outcome: { status: "passed" | "failed" | "incomplete"; diagnostics: string[] };
  counts: { proposed: number; recorded: number; evaluatorInvoked: number; corpusConsidered: number; retained: number };
  evidenceBytesBeforeSummary: number;
}

const invalid = (message: string): never => { throw new Error(`persistent-guided-protocol: ${message}`); };
export function guidedRecord<const K extends readonly string[]>(value: unknown, keys: K, optional = false): Record<K[number], unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return invalid("Expected plain data record");
  const own = Reflect.ownKeys(value);
  if ((!optional && own.length !== keys.length) || own.some(key => typeof key !== "string" || !keys.includes(key))) return invalid("Unexpected record fields");
  for (const key of own) { const entry = Object.getOwnPropertyDescriptor(value, key)!; if (!("value" in entry) || !entry.enumerable) return invalid("Expected enumerable data properties"); }
  return value as Record<K[number], unknown>;
}
export function guidedArray(value: unknown, maximum: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) return invalid("Expected bounded dense ordinary array");
  for (let index = 0; index < value.length; index++) { const entry = Object.getOwnPropertyDescriptor(value, index); if (!entry || !("value" in entry) || !entry.enumerable) return invalid("Expected array data entries"); }
  return value;
}
export function guidedInteger(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) return invalid(`Expected integer ${minimum}..${maximum}`);
  return value;
}
export function guidedHash(value: unknown): string { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value) ? value : invalid("Invalid digest"); }
const enumValue = <const T extends readonly (string | null)[]>(value: unknown, choices: T): T[number] => choices.includes(value as T[number]) ? value as T[number] : invalid("Unknown enum");
const text = (value: unknown, maximum: number): string => typeof value === "string" && value.length > 0 && value.length <= maximum ? value : invalid("Invalid bounded text");
export function guidedEqual(actual: unknown, expected: unknown): boolean {
  if (!expected || typeof expected !== "object") return Object.is(actual, expected);
  if (!actual || typeof actual !== "object" || Array.isArray(actual) !== Array.isArray(expected)) return false;
  if (Array.isArray(actual) ? Object.getPrototypeOf(actual) !== Array.prototype : ![Object.prototype, null].includes(Object.getPrototypeOf(actual))) return false;
  const keys = Reflect.ownKeys(expected);
  if (Reflect.ownKeys(actual).length !== keys.length) return false;
  return keys.every(key => { const found = Object.getOwnPropertyDescriptor(actual, key), wanted = Object.getOwnPropertyDescriptor(expected, key)!; return found && "value" in found && found.enumerable === wanted.enumerable && guidedEqual(found.value, wanted.value); });
}
/** Only trusted, previously detached output belongs here; this is not an arbitrary-object decoder. */
export function guidedJsonBytes(value: unknown, maximum: number): Buffer {
  const data = Buffer.from(JSON.stringify(value, null, 2) + "\n");
  if (data.length > maximum) throw new Error("persistent-campaign-evidence-budget: serialized evidence exceeds file bound");
  return data;
}
export function persistentGuidedNames(ordinal: number) {
  const stem = String(guidedInteger(ordinal, 1, PERSISTENT_GUIDED_LIMITS.maxSlots)).padStart(4, "0");
  return { decision: `${stem}-decision.json`, artifact: `${stem}.json`, invocation: `${stem}-invocation.json`, returnedArtifact: `${stem}-returned.json` };
}
export function validatePersistentGuidedIdentity(value: unknown): PersistentGuidedIdentity {
  const raw = guidedRecord(value, ["persistent", "modules"]), modules = guidedRecord(raw.modules, ["feedback", "corpus", "schedule"]);
  const pair = (value: unknown) => { const raw = guidedRecord(value, ["sourceSha256", "builtSha256"]); return { sourceSha256: guidedHash(raw.sourceSha256), builtSha256: guidedHash(raw.builtSha256) }; };
  return { persistent: validatePersistentIdentity(raw.persistent), modules: { feedback: pair(modules.feedback), corpus: pair(modules.corpus), schedule: pair(modules.schedule) } };
}
export function persistentGuidedBuildIdentity(compiler: string, runtime: string): PersistentGuidedIdentity {
  const pair = (name: string) => ({ sourceSha256: persistentDigest(readFileSync(`tests/generative/persistent-${name}.ts`)), builtSha256: persistentDigest(readFileSync(`dist/tests/generative/persistent-${name}.js`)) });
  return validatePersistentGuidedIdentity({ persistent: persistentBuildIdentity(compiler, runtime), modules: { feedback: pair("feedback"), corpus: pair("corpus"), schedule: pair("schedule") } });
}
export function persistentGuidedIdentityChanges(before: PersistentGuidedIdentity, after: PersistentGuidedIdentity): string[] {
  const left = validatePersistentGuidedIdentity(before), right = validatePersistentGuidedIdentity(after), changes: string[] = [];
  for (const key of Object.keys(left.persistent) as (keyof PersistentIdentity)[]) if (left.persistent[key] !== right.persistent[key]) changes.push(`persistent.${key}`);
  for (const module of ["feedback", "corpus", "schedule"] as const) for (const kind of ["sourceSha256", "builtSha256"] as const) if (left.modules[module][kind] !== right.modules[module][kind]) changes.push(`modules.${module}.${kind}`);
  return changes;
}
export function validatePersistentGuidedConfiguration(value: unknown = {}): PersistentGuidedConfiguration {
  const raw = guidedRecord(value, ["schedule", "workerLimits", "corpusBudgets", "maxElapsedMs"], true);
  return { schedule: validatePersistentScheduleOptions(Object.hasOwn(raw, "schedule") ? raw.schedule : PERSISTENT_SCHEDULE_DEFAULTS), workerLimits: validatePersistentLimits(Object.hasOwn(raw, "workerLimits") ? raw.workerLimits : PERSISTENT_LIMITS), corpusBudgets: validatePersistentCorpusBudgets(Object.hasOwn(raw, "corpusBudgets") ? raw.corpusBudgets : {}), maxElapsedMs: guidedInteger(Object.hasOwn(raw, "maxElapsedMs") ? raw.maxElapsedMs : 60000, 1, 60000) };
}
export function validatePersistentGuidedReference(value: unknown, expectedName: string, maximum: number): PersistentGuidedFileReference {
  const raw = guidedRecord(value, ["name", "sha256", "bytes"]);
  if (raw.name !== expectedName) return invalid("Unexpected evidence filename");
  return { name: expectedName, sha256: guidedHash(raw.sha256), bytes: guidedInteger(raw.bytes, 1, maximum) };
}
export function validatePersistentGuidedFiles(value: unknown): PersistentGuidedFiles[] {
  let returned = 0;
  const result = guidedArray(value, PERSISTENT_GUIDED_LIMITS.maxSlots).map((value, index) => {
    const raw = guidedRecord(value, ["ordinal", "decision", "artifact", "invocation", "returnedArtifact"]), ordinal = guidedInteger(raw.ordinal, 1, PERSISTENT_GUIDED_LIMITS.maxSlots), names = persistentGuidedNames(ordinal);
    if (ordinal !== index + 1) return invalid("Noncanonical evidence order");
    const returnedArtifact = raw.returnedArtifact === null ? null : validatePersistentGuidedReference(raw.returnedArtifact, names.returnedArtifact, PERSISTENT_GUIDED_LIMITS.caseBytes);
    if (returnedArtifact) returned++;
    return { ordinal, decision: validatePersistentGuidedReference(raw.decision, names.decision, PERSISTENT_GUIDED_LIMITS.decisionBytes), artifact: validatePersistentGuidedReference(raw.artifact, names.artifact, PERSISTENT_GUIDED_LIMITS.caseBytes), invocation: validatePersistentGuidedReference(raw.invocation, names.invocation, PERSISTENT_GUIDED_LIMITS.invocationBytes), returnedArtifact };
  });
  if (returned > 1 || result.some((row, index) => row.returnedArtifact !== null && index !== result.length - 1)) return invalid("Returned evidence must be a single terminal companion");
  return result;
}
export function validatePersistentGuidedInvocation(value: unknown, maxElapsedMs: number): PersistentGuidedInvocation {
  guidedInteger(maxElapsedMs, 1, 60000);
  const raw = guidedRecord(value, ["schemaVersion", "ordinal", "decision", "artifact", "returnedArtifact", "evaluatorInvoked", "resultOrigin", "timing", "abortCause", "workerLimits", "result"]);
  if (raw.schemaVersion !== "nightshade-persistent-guided-invocation-1" || typeof raw.evaluatorInvoked !== "boolean") return invalid("Invalid invocation schema/flag");
  const ordinal = guidedInteger(raw.ordinal, 1, PERSISTENT_GUIDED_LIMITS.maxSlots), names = persistentGuidedNames(ordinal);
  const timing = guidedRecord(raw.timing, ["proposedAtMs", "startedAtMs", "finishedAtMs", "remainingMsAtLaunch"]);
  const proposedAtMs = guidedInteger(timing.proposedAtMs, 0, Number.MAX_SAFE_INTEGER), finishedAtMs = guidedInteger(timing.finishedAtMs, proposedAtMs, Number.MAX_SAFE_INTEGER);
  const startedAtMs = timing.startedAtMs === null ? null : guidedInteger(timing.startedAtMs, proposedAtMs, finishedAtMs);
  const remainingMsAtLaunch = timing.remainingMsAtLaunch === null ? null : guidedInteger(timing.remainingMsAtLaunch, 1, maxElapsedMs);
  if (raw.evaluatorInvoked ? startedAtMs === null || remainingMsAtLaunch !== maxElapsedMs - startedAtMs : startedAtMs !== null || remainingMsAtLaunch !== null) return invalid("Invocation launch/timing mismatch");
  const resultOrigin = enumValue(raw.resultOrigin, ["evaluator", "supervisor"]), abortCause = enumValue(raw.abortCause, [null, "deadline", "external-signal"]);
  const rawResult = guidedRecord(raw.result, ["status", "diagnostic", "signature"]), status = enumValue(rawResult.status, ["passed", "failed", "incomplete"]);
  const diagnostic = text(rawResult.diagnostic, 256), signature = text(rawResult.signature, 512);
  if (status === "passed" ? diagnostic !== "persistent-model-checked" || signature !== "persistent-model-checked" : status === "failed" ? diagnostic !== "persistent-model-disagreement" : !PERSISTENT_FEEDBACK_DIAGNOSTICS.includes(diagnostic as never) || signature !== diagnostic) return invalid("Invalid invocation result classification");
  const returnedArtifact = raw.returnedArtifact === null ? null : validatePersistentGuidedReference(raw.returnedArtifact, names.returnedArtifact, PERSISTENT_GUIDED_LIMITS.caseBytes);
  if (resultOrigin === "evaluator" && (!raw.evaluatorInvoked || abortCause !== null || returnedArtifact !== null || finishedAtMs >= maxElapsedMs)) return invalid("Evaluator result lacks on-time invocation");
  if (resultOrigin === "supervisor" && (status !== "incomplete" || (abortCause === null ? diagnostic !== "persistent-protocol" || !raw.evaluatorInvoked : diagnostic !== "worker-interrupted"))) return invalid("Invalid supervisor result");
  if (!raw.evaluatorInvoked && (resultOrigin !== "supervisor" || abortCause === null || returnedArtifact !== null)) return invalid("Uninvoked proposal cannot contain measured evidence");
  if (returnedArtifact && (!raw.evaluatorInvoked || resultOrigin !== "supervisor" || abortCause === null)) return invalid("Invalid returned companion");
  if (abortCause === "deadline" && finishedAtMs < maxElapsedMs) return invalid("Deadline predates its bound");
  return { schemaVersion: "nightshade-persistent-guided-invocation-1", ordinal, decision: validatePersistentGuidedReference(raw.decision, names.decision, PERSISTENT_GUIDED_LIMITS.decisionBytes), artifact: validatePersistentGuidedReference(raw.artifact, names.artifact, PERSISTENT_GUIDED_LIMITS.caseBytes), returnedArtifact, evaluatorInvoked: raw.evaluatorInvoked, resultOrigin, timing: { proposedAtMs, startedAtMs, finishedAtMs, remainingMsAtLaunch }, abortCause, workerLimits: validatePersistentLimits(raw.workerLimits), result: { status, diagnostic, signature } };
}
export function validatePersistentGuidedPostIdentity(value: unknown, initial: PersistentGuidedIdentity): PersistentGuidedPostIdentity {
  const raw = guidedRecord(value, ["status", "identity"]), status = enumValue(raw.status, ["matched", "drift", "unavailable"]);
  if (status === "unavailable") { if (raw.identity !== null) return invalid("Unavailable identity must be null"); return { status, identity: null }; }
  const identity = validatePersistentGuidedIdentity(raw.identity), changed = persistentGuidedIdentityChanges(initial, identity).length > 0;
  if (changed !== (status === "drift")) return invalid("Post-identity classification mismatch");
  return { status, identity };
}
export function persistentGuidedCounts(transcript: PersistentScheduleTranscript, invocations: PersistentGuidedInvocation[]): PersistentGuidedSummary["counts"] {
  const snapshot = transcript.snapshot;
  return { proposed: snapshot.proposed, recorded: snapshot.recorded, evaluatorInvoked: invocations.filter(value => value.evaluatorInvoked).length, corpusConsidered: snapshot.corpus.considered, retained: snapshot.corpus.entries.length };
}
export function persistentGuidedOutcome(transcript: PersistentScheduleTranscript, invocations: PersistentGuidedInvocation[], elapsedMs: number, configuration: PersistentGuidedConfiguration, postIdentity: PersistentGuidedPostIdentity, finalAbortCause: PersistentGuidedInvocation["abortCause"] = null): PersistentGuidedSummary["outcome"] {
  const schedule = transcript.snapshot.outcome, diagnostics = new Set<string>();
  if (schedule.status === "running") return invalid("Cannot finalize a running campaign");
  if (schedule.status !== "passed") diagnostics.add(schedule.diagnostic);
  for (const invocation of invocations) {
    if (invocation.abortCause === "deadline") diagnostics.add("persistent-campaign-time-budget");
    if (invocation.abortCause === "external-signal") diagnostics.add("persistent-campaign-interrupted");
    if (invocation.resultOrigin === "supervisor" && invocation.result.diagnostic === "persistent-protocol") diagnostics.add("persistent-campaign-protocol");
  }
  if (finalAbortCause === "external-signal") diagnostics.add("persistent-campaign-interrupted");
  if (finalAbortCause === "deadline" || elapsedMs >= configuration.maxElapsedMs) diagnostics.add("persistent-campaign-time-budget");
  if (postIdentity.status === "drift") diagnostics.add("persistent-campaign-build-drift");
  if (postIdentity.status === "unavailable") diagnostics.add("persistent-campaign-identity-unavailable");
  if ([...diagnostics].some(code => !PERSISTENT_GUIDED_DIAGNOSTICS.includes(code as never))) return invalid("Unknown campaign diagnostic");
  const extra = [...diagnostics].some(code => code !== "persistent-model-disagreement");
  return { status: schedule.status === "passed" && !diagnostics.size ? "passed" : schedule.status === "failed" && !extra ? "failed" : "incomplete", diagnostics: [...diagnostics].sort() };
}
/** Caller first reconstructs the transcript from original bytes; this checks its envelope. */
export function validatePersistentGuidedSummary(value: unknown, transcript: PersistentScheduleTranscript, invocationValues: PersistentGuidedInvocation[]): PersistentGuidedSummary {
  const raw = guidedRecord(value, ["schemaVersion", "scope", "identity", "configuration", "transcript", "files", "elapsedMs", "finalAbortCause", "postIdentity", "outcome", "counts", "evidenceBytesBeforeSummary"]);
  if (raw.schemaVersion !== "nightshade-owned-persistent-guided-1" || raw.scope !== "owned-fixed-fixture-compiled-evaluation-only") return invalid("Invalid campaign schema/scope");
  const identity = validatePersistentGuidedIdentity(raw.identity), configuration = validatePersistentGuidedConfiguration(raw.configuration), files = validatePersistentGuidedFiles(raw.files);
  if (!guidedEqual(raw.configuration, configuration) || !guidedEqual(raw.transcript, transcript) || !guidedEqual(transcript.identity, identity.persistent) || !guidedEqual(transcript.workerLimits, configuration.workerLimits) || !guidedEqual(transcript.options, configuration.schedule) || !guidedEqual(transcript.corpusBudgets, configuration.corpusBudgets)) return invalid("Campaign/transcript metadata mismatch");
  const invocations = guidedArray(invocationValues, PERSISTENT_GUIDED_LIMITS.maxSlots).map(value => validatePersistentGuidedInvocation(value, configuration.maxElapsedMs));
  if (files.length !== transcript.rows.length || files.length !== invocations.length || transcript.snapshot.pending !== null) return invalid("Campaign evidence count/pending mismatch");
  let previousFinish = 0, evidenceBytesBeforeSummary = 0;
  for (let index = 0; index < files.length; index++) {
    const file = files[index], invocation = invocations[index];
    if (invocation.ordinal !== file.ordinal || !guidedEqual(invocation.decision, file.decision) || !guidedEqual(invocation.artifact, file.artifact) || !guidedEqual(invocation.returnedArtifact, file.returnedArtifact) || !guidedEqual(invocation.workerLimits, configuration.workerLimits)) return invalid("Invocation file/limits association mismatch");
    if (invocation.timing.proposedAtMs < previousFinish) return invalid("Nonmonotonic invocation timing");
    previousFinish = invocation.timing.finishedAtMs;
    if ((invocation.abortCause !== null || invocation.resultOrigin === "supervisor") && index !== files.length - 1) return invalid("Trailing invocation after supervisor stop");
    const reference = transcript.rows[index].artifact;
    if (!reference || reference.sha256 !== file.artifact.sha256 || reference.bytes !== file.artifact.bytes) return invalid("Transcript original-byte association mismatch");
    evidenceBytesBeforeSummary += file.decision.bytes + file.artifact.bytes + file.invocation.bytes + (file.returnedArtifact?.bytes ?? 0);
  }
  if (evidenceBytesBeforeSummary + PERSISTENT_GUIDED_LIMITS.summaryBytes > PERSISTENT_GUIDED_LIMITS.archiveBytes) return invalid("Campaign archive reserve exhausted");
  const elapsedMs = guidedInteger(raw.elapsedMs, previousFinish, Number.MAX_SAFE_INTEGER), postIdentity = validatePersistentGuidedPostIdentity(raw.postIdentity, identity);
  if (transcript.stopReason === "persistent-campaign-time-budget" && elapsedMs < configuration.maxElapsedMs) return invalid("Campaign time stop predates its deadline");
  const finalAbortCause = enumValue(raw.finalAbortCause, [null, "deadline", "external-signal"]);
  const firstInvocationAbortCause = invocations.find(invocation => invocation.abortCause !== null)?.abortCause ?? null;
  if (firstInvocationAbortCause !== null && finalAbortCause !== firstInvocationAbortCause) return invalid("Final cancellation differs from first invocation cause");
  const betweenProposalCause = transcript.stopReason === "persistent-campaign-time-budget" ? "deadline" : transcript.stopReason === "persistent-campaign-interrupted" ? "external-signal" : null;
  if (betweenProposalCause !== null && finalAbortCause !== betweenProposalCause) return invalid("Final cancellation differs from between-proposal stop cause");
  if (finalAbortCause === "deadline" && elapsedMs < configuration.maxElapsedMs) return invalid("Final deadline predates its bound");
  if (finalAbortCause === null && (elapsedMs >= configuration.maxElapsedMs || invocations.some(invocation => invocation.abortCause !== null) || transcript.stopReason === "persistent-campaign-interrupted")) return invalid("Final cancellation cause is missing");
  const outcome = persistentGuidedOutcome(transcript, invocations, elapsedMs, configuration, postIdentity, finalAbortCause), counts = persistentGuidedCounts(transcript, invocations);
  if (!guidedEqual(raw.outcome, outcome) || !guidedEqual(raw.counts, counts) || raw.evidenceBytesBeforeSummary !== evidenceBytesBeforeSummary) return invalid("Derived campaign outcome/count/byte mismatch");
  return { schemaVersion: "nightshade-owned-persistent-guided-1", scope: "owned-fixed-fixture-compiled-evaluation-only", identity, configuration, transcript: structuredClone(transcript), files, elapsedMs, finalAbortCause, postIdentity, outcome, counts, evidenceBytesBeforeSummary };
}
