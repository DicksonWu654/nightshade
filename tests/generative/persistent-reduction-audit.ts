// Offline evidence consistency only. No stored source, model or runtime is executed.
import { closeSync, constants, fstatSync, openSync, readSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { comparePersistentResults, PERSISTENT_FILE_BYTES, persistentIdentityChanges, validatePersistentArtifact, validatePersistentLimits, type PersistentArtifact, type PersistentIdentity } from "./persistent-artifacts.js";
import { persistentDigest } from "./persistent-model.js";
import { persistentReductionCandidates, persistentReductionProperty, type PersistentReductionCandidate } from "./persistent-reduction.js";

export interface PersistentReductionAudit {
  schemaVersion: "nightshade-persistent-reduction-audit-1";
  scope: "offline-evidence-consistency-only";
  summarySha256: string;
  identity: PersistentIdentity;
  reductionStatus: "complete" | "incomplete";
  diagnostics: string[];
  checks: number;
  changed: boolean;
  final: PersistentArtifact | null;
  verifiedFiles: { file: string; sha256: string; bytes: number }[];
}
export interface AuditedPersistentReductionEvidence {
  audit: PersistentReductionAudit;
  input: PersistentArtifact;
  evaluations: { file: string; evaluatorInvoked: boolean; artifact: PersistentArtifact }[];
  finalSourceArtifact: string | null;
}
const fail = (message: string): never => { throw new Error(`Invalid persistent reduction evidence: ${message}`); };
const check = (condition: unknown, message: string): void => { if (!condition) fail(message); };
const object = (value: unknown, keys: string[], label: string): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return fail(`${label} must be a plain object`);
  check(isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort()), `${label} fields`);
  return value as Record<string, unknown>;
};
const integer = (value: unknown, minimum: number, maximum: number, label: string): number => {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) return fail(label);
  return value;
};
const bool = (value: unknown, label: string): boolean => { if (typeof value !== "boolean") return fail(label); return value; };
const equal = (actual: unknown, expected: unknown, label: string): void => check(isDeepStrictEqual(actual, expected), label);
const fileFields = ["artifact", "sha256", "bytes"];
const evaluationFields = ["sequenceSha256", "limits", "evaluatorInvoked"];
const diagnosticsAllowed = ["persistent-reduction-check-budget", "persistent-reduction-time-budget", "persistent-reduction-interrupted", "persistent-reduction-evaluation-incomplete", "persistent-reduction-build-drift", "persistent-reduction-original-incomplete", "persistent-reduction-replay-drift", "persistent-reduction-not-failed"];

function bytes(path: string): Buffer {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = fstatSync(descriptor);
    check(stat.isFile() && stat.size <= PERSISTENT_FILE_BYTES, "file must be regular and at most 1 MiB");
    const buffer = Buffer.alloc(PERSISTENT_FILE_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(descriptor, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    check(length <= PERSISTENT_FILE_BYTES, "file grew beyond 1 MiB");
    return buffer.subarray(0, length);
  } finally { closeSync(descriptor); }
}
function parse(contents: Buffer): unknown {
  try { return JSON.parse(contents.toString("utf8")); }
  catch { return fail("invalid JSON"); }
}

/**
 * Audit at most 260 known names, each opened once with bounded descriptor reads.
 * Hash agreement does not authenticate execution, compiler provenance, elapsed
 * deadlines, or an independently discovered defect. Conservative interruption/
 * time labels are retained; they can never make an incomplete run complete.
 */
export function readAuditedPersistentReduction(directory: string): AuditedPersistentReductionEvidence {
  const root = realpathSync(directory);
  const verifiedFiles: PersistentReductionAudit["verifiedFiles"] = [];
  const evaluations: AuditedPersistentReductionEvidence["evaluations"] = [];
  const read = (name: string) => {
    // All names are generated below, never taken from arbitrary manifest paths.
    const path = resolve(root, name);
    check(realpathSync(path) === path, "symlinked evidence is not accepted");
    const data = bytes(path);
    verifiedFiles.push({ file: name, sha256: persistentDigest(data), bytes: data.length });
    return data;
  };
  const summaryBytes = read("summary.json");
  const summary = object(parse(summaryBytes), ["schemaVersion", "scope", "identity", "savedWorkerLimits", "budget", "input", "originalReplay", "replay", "reductionStatus", "diagnostics", "reductionSignature", "checks", "changed", "attempts", "final"], "summary");
  equal(summary.schemaVersion, "nightshade-owned-persistent-reduction-run-1", "summary schema");
  equal(summary.scope, "owned-fixed-fixture-compiled-evaluation-only", "summary scope");
  check(summary.reductionStatus === "complete" || summary.reductionStatus === "incomplete", "reduction status");
  const status = summary.reductionStatus as "complete" | "incomplete";
  const configured = object(summary.budget, ["maxChecks", "maxElapsedMs"], "budget");
  const maxChecks = integer(configured.maxChecks, 1, 256, "check bound");
  const maxElapsedMs = integer(configured.maxElapsedMs, 1, 60000, "elapsed bound");
  const checks = integer(summary.checks, 0, maxChecks, "check count");
  const changed = bool(summary.changed, "changed flag");
  check(Array.isArray(summary.diagnostics) && summary.diagnostics.length <= diagnosticsAllowed.length, "diagnostics array");
  const diagnostics = summary.diagnostics as unknown[];
  check(diagnostics.every(item => typeof item === "string" && diagnosticsAllowed.includes(item)), "unknown diagnostic");
  equal(diagnostics, [...new Set(diagnostics)].sort(), "diagnostic order/duplicates");
  const labels = new Set(diagnostics as string[]);
  equal(status, labels.size ? "incomplete" : "complete", "status/diagnostic consistency");
  const required = new Set<string>();
  const caseFile = (record: Record<string, unknown>, expectedName: string): PersistentArtifact => {
    equal(record.artifact, expectedName, "artifact name/order");
    check(typeof record.sha256 === "string" && /^[a-f0-9]{64}$/.test(record.sha256), "artifact digest");
    const length = integer(record.bytes, 1, PERSISTENT_FILE_BYTES, "artifact byte count");
    const data = read(expectedName);
    equal(data.length, length, "artifact byte count mismatch");
    equal(persistentDigest(data), record.sha256, "artifact hash mismatch");
    return validatePersistentArtifact(parse(data));
  };
  const inputRecord = object(summary.input, fileFields, "input");
  const input = caseFile(inputRecord, "input.json");
  equal(summary.identity, input.identity, "summary/input identity");
  equal(summary.savedWorkerLimits, input.limits, "saved worker limits");
  const saved = input.limits;
  let previousInvokedTimeout = maxElapsedMs;
  const evaluation = (record: Record<string, unknown>, artifact: PersistentArtifact): void => {
    equal(persistentIdentityChanges(input.identity, artifact.identity), [], "case identity drift");
    const limits = validatePersistentLimits(record.limits);
    equal(limits, artifact.limits, "case/evaluation limits");
    equal(limits.heapMiB, saved.heapMiB, "saved heap ceiling changed");
    equal(limits.maxOutputBytes, saved.maxOutputBytes, "saved output ceiling changed");
    check(limits.timeoutMs <= saved.timeoutMs, "saved timeout raised");
    equal(record.sequenceSha256, persistentDigest(JSON.stringify(artifact.sequence)), "evaluation sequence identity");
    const invoked = bool(record.evaluatorInvoked, "invocation flag");
    if (invoked) {
      check(limits.timeoutMs <= previousInvokedTimeout, "invoked timeout exceeds total or preceding allowance");
      previousInvokedTimeout = limits.timeoutMs;
    }
    if (!invoked) {
      check(artifact.result.status === "incomplete" && ["worker-timeout", "worker-interrupted"].includes(artifact.result.diagnostic), "uninvoked evaluator cannot have measured evidence");
      check(!Object.hasOwn(artifact.result, "diagnosticResponse"), "uninvoked evaluator cannot have diagnostic streams");
      required.add(artifact.result.diagnostic === "worker-timeout" ? "persistent-reduction-time-budget" : "persistent-reduction-interrupted");
    }
  };
  const originalRecord = object(summary.originalReplay, [...fileFields, ...evaluationFields], "original replay");
  const replay = caseFile(originalRecord, "original-replay.json");
  evaluation(originalRecord, replay);
  evaluations.push({ file: "original-replay.json", evaluatorInvoked: originalRecord.evaluatorInvoked as boolean, artifact: replay });
  equal(replay.sequence, input.sequence, "original replay sequence changed");
  const comparison = comparePersistentResults(input.result, replay.result);
  const matched = input.result.status === "failed" && replay.result.status === "failed" && comparison.sameStatus && comparison.sameSignature && comparison.sameObservation === true && comparison.sameCompiledJavaScript === true;
  // JSON omits undefined optional hashes for incomplete results.
  equal(summary.replay, JSON.parse(JSON.stringify({ ...comparison, matchedFailure: matched })), "rederived replay comparison");
  check(Array.isArray(summary.attempts) && summary.attempts.length === checks, "attempt count");
  const attempts = summary.attempts as unknown[];
  let current: PersistentReductionCandidate = { sequence: replay.sequence, originalRows: replay.sequence.operations.map((_, index) => index) };
  let accepted = replay;
  let sourceArtifact = "original-replay.json";
  const signature = matched ? persistentReductionProperty(current, replay.result) : null;
  if (!matched) {
    required.add(replay.result.status === "incomplete" ? "persistent-reduction-original-incomplete"
      : !comparison.sameStatus || !comparison.sameSignature || comparison.sameObservation !== true || comparison.sameCompiledJavaScript !== true
        ? "persistent-reduction-replay-drift" : "persistent-reduction-not-failed");
    equal(attempts, [], "unmatched original seeded candidates");
    equal(summary.final, null, "unmatched original seeded final failure");
    equal(summary.reductionSignature, null, "unmatched original signature");
    equal(changed, false, "unmatched original changed");
  } else {
    const anchor = /^persistent-reduction-property-1\|original-row:(\d+)\|/.exec(signature!);
    const originalAnchor = anchor ? Number(anchor[1]) : undefined;
    const seen = new Set([JSON.stringify(current)]);
    let schedule = persistentReductionCandidates(current);
    const next = (): PersistentReductionCandidate | undefined => {
      for (let value = schedule.next(); !value.done; value = schedule.next()) {
        const candidate = value.value;
        if (originalAnchor !== undefined && !candidate.originalRows.includes(originalAnchor)) continue;
        const key = JSON.stringify(candidate);
        if (seen.has(key)) continue;
        seen.add(key);
        return candidate;
      }
      return undefined;
    };
    let terminal = false;
    for (const [index, value] of attempts.entries()) {
      check(!terminal, "attempt followed interruption/deadline");
      const record = object(value, [...fileFields, ...evaluationFields, "originalRows", "reductionSignature", "preserved", "reason"], "attempt");
      const candidate = next();
      check(candidate, "unexpected candidate after finite schedule");
      const name = `attempt-${String(index + 1).padStart(4, "0")}.json`;
      const artifact = caseFile(record, name);
      evaluation(record, artifact);
      evaluations.push({ file: name, evaluatorInvoked: record.evaluatorInvoked as boolean, artifact });
      equal(artifact.sequence, candidate!.sequence, "candidate schedule/order mismatch");
      equal(record.originalRows, candidate!.originalRows, "original-row mapping mismatch");
      const property = persistentReductionProperty(candidate!, artifact.result);
      equal(record.reductionSignature, property, "candidate property mapping");
      const preserved = bool(record.preserved, "preserved flag");
      if (!record.evaluatorInvoked) check(["time-budget", "interrupted"].includes(record.reason as string), "uninvoked candidate must stop reduction");
      const result = artifact.result;
      let reason: string;
      if (result.status === "incomplete") required.add("persistent-reduction-evaluation-incomplete");
      if (result.status === "incomplete" && result.diagnostic === "worker-interrupted") equal(record.reason, "interrupted", "worker interruption must take priority");
      if (record.reason === "interrupted") {
        required.add("persistent-reduction-interrupted"); reason = "interrupted"; terminal = true;
      } else if (record.reason === "time-budget") {
        required.add("persistent-reduction-time-budget"); reason = "time-budget"; terminal = true;
      } else if (result.status === "incomplete") {
        check(result.diagnostic !== "worker-interrupted", "worker interruption must stop reduction");
        reason = "incomplete-evaluation";
      } else if (result.observation.compiledJavaScriptSha256 !== (replay.result.status === "failed" ? replay.result.observation.compiledJavaScriptSha256 : "")) {
        required.add("persistent-reduction-build-drift"); reason = "compiled-build-drift";
      } else reason = result.status === "passed" ? "passed" : property === signature ? "preserved" : "different-property";
      equal(record.reason, reason, "candidate reason");
      equal(preserved, reason === "preserved", "false property preservation");
      if (preserved) { current = candidate!; accepted = artifact; sourceArtifact = name; schedule = persistentReductionCandidates(current); }
    }
    const more = next() !== undefined;
    // The reducer tests deadline/interruption before its check ceiling. A stop
    // between evaluations may therefore precede check-budget classification.
    if (!terminal && more && checks === maxChecks && !labels.has("persistent-reduction-time-budget") && !labels.has("persistent-reduction-interrupted")) required.add("persistent-reduction-check-budget");
    if (!terminal && more && checks === maxChecks && labels.has("persistent-reduction-check-budget")) required.add("persistent-reduction-check-budget");
    if (!terminal && more && checks < maxChecks) check(labels.has("persistent-reduction-time-budget") || labels.has("persistent-reduction-interrupted"), "unfinished schedule lacks incomplete deadline/interruption");
    if (status === "complete") check(!more && !terminal, "complete run has unfinished schedule");
    if (summary.reductionSignature === null) check(checks === 0 && (labels.has("persistent-reduction-time-budget") || labels.has("persistent-reduction-interrupted")), "missing reduction signature");
    else equal(summary.reductionSignature, signature, "original reduction property");
    equal(changed, !isDeepStrictEqual(current.sequence, input.sequence), "final changed flag");
    const finalRecord = object(summary.final, [...fileFields, "originalRows", "sourceArtifact", "caseStatus", "limits"], "final");
    equal(finalRecord.originalRows, current.originalRows, "final original rows");
    equal(finalRecord.sourceArtifact, sourceArtifact, "final source record");
    equal(finalRecord.caseStatus, "failed", "final case status");
    equal(finalRecord.limits, accepted.limits, "final saved limits");
    const final = caseFile(finalRecord, "final.json");
    equal(final, accepted, "final case differs from last accepted failure");
    check(final.result.status === "failed", "final is not a qualified failure");
    accepted = final;
  }
  for (const diagnostic of required) check(labels.has(diagnostic), `missing ${diagnostic}`);
  for (const diagnostic of labels) check(required.has(diagnostic) || ["persistent-reduction-time-budget", "persistent-reduction-interrupted"].includes(diagnostic), `unjustified ${diagnostic}`);
  return { audit: { schemaVersion: "nightshade-persistent-reduction-audit-1", scope: "offline-evidence-consistency-only", summarySha256: persistentDigest(summaryBytes), identity: input.identity,
    reductionStatus: status, diagnostics: [...labels], checks, changed, final: matched ? accepted : null, verifiedFiles }, input, evaluations, finalSourceArtifact: matched ? sourceArtifact : null };
}

export function auditPersistentReduction(directory: string): PersistentReductionAudit {
  return readAuditedPersistentReduction(directory).audit;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== "--audit") throw new Error("Use --audit REDUCTION_DIRECTORY");
    const audited = auditPersistentReduction(process.argv[3]);
    console.log(JSON.stringify({ ...audited, final: audited.final ? { status: audited.final.result.status, signature: audited.final.result.signature } : null }, null, 2));
    process.exitCode = audited.reductionStatus === "complete" ? 0 : 2;
  } catch (error) { console.error(error instanceof Error ? error.message : "Persistent reduction audit failed"); process.exitCode = 2; }
}
