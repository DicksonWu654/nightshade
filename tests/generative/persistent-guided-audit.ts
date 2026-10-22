/** Offline original-evidence consistency only; persisted provenance does not attest execution. */
import fs from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { persistentDigest } from "./persistent-model.js";
import { validatePersistentArtifact, type PersistentArtifact } from "./persistent-artifacts.js";
import { auditPersistentSchedule } from "./persistent-schedule-audit.js";
import type { PersistentDecision } from "./persistent-schedule.js";
import { PERSISTENT_GUIDED_LIMITS, persistentGuidedNames, validatePersistentGuidedConfiguration, validatePersistentGuidedFiles, validatePersistentGuidedInvocation, validatePersistentGuidedReference, validatePersistentGuidedSummary, type PersistentGuidedFileReference, type PersistentGuidedInvocation, type PersistentGuidedSummary } from "./persistent-guided-format.js";

const fail = (message: string): never => { throw new Error(`persistent-campaign-audit-protocol: ${message}`); };
const check = (condition: unknown, message: string): void => { if (!condition) fail(message); };
const equal = (actual: unknown, expected: unknown, message: string): void => check(isDeepStrictEqual(actual, expected), message);

function record(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return fail("Expected JSON data record");
  equal(Object.keys(value).sort(), [...keys].sort(), "Unexpected evidence fields");
  return value as Record<string, unknown>;
}

function parse(bytes: Uint8Array): unknown {
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { return fail("Invalid UTF-8 JSON evidence"); }
}

/** No saved path is ever passed to this reader; callers derive all ordinal names. */
function boundedReader(directory: string, maxFiles: number, maxTotalBytes: number) {
  const root = resolve(directory), initial = fs.lstatSync(root);
  check(initial.isDirectory() && !initial.isSymbolicLink() && fs.realpathSync(root) === root, "Expected ordinary nonsymlink campaign directory");
  const entries = (): string[] => {
    const current = fs.lstatSync(root);
    check(current.isDirectory() && !current.isSymbolicLink() && current.dev === initial.dev && current.ino === initial.ino && fs.realpathSync(root) === root, "Campaign directory changed");
    const opened = fs.opendirSync(root), names: string[] = [];
    try {
      for (let entry = opened.readSync(); entry; entry = opened.readSync()) {
        check(names.length < maxFiles, "Campaign file count exceeds bound");
        check(entry.isFile() && !entry.isSymbolicLink(), "Campaign evidence must be ordinary files");
        names.push(entry.name);
      }
    } finally { opened.closeSync(); }
    return names.sort();
  };
  const initialNames = entries(), visited = new Set<string>();
  let totalBytes = 0;
  const verifiedFiles: { file: string; sha256: string; bytes: number }[] = [];
  return {
    read(name: string, maximumBytes: number): Buffer {
      check(initialNames.includes(name) && !visited.has(name), "Missing or repeated evidence file");
      check(!name.includes("/") && !name.includes("\\") && name !== "." && name !== "..", "Invalid derived evidence filename");
      const path = resolve(root, name), before = fs.lstatSync(path);
      check(before.isFile() && !before.isSymbolicLink(), "Campaign evidence must be ordinary files");
      const descriptor = fs.openSync(path, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
      try {
        const stat = fs.fstatSync(descriptor), cap = Math.min(maximumBytes, maxTotalBytes - totalBytes);
        check(stat.isFile() && stat.dev === before.dev && stat.ino === before.ino, "Evidence descriptor changed or is not a regular file");
        check(cap >= 0 && stat.size <= cap, "Evidence file or aggregate byte bound exceeded");
        const buffer = Buffer.alloc(cap + 1);
        let length = 0;
        while (length < buffer.length) {
          const count = fs.readSync(descriptor, buffer, length, buffer.length - length, null);
          if (!count) break;
          length += count;
        }
        check(length <= cap, "Evidence grew beyond file or aggregate byte bound");
        totalBytes += length; visited.add(name);
        const data = Buffer.from(buffer.subarray(0, length));
        verifiedFiles.push({ file: name, sha256: persistentDigest(data), bytes: length });
        return data;
      } finally { fs.closeSync(descriptor); }
    },
    finish(expectedNames: string[]) {
      equal(initialNames, [...expectedNames].sort(), "Unexpected campaign file set");
      equal(entries(), initialNames, "Campaign file set changed during audit");
      equal([...visited].sort(), initialNames, "Unverified campaign file");
      return { totalBytes, verifiedFiles: structuredClone(verifiedFiles) };
    },
  };
}

export interface AuditedPersistentGuided {
  scope: "offline-evidence-consistency-only";
  summary: PersistentGuidedSummary;
  summarySha256: string;
  verifiedFiles: PersistentGuidedFileReference[];
  steps: {
    decision: PersistentDecision;
    artifact: PersistentArtifact;
    originalBytes: Uint8Array;
    invocation: PersistentGuidedInvocation;
    returnedArtifact: PersistentArtifact | null;
  }[];
}

/** Read each bounded original once. Replay consumes these detached values, never saved executable code. */
export function readAuditedPersistentGuided(directory: string): AuditedPersistentGuided {
  const limits = PERSISTENT_GUIDED_LIMITS;
  const reader = boundedReader(directory, limits.maxFiles, limits.archiveBytes);
  const summaryBytes = reader.read("summary.json", limits.summaryBytes);
  const saved = record(parse(summaryBytes), ["schemaVersion", "scope", "identity", "configuration", "transcript", "files", "elapsedMs", "finalAbortCause", "postIdentity", "outcome", "counts", "evidenceBytesBeforeSummary"]);
  const configuration = validatePersistentGuidedConfiguration(saved.configuration);
  const files = validatePersistentGuidedFiles(saved.files), expectedNames = ["summary.json"];
  const originals: Buffer[] = [], decisions: unknown[] = [], invocations: PersistentGuidedInvocation[] = [];
  const artifacts: PersistentArtifact[] = [], returnedArtifacts: (PersistentArtifact | null)[] = [];
  const readReference = (value: unknown, name: string, maximum: number): Buffer => {
    const reference = validatePersistentGuidedReference(value, name, maximum);
    const data = reader.read(name, maximum);
    equal(reference, { name, sha256: persistentDigest(data), bytes: data.length }, "Original file reference differs from saved bytes");
    expectedNames.push(name);
    return data;
  };
  for (const [index, file] of files.entries()) {
    const names = persistentGuidedNames(index + 1);
    decisions.push(parse(readReference(file.decision, names.decision, limits.decisionBytes)));
    const original = readReference(file.artifact, names.artifact, limits.caseBytes);
    originals.push(original); artifacts.push(validatePersistentArtifact(parse(original)));
    const invocation = validatePersistentGuidedInvocation(parse(readReference(file.invocation, names.invocation, limits.invocationBytes)), configuration.maxElapsedMs);
    invocations.push(invocation);
    equal(invocation.ordinal, index + 1, "Invocation ordinal differs from original file order");
    equal(invocation.decision, file.decision, "Invocation decision reference differs");
    equal(invocation.artifact, file.artifact, "Invocation case reference differs");
    equal(invocation.returnedArtifact, file.returnedArtifact, "Invocation returned-case reference differs");
    if (file.returnedArtifact !== null) {
      check(index === files.length - 1, "Returned evidence must be on the final invocation");
      returnedArtifacts.push(validatePersistentArtifact(parse(readReference(file.returnedArtifact, names.returnedArtifact, limits.caseBytes))));
    } else returnedArtifacts.push(null);
  }
  const rebuilt = auditPersistentSchedule(saved.transcript, originals).transcript;
  equal(decisions, rebuilt.decisions, "Original decision files differ from reconstructed schedule");
  const summary = validatePersistentGuidedSummary(saved, rebuilt, invocations);
  if (rebuilt.stopReason === "persistent-campaign-time-budget") check(summary.elapsedMs >= configuration.maxElapsedMs, "Saved time stop predates campaign deadline");
  for (const [index, artifact] of artifacts.entries()) {
    const invocation = invocations[index], returned = returnedArtifacts[index];
    equal(artifact.sequence, rebuilt.decisions[index].sequence, "Original case differs from reconstructed proposal");
    equal(artifact.identity, summary.identity.persistent, "Original case identity differs from campaign");
    equal(artifact.limits, configuration.workerLimits, "Original case limits differ from fixed campaign limits");
    equal(invocation.workerLimits, artifact.limits, "Invocation limits differ from original case");
    const { status, diagnostic, signature } = artifact.result;
    equal(invocation.result, { status, diagnostic, signature }, "Invocation result classification differs from original case");
    if (invocation.resultOrigin === "evaluator") {
      check(invocation.evaluatorInvoked && invocation.abortCause === null && returned === null, "Evaluator-origin evidence cannot be uninvoked or supervisor-cancelled");
    } else {
      check(status === "incomplete" && !Object.hasOwn(artifact.result, "diagnosticResponse"), "Supervisor-selected evidence must be incomplete without measured streams");
      equal(diagnostic, invocation.abortCause === null ? "persistent-protocol" : "worker-interrupted", "Supervisor result does not match its recorded cause");
      check(invocation.evaluatorInvoked || invocation.abortCause !== null, "Uninvoked proposal needs explicit cancellation evidence");
    }
    if (returned !== null) {
      check(invocation.evaluatorInvoked && invocation.resultOrigin === "supervisor" && invocation.abortCause !== null, "Returned evidence lacks an invoked cancellation");
      equal(returned.sequence, artifact.sequence, "Returned case sequence differs");
      equal(returned.identity, artifact.identity, "Returned case identity differs");
      equal(returned.limits, artifact.limits, "Returned case limits differ");
    }
  }
  const checked = reader.finish(expectedNames);
  equal(checked.totalBytes, summary.evidenceBytesBeforeSummary + summaryBytes.length, "Campaign byte accounting differs from original files");
  return { scope: "offline-evidence-consistency-only", summary: structuredClone(summary), summarySha256: persistentDigest(summaryBytes),
    verifiedFiles: checked.verifiedFiles.map(({ file, ...reference }) => ({ name: file, ...reference })),
    steps: artifacts.map((artifact, index) => ({ decision: structuredClone(rebuilt.decisions[index]), artifact: structuredClone(artifact), originalBytes: Buffer.from(originals[index]),
      invocation: structuredClone(invocations[index]), returnedArtifact: returnedArtifacts[index] && structuredClone(returnedArtifacts[index]) })) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== "--audit") throw new Error("Use --audit CAMPAIGN_DIRECTORY");
    const audited = readAuditedPersistentGuided(process.argv[3]);
    console.log(JSON.stringify({ scope: audited.scope, summarySha256: audited.summarySha256, savedOutcome: audited.summary.outcome, verifiedFiles: audited.verifiedFiles.length }, null, 2));
    process.exitCode = 0;
  } catch (error) { console.error(error instanceof Error ? error.message : "Persistent campaign audit failed"); process.exitCode = 2; }
}
