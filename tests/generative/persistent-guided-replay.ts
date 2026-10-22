/** Exact execution replay of one audited, fixed owned-fixture campaign. */
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { comparePersistentResults, incompletePersistentResult, makePersistentArtifact, runPersistentSequenceIsolated, validatePersistentResult, type PersistentResult } from "./persistent-artifacts.js";
import { extractPersistentFeedback } from "./persistent-feedback.js";
import { persistentDigest, validatePersistentSequence } from "./persistent-model.js";
import { PersistentSchedule, type PersistentDecision, type PersistentScheduleRow, type PersistentScheduleSnapshot } from "./persistent-schedule.js";
import { readAuditedPersistentGuided } from "./persistent-guided-audit.js";
import type { PersistentGuidedEvaluator, PersistentGuidedIdentityProvider } from "./persistent-guided.js";
import { guidedEqual, guidedInteger, guidedJsonBytes, guidedRecord, persistentGuidedBuildIdentity, persistentGuidedIdentityChanges, persistentGuidedNames, PERSISTENT_GUIDED_LIMITS, validatePersistentGuidedIdentity, type PersistentGuidedFileReference, type PersistentGuidedIdentity, type PersistentGuidedPostIdentity, type PersistentGuidedSummary } from "./persistent-guided-format.js";

export interface PersistentGuidedReplayConfiguration { maxElapsedMs: number }
type AbortSource = "saved-launch-allowance" | "replay-deadline" | "external-signal";
type AbortCause = "deadline" | "external-signal";
export interface PersistentGuidedReplayInvocation {
  schemaVersion: "nightshade-persistent-guided-replay-invocation-1";
  ordinal: number;
  decision: PersistentGuidedFileReference;
  artifact: PersistentGuidedFileReference;
  returnedArtifact: PersistentGuidedFileReference | null;
  evaluatorInvoked: boolean;
  resultOrigin: "evaluator" | "supervisor";
  workerLimits: PersistentGuidedSummary["configuration"]["workerLimits"];
  timing: { proposedAtMs: number; startedAtMs: number | null; finishedAtMs: number; savedRemainingMsAtLaunch: number; replayRemainingMsAtLaunch: number | null; remainingMsAtLaunch: number | null; deadlineAtMs: number | null };
  abortCause: AbortCause | null;
  abortSource: AbortSource | null;
  result: { status: PersistentResult["status"]; diagnostic: string; signature: string };
}
export interface PersistentGuidedReplayComparison {
  sameStatus: boolean;
  sameSignature: boolean;
  sameObservation: boolean | null;
  sameCompiledJavaScript: boolean | null;
  sameFullResult: boolean;
  sameFeedback: boolean;
  sameAdmission: boolean;
  sameScheduleRow: boolean;
  sameArtifactBytes: boolean;
  matched: boolean;
}
export interface PersistentGuidedReplayRow {
  ordinal: number;
  saved: PersistentGuidedSummary["files"][number] & { evaluatorInvoked: boolean; resultOrigin: "evaluator" | "supervisor" };
  disposition: "not-replayed" | "saved-uninvoked" | "pending" | "decision-drift" | "not-invoked" | "matched" | "drift" | "incomplete";
  sameDecision: boolean | null;
  fresh: { decision: PersistentGuidedFileReference | null; artifact: PersistentGuidedFileReference | null; invocation: PersistentGuidedFileReference | null; returnedArtifact: PersistentGuidedFileReference | null };
  comparison: PersistentGuidedReplayComparison | null;
}
export interface PersistentGuidedReplaySummary {
  schemaVersion: "nightshade-owned-persistent-guided-replay-1";
  scope: "owned-fixed-fixture-exact-compiled-evaluation-replay-only";
  saved: { summarySha256: string; identity: PersistentGuidedIdentity; configuration: PersistentGuidedSummary["configuration"]; outcome: PersistentGuidedSummary["outcome"]; counts: PersistentGuidedSummary["counts"] };
  identity: PersistentGuidedIdentity;
  configuration: PersistentGuidedReplayConfiguration;
  rows: PersistentGuidedReplayRow[];
  schedule: { decisions: PersistentDecision[]; rows: PersistentScheduleRow[]; snapshot: PersistentScheduleSnapshot };
  scheduleComparison: { sameCounts: boolean; sameCorpusSemantics: boolean; sameScheduleOutcome: boolean; sameEvidenceBytes: boolean; sameRawSnapshot: boolean };
  elapsedMs: number;
  finalAbortCause: AbortCause | null;
  finalAbortSource: AbortSource | null;
  postIdentity: PersistentGuidedPostIdentity;
  exactEvidenceMatched: boolean;
  allArtifactBytesMatched: boolean;
  reproducedQualifiedFailure: boolean;
  outcome: { status: "passed" | "failed" | "incomplete"; diagnostics: string[] };
  counts: { saved: number; savedInvoked: number; proposed: number; recorded: number; evaluatorInvoked: number; matched: number; retained: number };
  evidenceBytesBeforeSummary: number;
}

export function validatePersistentGuidedReplayConfiguration(value: unknown = {}): PersistentGuidedReplayConfiguration {
  const raw = guidedRecord(value, ["maxElapsedMs"] as const, true);
  return { maxElapsedMs: Object.hasOwn(raw, "maxElapsedMs") ? guidedInteger(raw.maxElapsedMs, 1, 60000) : 60000 };
}

/** Byte associations remain in the saved/fresh evidence. This projection compares dispositions only. */
function semanticAdmission(row: PersistentScheduleRow) {
  if (row.admission === null) return null;
  const { artifact, ...rest } = row.admission;
  return { ...rest, hasArtifact: artifact !== null };
}
function semanticRow(row: PersistentScheduleRow) {
  const { artifact, admission: _admission, ...rest } = row;
  return { ...rest, hasArtifact: artifact !== null, admission: semanticAdmission(row) };
}
function semanticCorpus(snapshot: PersistentScheduleSnapshot) {
  const { evidenceBytes: _bytes, entries, ...rest } = snapshot.corpus;
  return { ...rest, entries: entries.map(({ artifactSha256: _hash, artifactBytes: _length, ...entry }) => entry) };
}

/**
 * A new parent hash can be mapped only after its entire result matched and its
 * actual retained entry and ordinal were checked. The real decision is untouched.
 */
function sameDecisionWithOriginalParent(decision: PersistentDecision, original: PersistentDecision, rows: PersistentGuidedReplayRow[], snapshot: PersistentScheduleSnapshot): boolean {
  const compared = structuredClone(decision);
  if (compared.parent) {
    const parent = compared.parent, row = rows[parent.ordinal - 1], entry = snapshot.corpus.entries[parent.retainedIndex];
    if (!row || row.disposition !== "matched" || !row.comparison?.matched || !row.comparison.sameFullResult || !row.fresh.artifact || !entry
      || row.ordinal !== parent.ordinal || entry.ordinal !== parent.ordinal || entry.artifactSha256 !== parent.artifactSha256
      || row.fresh.artifact.sha256 !== parent.artifactSha256 || entry.sequenceSha256 !== parent.sequenceSha256 || entry.operationsSha256 !== parent.operationsSha256) return false;
    parent.artifactSha256 = row.saved.artifact.sha256;
  }
  return guidedEqual(compared, original);
}

/** One detached audit is consumed before identity checks or creation of any output. */
export async function replayPersistentGuided(
  inputDirectory: string,
  outputDirectory: string,
  evaluate: PersistentGuidedEvaluator,
  identityProvider: PersistentGuidedIdentityProvider,
  configuration: unknown = {},
  signal?: AbortSignal,
  clock?: () => number,
): Promise<PersistentGuidedReplaySummary> {
  if (typeof inputDirectory !== "string" || !inputDirectory || typeof outputDirectory !== "string" || !outputDirectory || typeof evaluate !== "function" || typeof identityProvider !== "function" || clock !== undefined && typeof clock !== "function" || signal !== undefined && !(signal instanceof AbortSignal)) throw new Error("Invalid owned persistent campaign replay arguments");
  const config = validatePersistentGuidedReplayConfiguration(configuration);
  const audited = readAuditedPersistentGuided(inputDirectory), saved = audited.summary;
  const identity = validatePersistentGuidedIdentity(identityProvider());
  if (persistentGuidedIdentityChanges(saved.identity, identity).length) throw new Error("persistent-replay-build-drift: exact saved identity required before replay");
  const output = resolve(outputDirectory), origin = performance.now();
  let lastTime = 0;
  const now = (): number => { const value = guidedInteger(clock ? clock() : Math.floor(performance.now() - origin), lastTime, Number.MAX_SAFE_INTEGER); lastTime = value; return value; };
  now();
  mkdirSync(output);
  let evidenceBytes = 0, fileCount = 0;
  const save = (name: string, bytes: Buffer): PersistentGuidedFileReference => {
    if (fileCount + 1 >= PERSISTENT_GUIDED_LIMITS.maxFiles || evidenceBytes + bytes.length + PERSISTENT_GUIDED_LIMITS.summaryBytes > PERSISTENT_GUIDED_LIMITS.archiveBytes) throw new Error("persistent-replay-evidence-budget: archive reserve exhausted");
    writeFileSync(resolve(output, name), bytes, { flag: "wx", flush: true });
    evidenceBytes += bytes.length; fileCount++;
    return { name, sha256: persistentDigest(bytes), bytes: bytes.length };
  };
  const schedule = new PersistentSchedule(identity.persistent, saved.configuration.workerLimits, saved.configuration.schedule, saved.configuration.corpusBudgets);
  const decisions: PersistentDecision[] = [], scheduleRows: PersistentScheduleRow[] = [], invocations: PersistentGuidedReplayInvocation[] = [];
  const rows: PersistentGuidedReplayRow[] = audited.steps.map((step, index) => ({ ordinal: index + 1,
    saved: { ...structuredClone(saved.files[index]), evaluatorInvoked: step.invocation.evaluatorInvoked, resultOrigin: step.invocation.resultOrigin },
    disposition: step.invocation.evaluatorInvoked ? "not-replayed" : "saved-uninvoked", sameDecision: null,
    fresh: { decision: null, artifact: null, invocation: null, returnedArtifact: null }, comparison: null }));
  const diagnostics = new Set<string>();
  if (saved.outcome.status === "incomplete") diagnostics.add("persistent-replay-saved-incomplete");
  const controller = new AbortController();
  let abortSource: AbortSource | null = null;
  const abort = (source: AbortSource) => { if (abortSource === null) { abortSource = source; controller.abort(); } };
  const external = () => abort("external-signal");
  const cause = (): AbortCause | null => abortSource === null ? null : abortSource === "external-signal" ? "external-signal" : "deadline";
  signal?.addEventListener("abort", external, { once: true });
  if (signal?.aborted) external();
  const timer = setTimeout(() => abort("replay-deadline"), Math.max(0, config.maxElapsedMs - lastTime));
  const stopped = (at: number, invocationDeadline: number | null = null): boolean => {
    if (invocationDeadline !== null && at >= invocationDeadline && invocationDeadline < config.maxElapsedMs) abort("saved-launch-allowance");
    if (at >= config.maxElapsedMs) abort("replay-deadline");
    if (signal?.aborted) external();
    return abortSource !== null;
  };
  const interrupted = () => incompletePersistentResult("worker-interrupted", "Owned replay supervisor selected cancellation; no complete selected evaluation evidence");
  const protocol = () => incompletePersistentResult("persistent-protocol", "Owned replay evaluator threw or returned unqualified result data");
  try {
    for (const [index, step] of audited.steps.entries()) {
      const row = rows[index];
      if (!step.invocation.evaluatorInvoked) { diagnostics.add("persistent-replay-saved-uninvoked"); break; }
      const proposedAtMs = now();
      if (stopped(proposedAtMs)) break;
      const reserve = PERSISTENT_GUIDED_LIMITS.summaryBytes + 2 * PERSISTENT_GUIDED_LIMITS.caseBytes + PERSISTENT_GUIDED_LIMITS.decisionBytes + PERSISTENT_GUIDED_LIMITS.invocationBytes;
      if (evidenceBytes + reserve > PERSISTENT_GUIDED_LIMITS.archiveBytes) { diagnostics.add("persistent-replay-evidence-budget"); break; }
      const before = schedule.snapshot(), decision = schedule.next();
      if (!decision) { diagnostics.add("persistent-replay-decision-drift"); break; }
      decisions.push(decision); row.disposition = "pending";
      const names = persistentGuidedNames(row.ordinal);
      row.fresh.decision = save(names.decision, guidedJsonBytes(decision, PERSISTENT_GUIDED_LIMITS.decisionBytes));
      row.sameDecision = sameDecisionWithOriginalParent(decision, step.decision, rows, before);
      if (!row.sameDecision) { row.disposition = "decision-drift"; diagnostics.add("persistent-replay-decision-drift"); break; }
      const savedAllowance = step.invocation.timing.remainingMsAtLaunch!;
      let evaluatorInvoked = false, startedAtMs: number | null = null, replayRemainingMsAtLaunch: number | null = null, remainingMsAtLaunch: number | null = null, deadlineAtMs: number | null = null;
      let selected: PersistentResult, returned: PersistentResult | null = null, resultOrigin: "evaluator" | "supervisor" = "supervisor";
      let finishedAtMs: number;
      const atLaunch = now();
      if (stopped(atLaunch)) { selected = interrupted(); finishedAtMs = atLaunch; }
      else {
        type Evaluation = { kind: "result"; result: PersistentResult } | { kind: "protocol" } | { kind: "cancelled" };
        let accepting = true, settled: PersistentResult | null = null, cancel: (() => void) | undefined, launchTimer: ReturnType<typeof setTimeout> | undefined;
        try {
          const cancellation = new Promise<Evaluation>(resolve => { cancel = () => resolve({ kind: "cancelled" }); controller.signal.addEventListener("abort", cancel, { once: true }); });
          const work = Promise.resolve().then(async (): Promise<Evaluation> => {
            const launch = now();
            if (stopped(launch)) return { kind: "cancelled" };
            startedAtMs = launch; replayRemainingMsAtLaunch = config.maxElapsedMs - launch;
            remainingMsAtLaunch = Math.min(savedAllowance, replayRemainingMsAtLaunch); deadlineAtMs = launch + remainingMsAtLaunch;
            launchTimer = setTimeout(() => abort(savedAllowance < replayRemainingMsAtLaunch! ? "saved-launch-allowance" : "replay-deadline"), remainingMsAtLaunch);
            evaluatorInvoked = true;
            try {
              const value = await evaluate(validatePersistentSequence(decision.sequence), { ...saved.configuration.workerLimits }, controller.signal);
              if (!accepting) return { kind: "cancelled" };
              const result = validatePersistentResult(decision.sequence, value); settled = result;
              return { kind: "result", result };
            } catch { return { kind: "protocol" }; }
          });
          const outcome = await Promise.race([cancellation, work]);
          accepting = false; finishedAtMs = now();
          if (stopped(finishedAtMs, deadlineAtMs) || outcome.kind === "cancelled") { selected = interrupted(); returned = outcome.kind === "result" ? outcome.result : settled; }
          else if (outcome.kind === "protocol") selected = protocol();
          else { selected = outcome.result; resultOrigin = "evaluator"; }
        } finally { accepting = false; if (cancel) controller.signal.removeEventListener("abort", cancel); if (launchTimer !== undefined) clearTimeout(launchTimer); }
      }
      const artifact = makePersistentArtifact(decision.sequence, identity.persistent, saved.configuration.workerLimits, selected);
      const bytes = guidedJsonBytes(artifact, PERSISTENT_GUIDED_LIMITS.caseBytes);
      row.fresh.artifact = save(names.artifact, bytes);
      row.fresh.returnedArtifact = returned === null ? null : save(names.returnedArtifact, guidedJsonBytes(makePersistentArtifact(decision.sequence, identity.persistent, saved.configuration.workerLimits, returned), PERSISTENT_GUIDED_LIMITS.caseBytes));
      const freshScheduleRow = schedule.record(bytes); scheduleRows.push(freshScheduleRow);
      const invocation: PersistentGuidedReplayInvocation = { schemaVersion: "nightshade-persistent-guided-replay-invocation-1", ordinal: row.ordinal,
        decision: row.fresh.decision, artifact: row.fresh.artifact, returnedArtifact: row.fresh.returnedArtifact, evaluatorInvoked, resultOrigin,
        workerLimits: { ...saved.configuration.workerLimits }, timing: { proposedAtMs, startedAtMs, finishedAtMs, savedRemainingMsAtLaunch: savedAllowance, replayRemainingMsAtLaunch, remainingMsAtLaunch, deadlineAtMs },
        abortCause: cause(), abortSource, result: { status: selected.status, diagnostic: selected.diagnostic, signature: selected.signature } };
      invocations.push(invocation); row.fresh.invocation = save(names.invocation, guidedJsonBytes(invocation, PERSISTENT_GUIDED_LIMITS.invocationBytes));
      const compared = comparePersistentResults(step.artifact.result, selected);
      const comparison: PersistentGuidedReplayComparison = { sameStatus: compared.sameStatus, sameSignature: compared.sameSignature, sameObservation: compared.sameObservation, sameCompiledJavaScript: compared.sameCompiledJavaScript,
        sameFullResult: guidedEqual(selected, step.artifact.result), sameFeedback: guidedEqual(extractPersistentFeedback(decision.sequence, selected), extractPersistentFeedback(step.artifact.sequence, step.artifact.result)),
        sameAdmission: guidedEqual(semanticAdmission(freshScheduleRow), semanticAdmission(saved.transcript.rows[index])), sameScheduleRow: guidedEqual(semanticRow(freshScheduleRow), semanticRow(saved.transcript.rows[index])),
        sameArtifactBytes: bytes.equals(Buffer.from(step.originalBytes)), matched: false };
      comparison.matched = evaluatorInvoked && resultOrigin === "evaluator" && step.invocation.resultOrigin === "evaluator" && selected.status !== "incomplete" && step.artifact.result.status !== "incomplete"
        && comparison.sameFullResult && comparison.sameStatus && comparison.sameSignature && comparison.sameObservation === true && comparison.sameCompiledJavaScript === true && comparison.sameFeedback && comparison.sameAdmission && comparison.sameScheduleRow;
      row.comparison = comparison;
      row.disposition = !evaluatorInvoked ? "not-invoked" : selected.status === "incomplete" ? "incomplete" : comparison.matched ? "matched" : "drift";
      if (freshScheduleRow.status === "incomplete") diagnostics.add(freshScheduleRow.diagnostic!);
      if (selected.status === "incomplete") { diagnostics.add(selected.diagnostic); break; }
      if (!comparison.matched) { diagnostics.add("persistent-replay-result-drift"); break; }
      if (freshScheduleRow.status === "incomplete") { diagnostics.add(freshScheduleRow.diagnostic!); break; }
    }
    const snapshot = schedule.snapshot(), original = saved.transcript.snapshot;
    const scheduleComparison = {
      sameCounts: guidedEqual({ planned: snapshot.planned, proposed: snapshot.proposed, recorded: snapshot.recorded, counts: snapshot.counts, pending: snapshot.pending !== null }, { planned: original.planned, proposed: original.proposed, recorded: original.recorded, counts: original.counts, pending: original.pending !== null }),
      sameCorpusSemantics: guidedEqual(semanticCorpus(snapshot), semanticCorpus(original)), sameScheduleOutcome: guidedEqual(snapshot.outcome, original.outcome),
      sameEvidenceBytes: snapshot.corpus.evidenceBytes === original.corpus.evidenceBytes, sameRawSnapshot: guidedEqual(snapshot, original),
    };
    if (!scheduleComparison.sameCounts || !scheduleComparison.sameCorpusSemantics || !scheduleComparison.sameScheduleOutcome) diagnostics.add("persistent-replay-summary-drift");
    if (rows.some(row => row.disposition !== "matched")) diagnostics.add("persistent-replay-prefix");
    let postIdentity: PersistentGuidedPostIdentity;
    try { const post = validatePersistentGuidedIdentity(identityProvider()); postIdentity = { status: persistentGuidedIdentityChanges(identity, post).length ? "drift" : "matched", identity: post }; }
    catch { postIdentity = { status: "unavailable", identity: null }; }
    if (postIdentity.status !== "matched") diagnostics.add(postIdentity.status === "drift" ? "persistent-replay-build-drift" : "persistent-replay-identity-unavailable");
    // Post-final provider work belongs to the envelope, never rewrites recorded cases.
    const elapsedMs = now(); stopped(elapsedMs);
    const finalAbortCause = cause();
    if (finalAbortCause !== null) diagnostics.add(finalAbortCause === "external-signal" ? "persistent-replay-interrupted" : "persistent-replay-time-budget");
    const exactEvidenceMatched = diagnostics.size === 0 && saved.outcome.status !== "incomplete" && postIdentity.status === "matched" && rows.length > 0 && rows.every(row => row.disposition === "matched");
    const reproducedQualifiedFailure = exactEvidenceMatched && saved.outcome.status === "failed" && snapshot.outcome.status === "failed";
    const summary: PersistentGuidedReplaySummary = { schemaVersion: "nightshade-owned-persistent-guided-replay-1", scope: "owned-fixed-fixture-exact-compiled-evaluation-replay-only",
      saved: { summarySha256: audited.summarySha256, identity: saved.identity, configuration: saved.configuration, outcome: saved.outcome, counts: saved.counts }, identity, configuration: config, rows,
      schedule: { decisions, rows: scheduleRows, snapshot }, scheduleComparison, elapsedMs, finalAbortCause, finalAbortSource: abortSource, postIdentity, exactEvidenceMatched,
      allArtifactBytesMatched: exactEvidenceMatched && rows.every(row => row.comparison?.sameArtifactBytes), reproducedQualifiedFailure,
      outcome: { status: exactEvidenceMatched && saved.outcome.status === "passed" && snapshot.outcome.status === "passed" ? "passed" : reproducedQualifiedFailure ? "failed" : "incomplete", diagnostics: [...diagnostics].sort() },
      counts: { saved: rows.length, savedInvoked: saved.counts.evaluatorInvoked, proposed: decisions.length, recorded: scheduleRows.length, evaluatorInvoked: invocations.filter(value => value.evaluatorInvoked).length, matched: rows.filter(row => row.disposition === "matched").length, retained: snapshot.corpus.entries.length },
      evidenceBytesBeforeSummary: evidenceBytes };
    const summaryBytes = guidedJsonBytes(summary, PERSISTENT_GUIDED_LIMITS.summaryBytes);
    if (evidenceBytes + summaryBytes.length > PERSISTENT_GUIDED_LIMITS.archiveBytes || fileCount + 1 > PERSISTENT_GUIDED_LIMITS.maxFiles) throw new Error("persistent-replay-evidence-budget: summary exceeds archive bound");
    writeFileSync(resolve(output, "summary.json"), summaryBytes, { flag: "wx", flush: true });
    return structuredClone(summary);
  } finally { clearTimeout(timer); signal?.removeEventListener("abort", external); }
}

export async function persistentGuidedReplayMain(args = process.argv.slice(2)): Promise<number> {
  if (args.length === 1 && args[0] === "--help") {
    console.log("Exact owned persistent campaign replay: --replay DIRECTORY --output NEW_DIRECTORY [--max-elapsed-ms 1..60000]\nRequires pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST; run from repository root. Fixed owned fixture only.\nExit 0: exact replay of a passing campaign; 1: reproduced qualified failure; 2: incomplete/input/evidence failure."); return 0;
  }
  const flags = new Map<string, string>();
  for (let index = 0; index < args.length; index++) { const flag = args[index]; if (!["--replay", "--output", "--max-elapsed-ms"].includes(flag) || flags.has(flag) || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error(`Invalid persistent replay argument ${flag}`); flags.set(flag, args[++index]); }
  if (!flags.has("--replay") || !flags.has("--output")) throw new Error("--replay and a new --output directory are required");
  const elapsed = flags.get("--max-elapsed-ms");
  if (elapsed !== undefined && !/^[1-9][0-9]*$/.test(elapsed)) throw new Error("Invalid replay max elapsed integer");
  const config = validatePersistentGuidedReplayConfiguration(elapsed === undefined ? {} : { maxElapsedMs: Number(elapsed) });
  if (!process.env.COMPACTC_TEST || !process.env.COMPACT_RUNTIME_TEST) throw new Error("Pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST are mandatory");
  const compiler = resolve(process.env.COMPACTC_TEST), runtime = resolve(process.env.COMPACT_RUNTIME_TEST), controller = new AbortController(), cancel = () => controller.abort();
  process.once("SIGINT", cancel); process.once("SIGTERM", cancel);
  try {
    const summary = await replayPersistentGuided(flags.get("--replay")!, flags.get("--output")!, (sequence, limits, signal) => runPersistentSequenceIsolated(sequence, compiler, runtime, limits, signal), () => persistentGuidedBuildIdentity(compiler, runtime), config, controller.signal);
    console.log(`${summary.outcome.status}; ${summary.counts.evaluatorInvoked} evaluator invocations; exact evidence ${summary.exactEvidenceMatched ? "matched" : "not matched"}; ${summary.outcome.diagnostics.join(", ") || "complete recorded campaign replayed"}`);
    return summary.outcome.status === "passed" ? 0 : summary.reproducedQualifiedFailure ? 1 : 2;
  } finally { process.removeListener("SIGINT", cancel); process.removeListener("SIGTERM", cancel); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await persistentGuidedReplayMain(); }
  catch (error) { console.error(error instanceof Error ? error.message : "Persistent campaign replay failed"); process.exitCode = 2; }
}
