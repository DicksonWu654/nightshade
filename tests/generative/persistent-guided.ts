// Fixed owned fixture only; injected functions are trusted in-process test seams.
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ExecutionLimits } from "../../src/runtime/process.js";
import { incompletePersistentResult, makePersistentArtifact, runPersistentSequenceIsolated, validatePersistentResult, type PersistentResult } from "./persistent-artifacts.js";
import { PERSISTENT_CORPUS_DEFAULTS } from "./persistent-corpus.js";
import { PERSISTENT_LIMITS, persistentDigest, validatePersistentSequence, type PersistentSequence } from "./persistent-model.js";
import { PersistentSchedule, PERSISTENT_SCHEDULE_DEFAULTS, type PersistentScheduleStopReason } from "./persistent-schedule.js";
import { auditPersistentSchedule, type PersistentScheduleTranscript } from "./persistent-schedule-audit.js";
import { guidedInteger, guidedJsonBytes, persistentGuidedBuildIdentity, persistentGuidedCounts, persistentGuidedIdentityChanges, persistentGuidedNames, persistentGuidedOutcome, PERSISTENT_GUIDED_LIMITS, validatePersistentGuidedConfiguration, validatePersistentGuidedIdentity, validatePersistentGuidedInvocation, validatePersistentGuidedSummary, type PersistentGuidedFiles, type PersistentGuidedFileReference, type PersistentGuidedInvocation, type PersistentGuidedPostIdentity, type PersistentGuidedSummary } from "./persistent-guided-format.js";

export type PersistentGuidedEvaluator = (sequence: PersistentSequence, limits: Required<ExecutionLimits>, signal: AbortSignal) => Promise<unknown>;
export type PersistentGuidedIdentityProvider = () => unknown;
type AbortCause = Exclude<PersistentGuidedInvocation["abortCause"], null>;

/** Fresh exclusive archive. A consistent archive is not execution attestation. */
export async function writePersistentGuidedRun(
  outputDirectory: string,
  configuration: unknown,
  evaluate: PersistentGuidedEvaluator,
  identityProvider: PersistentGuidedIdentityProvider,
  signal?: AbortSignal,
  clock?: () => number,
): Promise<PersistentGuidedSummary> {
  const config = validatePersistentGuidedConfiguration(configuration);
  if (typeof outputDirectory !== "string" || !outputDirectory || typeof evaluate !== "function" || typeof identityProvider !== "function" || clock !== undefined && typeof clock !== "function" || signal !== undefined && !(signal instanceof AbortSignal)) throw new Error("Invalid owned campaign writer arguments");
  const identity = validatePersistentGuidedIdentity(identityProvider());
  const output = resolve(outputDirectory);
  const origin = performance.now();
  let lastTime = 0;
  const now = (): number => { const value = guidedInteger(clock ? clock() : Math.floor(performance.now() - origin), lastTime, Number.MAX_SAFE_INTEGER); lastTime = value; return value; };
  now(); // Refuse invalid clock data before creating any output.
  mkdirSync(output);
  let evidenceBytes = 0;
  const save = (name: string, bytes: Buffer): PersistentGuidedFileReference => {
    if (evidenceBytes + bytes.length + PERSISTENT_GUIDED_LIMITS.summaryBytes > PERSISTENT_GUIDED_LIMITS.archiveBytes) throw new Error("persistent-campaign-evidence-budget: archive reserve exhausted");
    writeFileSync(resolve(output, name), bytes, { flag: "wx", flush: true });
    evidenceBytes += bytes.length;
    return { name, sha256: persistentDigest(bytes), bytes: bytes.length };
  };
  const schedule = new PersistentSchedule(identity.persistent, config.workerLimits, config.schedule, config.corpusBudgets);
  const decisions: PersistentScheduleTranscript["decisions"] = [], rows: PersistentScheduleTranscript["rows"] = [], originals: Buffer[] = [];
  const invocations: PersistentGuidedInvocation[] = [], files: PersistentGuidedFiles[] = [];
  const controller = new AbortController();
  let abortCause: AbortCause | null = null, stopReason: PersistentScheduleStopReason | null = null;
  const abort = (cause: AbortCause): void => { if (abortCause === null) { abortCause = cause; controller.abort(); } };
  const external = () => abort("external-signal");
  signal?.addEventListener("abort", external, { once: true });
  if (signal?.aborted) external();
  const timer = setTimeout(() => abort("deadline"), Math.max(0, config.maxElapsedMs - lastTime));
  const stopped = (at: number): AbortCause | null => { if (at >= config.maxElapsedMs) abort("deadline"); if (signal?.aborted) external(); return abortCause; };
  const interruptedResult = () => incompletePersistentResult("worker-interrupted", "Owned campaign supervisor selected cancellation; no complete selected evaluation evidence");
  const protocolResult = () => incompletePersistentResult("persistent-protocol", "Owned evaluator threw or returned unqualified result data");
  try {
    while (schedule.snapshot().outcome.status === "running") {
      const proposedAtMs = now(), before = stopped(proposedAtMs);
      if (before !== null) { stopReason = before === "deadline" ? "persistent-campaign-time-budget" : "persistent-campaign-interrupted"; schedule.stop(stopReason); break; }
      const reserve = PERSISTENT_GUIDED_LIMITS.summaryBytes + 2 * PERSISTENT_GUIDED_LIMITS.caseBytes + PERSISTENT_GUIDED_LIMITS.decisionBytes + PERSISTENT_GUIDED_LIMITS.invocationBytes;
      if (evidenceBytes + reserve > PERSISTENT_GUIDED_LIMITS.archiveBytes) { stopReason = "persistent-campaign-evidence-budget"; schedule.stop(stopReason); break; }
      const decision = schedule.next();
      if (!decision) throw new Error("Persistent schedule unexpectedly has no proposal");
      decisions.push(decision);
      const names = persistentGuidedNames(decision.ordinal);
      const decisionFile = save(names.decision, guidedJsonBytes(decision, PERSISTENT_GUIDED_LIMITS.decisionBytes));
      let evaluatorInvoked = false, startedAtMs: number | null = null, remainingMsAtLaunch: number | null = null;
      let selected: PersistentResult, resultOrigin: PersistentGuidedInvocation["resultOrigin"] = "supervisor", returned: PersistentResult | null = null;
      let finishedAtMs: number;
      const atLaunch = now();
      if (stopped(atLaunch) !== null) { selected = interruptedResult(); finishedAtMs = atLaunch; }
      else {
        type Evaluation = { kind: "result"; result: PersistentResult } | { kind: "protocol" } | { kind: "cancelled" };
        let accepting = true, settled: PersistentResult | null = null;
        let cancel: (() => void) | undefined;
        try {
          const cancellation = new Promise<Evaluation>(resolve => { cancel = () => resolve({ kind: "cancelled" }); controller.signal.addEventListener("abort", cancel, { once: true }); });
          const work = Promise.resolve().then(async (): Promise<Evaluation> => {
            const launch = now();
            if (stopped(launch) !== null) return { kind: "cancelled" };
            startedAtMs = launch; remainingMsAtLaunch = config.maxElapsedMs - launch; evaluatorInvoked = true;
            try {
              const value = await evaluate(validatePersistentSequence(decision.sequence), { ...config.workerLimits }, controller.signal);
              if (!accepting) return { kind: "cancelled" };
              const result = validatePersistentResult(decision.sequence, value);
              settled = result;
              return { kind: "result", result };
            } catch { return { kind: "protocol" }; }
          });
          const outcome = await Promise.race([cancellation, work]);
          accepting = false;
          finishedAtMs = now();
          if (stopped(finishedAtMs) !== null || outcome.kind === "cancelled") { selected = interruptedResult(); returned = outcome.kind === "result" ? outcome.result : settled; }
          else if (outcome.kind === "protocol") selected = protocolResult();
          else { selected = outcome.result; resultOrigin = "evaluator"; }
        } finally { accepting = false; if (cancel) controller.signal.removeEventListener("abort", cancel); }
      }
      const artifactBytes = guidedJsonBytes(makePersistentArtifact(decision.sequence, identity.persistent, config.workerLimits, selected), PERSISTENT_GUIDED_LIMITS.caseBytes);
      const artifact = save(names.artifact, artifactBytes);
      const returnedArtifact = returned === null ? null : save(names.returnedArtifact, guidedJsonBytes(makePersistentArtifact(decision.sequence, identity.persistent, config.workerLimits, returned), PERSISTENT_GUIDED_LIMITS.caseBytes));
      originals.push(artifactBytes);
      const row = schedule.record(artifactBytes); rows.push(row);
      const invocation = validatePersistentGuidedInvocation({ schemaVersion: "nightshade-persistent-guided-invocation-1", ordinal: decision.ordinal, decision: decisionFile, artifact, returnedArtifact, evaluatorInvoked, resultOrigin,
        timing: { proposedAtMs, startedAtMs, finishedAtMs, remainingMsAtLaunch }, abortCause, workerLimits: config.workerLimits, result: { status: selected.status, diagnostic: selected.diagnostic, signature: selected.signature } }, config.maxElapsedMs);
      invocations.push(invocation);
      const invocationFile = save(names.invocation, guidedJsonBytes(invocation, PERSISTENT_GUIDED_LIMITS.invocationBytes));
      files.push({ ordinal: decision.ordinal, decision: decisionFile, artifact, invocation: invocationFile, returnedArtifact });
    }
    const transcript: PersistentScheduleTranscript = { schemaVersion: "nightshade-persistent-schedule-transcript-1", identity: identity.persistent, workerLimits: config.workerLimits, options: config.schedule, corpusBudgets: config.corpusBudgets, decisions, rows, stopReason, snapshot: schedule.snapshot() };
    auditPersistentSchedule(transcript, originals);
    let postIdentity: PersistentGuidedPostIdentity;
    try { const post = validatePersistentGuidedIdentity(identityProvider()); postIdentity = { status: persistentGuidedIdentityChanges(identity, post).length ? "drift" : "matched", identity: post }; }
    catch { postIdentity = { status: "unavailable", identity: null }; }
    const elapsedMs = now(), finalAbortCause = stopped(elapsedMs);
    const summary = validatePersistentGuidedSummary({ schemaVersion: "nightshade-owned-persistent-guided-1", scope: "owned-fixed-fixture-compiled-evaluation-only", identity, configuration: config, transcript, files, elapsedMs, finalAbortCause, postIdentity,
      outcome: persistentGuidedOutcome(transcript, invocations, elapsedMs, config, postIdentity, finalAbortCause), counts: persistentGuidedCounts(transcript, invocations), evidenceBytesBeforeSummary: evidenceBytes }, transcript, invocations);
    const summaryBytes = guidedJsonBytes(summary, PERSISTENT_GUIDED_LIMITS.summaryBytes);
    if (evidenceBytes + summaryBytes.length > PERSISTENT_GUIDED_LIMITS.archiveBytes) throw new Error("persistent-campaign-evidence-budget: summary exceeds archive bound");
    writeFileSync(resolve(output, "summary.json"), summaryBytes, { flag: "wx", flush: true });
    return structuredClone(summary);
  } finally { clearTimeout(timer); signal?.removeEventListener("abort", external); }
}

export async function persistentGuidedMain(args = process.argv.slice(2)): Promise<number> {
  if (args.length === 1 && args[0] === "--help") {
    console.log("Owned persistent campaign: --output NEW_DIRECTORY [--seed UINT32] [--mutations 0..64] [--max-evaluations 1..68] [--max-elapsed-ms 1..60000] [--timeout-ms 1..60000] [--heap-mib 32..256] [--max-output-bytes 1024..1048576] [--max-cases 1..128] [--max-features 1..4096] [--max-considerations 1..256] [--max-evidence-bytes 1..67108864]\nRequires pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST; run from repository root. Fixed owned Counter/witness fixture only.\nExit 0: finite passing schedule; 1: qualified property failure; 2: incomplete/input/evidence failure. No proof, transaction or general contract coverage claim.");
    return 0;
  }
  const allowed = ["--output", "--seed", "--mutations", "--max-evaluations", "--max-elapsed-ms", "--timeout-ms", "--heap-mib", "--max-output-bytes", "--max-cases", "--max-features", "--max-considerations", "--max-evidence-bytes"];
  const flags = new Map<string, string>();
  for (let index = 0; index < args.length; index++) { const flag = args[index]; if (!allowed.includes(flag) || flags.has(flag) || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error(`Invalid persistent campaign argument ${flag}`); flags.set(flag, args[++index]); }
  if (!flags.has("--output")) throw new Error("A new --output directory is required");
  const integer = (flag: string, fallback: number): number => { const value = flags.get(flag); if (value !== undefined && !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`Invalid integer ${flag}`); return value === undefined ? fallback : Number(value); };
  const configuration = validatePersistentGuidedConfiguration({
    schedule: { seed: integer("--seed", PERSISTENT_SCHEDULE_DEFAULTS.seed), mutations: integer("--mutations", PERSISTENT_SCHEDULE_DEFAULTS.mutations), maxEvaluations: integer("--max-evaluations", PERSISTENT_SCHEDULE_DEFAULTS.maxEvaluations) },
    workerLimits: { timeoutMs: integer("--timeout-ms", PERSISTENT_LIMITS.timeoutMs), heapMiB: integer("--heap-mib", PERSISTENT_LIMITS.heapMiB), maxOutputBytes: integer("--max-output-bytes", PERSISTENT_LIMITS.maxOutputBytes) },
    corpusBudgets: { maxCases: integer("--max-cases", PERSISTENT_CORPUS_DEFAULTS.maxCases), maxFeatures: integer("--max-features", PERSISTENT_CORPUS_DEFAULTS.maxFeatures), maxConsiderations: integer("--max-considerations", PERSISTENT_CORPUS_DEFAULTS.maxConsiderations), maxEvidenceBytes: integer("--max-evidence-bytes", PERSISTENT_CORPUS_DEFAULTS.maxEvidenceBytes) }, maxElapsedMs: integer("--max-elapsed-ms", 60000),
  });
  if (!process.env.COMPACTC_TEST || !process.env.COMPACT_RUNTIME_TEST) throw new Error("Pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST are mandatory");
  const compiler = resolve(process.env.COMPACTC_TEST), runtime = resolve(process.env.COMPACT_RUNTIME_TEST), controller = new AbortController(), cancel = () => controller.abort();
  process.once("SIGINT", cancel); process.once("SIGTERM", cancel);
  try {
    const summary = await writePersistentGuidedRun(flags.get("--output")!, configuration, (sequence, limits, signal) => runPersistentSequenceIsolated(sequence, compiler, runtime, limits, signal), () => persistentGuidedBuildIdentity(compiler, runtime), controller.signal);
    console.log(`${summary.outcome.status}; ${summary.counts.evaluatorInvoked} evaluator invocations; ${summary.outcome.diagnostics.join(", ") || "scheduled slots complete"}`);
    return summary.outcome.status === "passed" ? 0 : summary.outcome.status === "failed" ? 1 : 2;
  } finally { process.removeListener("SIGINT", cancel); process.removeListener("SIGTERM", cancel); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await persistentGuidedMain(); }
  catch (error) { console.error(error instanceof Error ? error.message : "Persistent campaign failed"); process.exitCode = 2; }
}
