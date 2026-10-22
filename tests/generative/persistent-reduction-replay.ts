// Reexecutes saved invocations of the fixed owned fixture. Never loads saved code.
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { comparePersistentResults, incompletePersistentResult, makePersistentArtifact, PERSISTENT_FILE_BYTES, persistentBuildIdentity, persistentIdentityChanges, runPersistentSequenceIsolated, validatePersistentResult, type PersistentIdentity, type PersistentResult } from "./persistent-artifacts.js";
import { readAuditedPersistentReduction } from "./persistent-reduction-audit.js";
import type { OwnedPersistentEvaluator } from "./persistent-reduction-cli.js";
import { persistentDigest } from "./persistent-model.js";

interface EvidenceFile { artifact: string; sha256: string; bytes: number }
export interface PersistentReductionReplayOptions { maxElapsedMs?: number; signal?: AbortSignal }
export interface PersistentReductionReplayRow {
  savedFile: string;
  savedSha256: string;
  savedEvaluatorInvoked: boolean;
  replayEvaluatorInvoked: boolean;
  state: "matched" | "drift" | "incomplete" | "saved-uninvoked" | "not-replayed";
  fresh: EvidenceFile | null;
  comparison: ReturnType<typeof comparePersistentReductionReplayResults> | null;
}
export interface PersistentReductionReplaySummary {
  schemaVersion: "nightshade-persistent-reduction-execution-replay-1";
  scope: "saved-owned-fixture-invocations-only";
  identity: PersistentIdentity;
  savedSummarySha256: string;
  savedFiles: { file: string; sha256: string; bytes: number }[];
  savedReductionStatus: "complete" | "incomplete";
  savedReductionDiagnostics: string[];
  savedFinalStatus: "failed" | null;
  maxElapsedMs: number;
  replayStatus: "complete" | "incomplete";
  diagnostics: string[];
  invocations: number;
  recordedInvocations: number;
  exactEvidenceMatched: boolean;
  rows: PersistentReductionReplayRow[];
  finalSource: { savedFile: string; replayArtifact: string | null; matched: boolean } | null;
}

export function comparePersistentReductionReplayResults(before: PersistentResult, after: PersistentResult) {
  const comparison = comparePersistentResults(before, after);
  return { ...comparison,
    sameIncompleteClass: before.status === "incomplete" && after.status === "incomplete" ? before.diagnostic === after.diagnostic : null,
    exactEvidenceMatch: before.status !== "incomplete" && after.status !== "incomplete" && comparison.sameStatus && comparison.sameSignature && comparison.sameObservation === true && comparison.sameCompiledJavaScript === true };
}
function options(value: PersistentReductionReplayOptions) {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error("Invalid persistent reduction replay options");
  for (const key of Reflect.ownKeys(value)) {
    const field = Object.getOwnPropertyDescriptor(value, key)!;
    if (typeof key !== "string" || !["maxElapsedMs", "signal"].includes(key) || !("value" in field) || !field.enumerable) throw new Error("Invalid persistent reduction replay option");
  }
  const maxElapsedMs = Object.hasOwn(value, "maxElapsedMs") ? value.maxElapsedMs! : 60000;
  if (!Number.isSafeInteger(maxElapsedMs) || maxElapsedMs < 1 || maxElapsedMs > 60000) throw new Error("Persistent reduction replay maxElapsedMs must be 1..60000");
  if (Object.hasOwn(value, "signal") && !(value.signal instanceof AbortSignal)) throw new Error("Invalid persistent reduction replay AbortSignal");
  return { maxElapsedMs, signal: value.signal };
}

/**
 * The injected evaluator is a trusted in-process test seam, unavailable to the
 * command or saved evidence. Audits and detaches all evidence before invocation.
 * Replaying the saved cases does not reenact the old timing-driven stop schedule.
 */
export async function replayPersistentReduction(
  inputDirectory: string,
  identity: PersistentIdentity,
  outputDirectory: string,
  evaluate: OwnedPersistentEvaluator,
  configuration: PersistentReductionReplayOptions = {},
): Promise<PersistentReductionReplaySummary> {
  const bounded = options(configuration);
  if (typeof evaluate !== "function" || typeof outputDirectory !== "string" || !outputDirectory) throw new Error("Persistent reduction replay requires owned evaluator and new directory");
  const saved = readAuditedPersistentReduction(inputDirectory);
  const current = makePersistentArtifact(saved.input.sequence, identity, saved.input.limits, saved.input.result).identity;
  const changes = persistentIdentityChanges(saved.audit.identity, current);
  if (changes.length) throw new Error(`Persistent reduction replay requires exact build identity (${changes.join(", ")})`);
  const output = resolve(outputDirectory);
  mkdirSync(output);
  const write = (name: string, value: unknown): EvidenceFile => {
    const data = Buffer.from(JSON.stringify(value, null, 2) + "\n");
    if (data.length > PERSISTENT_FILE_BYTES) throw new Error("Persistent reduction replay evidence exceeds 1 MiB");
    writeFileSync(resolve(output, name), data, { flag: "wx" });
    return { artifact: name, sha256: persistentDigest(data), bytes: data.length };
  };
  const hashes = new Map(saved.audit.verifiedFiles.map(file => [file.file, file.sha256]));
  const rows: PersistentReductionReplayRow[] = saved.evaluations.map(record => ({ savedFile: record.file, savedSha256: hashes.get(record.file)!, savedEvaluatorInvoked: record.evaluatorInvoked,
    replayEvaluatorInvoked: false, state: record.evaluatorInvoked ? "not-replayed" : "saved-uninvoked", fresh: null, comparison: null }));
  const diagnostics = new Set<string>();
  if (rows.some(row => !row.savedEvaluatorInvoked)) diagnostics.add("persistent-reduction-replay-saved-uninvoked");
  const controller = new AbortController();
  const cancel = () => controller.abort();
  bounded.signal?.addEventListener("abort", cancel, { once: true });
  if (bounded.signal?.aborted) cancel();
  const deadline = performance.now() + bounded.maxElapsedMs;
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, bounded.maxElapsedMs);
  const stopped = () => {
    if (bounded.signal?.aborted) diagnostics.add("persistent-reduction-replay-interrupted");
    if (timedOut || performance.now() >= deadline) { diagnostics.add("persistent-reduction-replay-time-budget"); controller.abort(); }
    return controller.signal.aborted;
  };
  const interruption = () => incompletePersistentResult(timedOut || performance.now() >= deadline ? "worker-timeout" : "worker-interrupted", "Persistent reduction execution replay stopped; pending evidence is incomplete");
  try {
    for (const [index, record] of saved.evaluations.entries()) {
      if (stopped()) break;
      if (!record.evaluatorInvoked) continue;
      const row = rows[index];
      let abort: (() => void) | undefined;
      let result: PersistentResult;
      try {
        const cancelled = new Promise<PersistentResult>(resolve => { abort = () => resolve(interruption()); controller.signal.addEventListener("abort", abort, { once: true }); });
        const work = Promise.resolve().then(async () => {
          if (stopped()) return interruption();
          row.replayEvaluatorInvoked = true;
          try {
            // Exact saved limits. The independent overall deadline may cancel
            // execution; it cannot masquerade as a replay under changed limits.
            const value = await evaluate(structuredClone(record.artifact.sequence), { ...record.artifact.limits }, controller.signal);
            return validatePersistentResult(record.artifact.sequence, value);
          } catch { return incompletePersistentResult("persistent-protocol", "Invalid or thrown persistent reduction replay evaluator result"); }
        });
        result = await Promise.race([cancelled, work]);
        if (stopped()) result = interruption();
      } finally { if (abort) controller.signal.removeEventListener("abort", abort); }
      row.fresh = write(`replay-${String(index + 1).padStart(4, "0")}.json`, makePersistentArtifact(record.artifact.sequence, current, record.artifact.limits, result));
      row.comparison = comparePersistentReductionReplayResults(record.artifact.result, result);
      if (record.artifact.result.status === "incomplete") diagnostics.add("persistent-reduction-replay-saved-incomplete");
      if (result.status === "incomplete") diagnostics.add("persistent-reduction-replay-evaluation-incomplete");
      if (record.artifact.result.status === "incomplete" || result.status === "incomplete") row.state = "incomplete";
      else if (!row.comparison.exactEvidenceMatch) { row.state = "drift"; diagnostics.add("persistent-reduction-replay-result-drift"); }
      else row.state = "matched";
      // A changed result must never license continuing along an old accepted
      // reduction history. Outstanding invocations remain explicitly unexecuted.
      if (row.state !== "matched" || stopped()) break;
    }
    stopped();
    const exactEvidenceMatched = rows.every(row => row.state === "matched") && !diagnostics.size;
    const source = rows.find(row => row.savedFile === saved.finalSourceArtifact);
    const summary: PersistentReductionReplaySummary = { schemaVersion: "nightshade-persistent-reduction-execution-replay-1", scope: "saved-owned-fixture-invocations-only", identity: current,
      savedSummarySha256: saved.audit.summarySha256, savedFiles: saved.audit.verifiedFiles, savedReductionStatus: saved.audit.reductionStatus, savedReductionDiagnostics: saved.audit.diagnostics,
      savedFinalStatus: saved.audit.final ? "failed" : null, maxElapsedMs: bounded.maxElapsedMs, replayStatus: exactEvidenceMatched ? "complete" : "incomplete", diagnostics: [...diagnostics].sort(),
      invocations: rows.filter(row => row.replayEvaluatorInvoked).length, recordedInvocations: rows.filter(row => row.savedEvaluatorInvoked).length, exactEvidenceMatched, rows,
      finalSource: saved.finalSourceArtifact ? { savedFile: saved.finalSourceArtifact, replayArtifact: source?.fresh?.artifact ?? null, matched: source?.state === "matched" } : null };
    write("summary.json", summary);
    return structuredClone(summary);
  } finally { clearTimeout(timer); bounded.signal?.removeEventListener("abort", cancel); }
}

export async function persistentReductionReplayMain(args = process.argv.slice(2)): Promise<number> {
  if (args.length === 1 && args[0] === "--help") {
    console.log("Owned persistent reduction execution replay: --replay REDUCTION_DIRECTORY --output NEW_DIRECTORY [--max-elapsed-ms 1..60000]\nAudits first; requires pinned COMPACTC_TEST/COMPACT_RUNTIME_TEST and exact build identity. Reexecutes saved invoked cases with exact saved limits. No build comparison or failure injection.\nExit 1: complete matching replay of a complete reduction retaining a failure; 2: incomplete, saved refusal/incompleteness, invalid input or drift. --help exits 0.");
    return 0;
  }
  const flags = new Map<string, string>();
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (!["--replay", "--output", "--max-elapsed-ms"].includes(flag) || flags.has(flag) || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error(`Invalid persistent reduction replay argument ${flag}`);
    flags.set(flag, args[++index]);
  }
  if (!flags.has("--replay") || !flags.has("--output")) throw new Error("Require --replay REDUCTION_DIRECTORY and new --output directory");
  const raw = flags.get("--max-elapsed-ms");
  if (raw !== undefined && !/^\d+$/.test(raw)) throw new Error("Invalid replay elapsed budget");
  const bounded = options({ maxElapsedMs: raw === undefined ? 60000 : Number(raw) });
  if (!process.env.COMPACTC_TEST || !process.env.COMPACT_RUNTIME_TEST) throw new Error("Pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST inputs are mandatory");
  const compiler = resolve(process.env.COMPACTC_TEST), runtime = resolve(process.env.COMPACT_RUNTIME_TEST);
  const identity = persistentBuildIdentity(compiler, runtime);
  const controller = new AbortController(), abort = () => controller.abort();
  process.once("SIGINT", abort); process.once("SIGTERM", abort);
  try {
    const result = await replayPersistentReduction(flags.get("--replay")!, identity, flags.get("--output")!, (sequence, limits, signal) => runPersistentSequenceIsolated(sequence, compiler, runtime, limits, signal), { maxElapsedMs: bounded.maxElapsedMs, signal: controller.signal });
    console.log(`${result.replayStatus}; ${result.invocations}/${result.recordedInvocations} replay invocations; saved reduction ${result.savedReductionStatus}; ${result.diagnostics.join(", ") || "recorded case evidence matched"}`);
    return result.replayStatus === "complete" && result.savedReductionStatus === "complete" && result.savedFinalStatus === "failed" ? 1 : 2;
  } finally { process.removeListener("SIGINT", abort); process.removeListener("SIGTERM", abort); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await persistentReductionReplayMain(); }
  catch (error) { console.error(error instanceof Error ? error.message : "Persistent reduction replay failed"); process.exitCode = 2; }
}
