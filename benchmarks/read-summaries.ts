import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { arch, cpus, loadavg, platform, release, tmpdir, totalmem } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { AnalysisFacts, Dataflow, Program } from "../src/index.js";
import { validateWithCompiler } from "../src/compiler/index.js";
import { analyzerIdentity } from "./identity.js";

type Mode = "cached" | "uncached";

interface Sample {
  frontendMs: number;
  analysisMs: number;
  peakRssMiB: number;
  complete: boolean;
  observationSha256: string;
  diagnostics: AnalysisFacts["diagnostics"];
  metrics: AnalysisFacts["metrics"];
}

interface Attempt {
  mode: Mode;
  repetition: number;
  order: number;
  startedAt: string;
  wallMs: number;
  loadBefore: number[];
  loadAfter: number[];
  exitStatus: number | null;
  signal: string | null;
  error?: string;
  stderr: string;
  invalidStdout?: string;
  sample?: Sample;
}

const limits = { maxSteps: 20000, maxPaths: 256, maxValues: 50000, workerHeapMiB: 384, workerTimeoutMs: 30000, workerOutputBytes: 1024 * 1024, maximumPeakRssMiB: 512, maximumAnalysisMs: 10000 };
const prelude = "pragma language_version >= 0.26.0; import CompactStandardLibrary; ";
const workloads = [
  {
    name: "derived-scalar-reads-128", expectedReadSummaryHits: 127, repeatedCalls: 128,
    source: `${prelude}export ledger stored: Field; circuit derive(): Bytes<32> { const hash0 = persistentHash<Field>(stored); ${Array.from({ length: 8 }, (_, index) => `const hash${index + 1} = persistentHash<Bytes<32>>(hash${index});`).join(" ")} return hash8; } export circuit entry(): Bytes<32> { for (const iteration of 0..127) { derive(); } return derive(); }`,
  },
  {
    name: "nested-private-query-sinks-128", expectedReadSummaryHits: 128, repeatedCalls: 128,
    source: `${prelude}export ledger seen: Set<Field>; export ledger table: Map<Field,Field>; circuit query(key: Field): [Boolean,Boolean] { return [seen.member(disclose(key)),table.member(disclose(key))]; } circuit nested(key: Field): [Boolean,Boolean] { query(key); return query(key); } export circuit entry(key: Field): [Boolean,Boolean] { for (const iteration of 0..127) { nested(key); } return nested(key); }`,
  },
  {
    name: "reads-between-unrelated-writes-128", expectedReadSummaryHits: 127, repeatedCalls: 128,
    source: `${prelude}export ledger stored: Field; export ledger other: Field; circuit read(): Field { return stored; } export circuit entry(value: Field): Field { for (const iteration of 0..127) { read(); other = disclose(value); } return read(); }`,
  },
];

function worker(source: string, mode: Mode): void {
  const start = performance.now();
  const program = new Program(source);
  const frontendMs = performance.now() - start;
  const analysisStarted = performance.now();
  const facts = new Dataflow(program, limits.maxSteps, limits.maxPaths, limits.maxValues, "instructions", mode === "cached", false).analyze();
  const analysisMs = performance.now() - analysisStarted;
  const observations = JSON.stringify({ paths: facts.paths, failedAssertions: facts.failedAssertions, completedEntries: facts.completedEntries }, (_, value) => value instanceof Set ? [...value].sort() : value);
  const sample: Sample = {
    frontendMs, analysisMs, peakRssMiB: process.resourceUsage().maxRSS / 1024,
    complete: facts.diagnostics.length === 0 && facts.completedEntries.length === program.entries.length,
    observationSha256: createHash("sha256").update(observations).digest("hex"),
    diagnostics: facts.diagnostics, metrics: facts.metrics,
  };
  console.log(JSON.stringify(sample));
}

function measure(source: string, mode: Mode, repetition: number, order: number): Attempt {
  const startedAt = new Date().toISOString();
  const loadBefore = loadavg();
  const start = performance.now();
  const child = spawnSync(process.execPath, [`--max-old-space-size=${limits.workerHeapMiB}`, fileURLToPath(import.meta.url), "--worker", source, mode], { encoding: "utf8", timeout: limits.workerTimeoutMs, maxBuffer: limits.workerOutputBytes, windowsHide: true });
  const attempt: Attempt = { mode, repetition, order, startedAt, wallMs: performance.now() - start, loadBefore, loadAfter: loadavg(), exitStatus: child.status, signal: child.signal, error: child.error?.message, stderr: child.stderr ?? "" };
  if (child.status !== 0 || child.error) {
    attempt.invalidStdout = child.stdout ?? "";
    return attempt;
  }
  try {
    const sample = JSON.parse(child.stdout) as Sample;
    if (typeof sample.complete !== "boolean" || !/^[a-f0-9]{64}$/.test(sample.observationSha256) || !Array.isArray(sample.diagnostics) || !sample.metrics || ![sample.frontendMs, sample.analysisMs, sample.peakRssMiB, sample.metrics.readSummaryHits, sample.metrics.statefulSummaryHits, sample.metrics.summaryHits].every(value => Number.isFinite(value) && value >= 0)) throw new Error("Worker output is not a valid benchmark sample");
    attempt.sample = sample;
  } catch (error) {
    attempt.error = error instanceof Error ? error.message : String(error);
    attempt.invalidStdout = child.stdout;
  }
  return attempt;
}

function summarize(attempts: Attempt[]) {
  const samples = attempts.flatMap(attempt => attempt.sample ? [attempt.sample] : []);
  return {
    medianAnalysisMs: samples.length === 5 ? samples.map(sample => sample.analysisMs).sort((first, second) => first - second)[2] : null,
    peakRssMiB: samples.length ? Math.max(...samples.map(sample => sample.peakRssMiB)) : null,
    attempts,
  };
}

const args = process.argv.slice(2);
if (args[0] === "--worker") {
  if (args.length !== 3 || !["cached", "uncached"].includes(args[2])) throw new Error("Invalid read-summary worker invocation");
  worker(args[1], args[2] as Mode);
} else {
  const checkOnly = args[0] === "--check-sources";
  if (checkOnly ? args.length !== 3 || args[1] !== "--compiler" : args.length !== 4 || args[0] !== "--output" || args[2] !== "--compiler") throw new Error("Use read-summaries --output NEW_FILE --compiler FILE, or --check-sources --compiler FILE");
  const compilerPath = resolve(args[checkOnly ? 2 : 3]);
  const output = checkOnly ? undefined : resolve(args[1]);
  if (output && existsSync(output)) throw new Error("Read-summary benchmark output already exists; preserve it and choose a new file");
  const temporary = mkdtempSync(resolve(tmpdir(), "nightshade-read-summary-benchmark-"));
  const loadBefore = loadavg();
  try {
    const rows = workloads.map(workload => {
      const source = resolve(temporary, "main.compact");
      writeFileSync(source, workload.source);
      const compiler = validateWithCompiler(compilerPath, source);
      const cachedAttempts: Attempt[] = [];
      const uncachedAttempts: Attempt[] = [];
      if (!checkOnly && compiler.valid) for (let repetition = 0; repetition < 5; repetition++) {
        const modes: Mode[] = repetition % 2 ? ["uncached", "cached"] : ["cached", "uncached"];
        for (const [order, mode] of modes.entries()) (mode === "cached" ? cachedAttempts : uncachedAttempts).push(measure(source, mode, repetition, order));
      }
      const cached = summarize(cachedAttempts);
      const uncached = summarize(uncachedAttempts);
      const attempts = [...cachedAttempts, ...uncachedAttempts];
      const samples = attempts.flatMap(attempt => attempt.sample ? [attempt.sample] : []);
      const observationsMatch = samples.length === 10 && samples.every(sample => sample.observationSha256 === samples[0].observationSha256);
      const failures: string[] = [];
      if (!compiler.valid) failures.push("compiler-validation-failed");
      if (!checkOnly) {
        if (samples.length !== 10) failures.push("missing-or-failed-worker-samples");
        if (!observationsMatch) failures.push("observation-equivalence-unconfirmed");
        if (samples.some(sample => !sample.complete || sample.diagnostics.length)) failures.push("incomplete-analysis");
        if (samples.some(sample => sample.peakRssMiB >= limits.maximumPeakRssMiB || sample.analysisMs >= limits.maximumAnalysisMs)) failures.push("resource-threshold-exceeded");
        if (cachedAttempts.some(({ sample }) => sample && (sample.metrics.readSummaryHits !== workload.expectedReadSummaryHits || sample.metrics.summaryHits !== sample.metrics.readSummaryHits || sample.metrics.statefulSummaryHits !== 0)) || uncachedAttempts.some(({ sample }) => sample && (sample.metrics.summaryHits !== 0 || sample.metrics.readSummaryHits !== 0 || sample.metrics.statefulSummaryHits !== 0))) failures.push("unexpected-summary-reuse");
      }
      const qualified = !checkOnly && failures.length === 0;
      return { workload: workload.name, source: workload.source, sourceSha256: createHash("sha256").update(workload.source).digest("hex"), repeatedCalls: workload.repeatedCalls, expectedReadSummaryHits: workload.expectedReadSummaryHits, compiler, qualified, failures, observationsMatch, cached, uncached, medianAnalysisSpeedup: qualified && cached.medianAnalysisMs && uncached.medianAnalysisMs !== null ? uncached.medianAnalysisMs / cached.medianAnalysisMs : null };
    });
    if (output) writeFileSync(output, JSON.stringify({
      version: "read-summaries-1", analyzerSourceAndLockSha256: analyzerIdentity(), measuredAt: new Date().toISOString(),
      environment: { node: process.version, platform: platform(), arch: arch(), kernel: release(), cpu: cpus()[0]?.model, cpuCount: cpus().length, totalMemoryMiB: totalmem() / 1024 / 1024, loadBefore, loadAfter: loadavg() },
      limits, compilerPath,
      methodology: "Five fresh processes per mode/workload, alternating first mode each repetition. Both modes disable mutation summaries; the cached mode enables the full summary toggle, while uncached disables all summaries. Sources contain no separate pure helper circuits, and qualification requires every cached hit to be a read-summary hit. Each entry invokes its read helper 128 times; the nested query workload performs two leaf calls per helper invocation and exercises a nested hit while recording the outer helper. Compare all successful paths, failed assertions and completed entries including full traces, without semantic normalization. Analysis timings include lazy instruction lowering and exclude process startup/frontend. Worker heap limit is a V8 setting, not an RSS cap or security sandbox. Raw process attempts retain crashes, diagnostics and timeout/output errors. Synthetic optimization workloads, not field throughput or security accuracy; different hardware establishes a new baseline and does not clear historical performance gates.",
      rows,
    }, null, 2) + "\n", { flag: "wx" });
    console.log(JSON.stringify(checkOnly
      ? { mode: "compiler-acceptance-only", rows: rows.map(({ workload, sourceSha256, compiler }) => ({ workload, sourceSha256, compiler })) }
      : rows.map(({ source, cached, uncached, ...row }) => ({ ...row, cached: { medianAnalysisMs: cached.medianAnalysisMs, peakRssMiB: cached.peakRssMiB }, uncached: { medianAnalysisMs: uncached.medianAnalysisMs, peakRssMiB: uncached.peakRssMiB } })), null, 2));
    if (rows.some(row => checkOnly ? !row.compiler.valid : !row.qualified)) process.exitCode = 1;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}
