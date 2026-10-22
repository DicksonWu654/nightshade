import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { arch, cpus, loadavg, platform, release, tmpdir, totalmem } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { isDeepStrictEqual } from "node:util";
import { AnalysisFacts, Dataflow, Program } from "../src/index.js";
import { BranchMutationEligibility } from "../src/analysis/summaries.js";
import { branchJournalEvents, type BranchMutationSummary } from "../src/dataflow/summaries.js";
import { validateWithCompiler } from "../src/compiler/index.js";
import { analyzerIdentity } from "./identity.js";

type Mode = "cached" | "uncached";
interface Workload { name: string; entries: number; writesPerArm: number; requireLowerSteps: boolean; source: string }
interface Sample {
  frontendMs: number; analysisMs: number; peakRssMiB: number; complete: boolean;
  observationSha256: string; diagnostics: AnalysisFacts["diagnostics"]; metrics: AnalysisFacts["metrics"];
  qualification: { failures: string[]; paths: number; writes: number; branchSummaries: number; alternatives: number[] };
}
interface Attempt {
  mode: Mode; repetition: number; order: number; startedAt: string; wallMs: number;
  loadBefore: number[]; loadAfter: number[]; exitStatus: number | null; signal: string | null;
  error?: string; stderr: string; invalidStdout?: string; sample?: Sample;
}
const limits = Object.freeze({ maxSteps: 20000, maxPaths: 256, maxValues: 50000, workerHeapMiB: 384, workerTimeoutMs: 30000, workerOutputBytes: 1048576, maximumPeakRssMiB: 512, maximumAnalysisMs: 10000 });
const digest = (bytes: string | Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const hashFile = (path: string): string => digest(readFileSync(path));

function source(entries: number, writes: number): string {
  return `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger first: Field;
export ledger second: Field;
circuit select(flag: Boolean, value: Field): [] {
  if (disclose(flag)) {
${Array.from({ length: writes }, () => "    first = disclose(value);").join("\n")}
  } else {
${Array.from({ length: writes }, () => "    second = disclose(value);").join("\n")}
  }
}
${Array.from({ length: entries }, (_, index) => `export circuit entry${index}(a: Uint<8>, b: Uint<8>, value: Field): [] {
  const flag = a < b;
  select(flag,value);
  select(flag,value);
}`).join("\n")}
`;
}
const workloads: Workload[] = [
  { name: "unknown-two-arm-small-1x1", entries: 1, writesPerArm: 1, requireLowerSteps: false, source: source(1, 1) },
  { name: "unknown-two-arm-primary-16x8", entries: 16, writesPerArm: 8, requireLowerSteps: true, source: source(16, 8) },
];

/** The trusted benchmark observes private cache shape; no product metric or replay behavior changes. */
function qualify(program: Program, facts: AnalysisFacts, dataflow: Dataflow, workload: Workload, mode: Mode, path: string): Sample["qualification"] {
  const failures = new Set<string>();
  const require = (condition: unknown, failure: string): void => { if (!condition) failures.add(failure); };
  require(program.entries.length === workload.entries && program.functions.size === workload.entries + 1, "unexpected-circuit-shape");
  require(facts.failedAssertions.length === 0, "unexpected-failed-assertion");
  require(isDeepStrictEqual(facts.completedEntries, program.entries), "incomplete-entry-coverage");
  require(facts.paths.length === 4 * workload.entries, "unexpected-abstract-path-count");
  const helper = [...program.functions.values()].find(fn => fn.symbol.name === "select");
  if (!helper) return { failures: ["missing-owned-helper"], paths: facts.paths.length, writes: 0, branchSummaries: 0, alternatives: [] };
  const plan = new BranchMutationEligibility(program).plan(helper.symbol.id);
  require(plan?.assignments === 2 * workload.writesPerArm, "branch-helper-ineligible");
  const conditionSpan = plan ? program.instructionCFG(helper.symbol.id).nodes[plan.instructions.branch].span : undefined;
  const expectedStarts = new Map<string, number[]>();
  for (const name of ["first", "second"]) {
    const text = `${name} = disclose(value)`;
    const starts: number[] = [];
    let at = workload.source.indexOf(text);
    while (at >= 0) { starts.push(at); at = workload.source.indexOf(text, at + text.length); }
    require(starts.length === workload.writesPerArm, "unexpected-rendered-assignment-count");
    expectedStarts.set(name, starts);
  }
  const sourcesAcrossEntries = new Set<string>();
  let writes = 0;
  for (const [entryIndex, entry] of program.entries.entries()) {
    const fn = program.functions.get(entry)!;
    require(fn.symbol.name === `entry${entryIndex}`, "unexpected-entry-order");
    require(isDeepStrictEqual(fn.declaration.parameters.map(parameter => [parameter.name, parameter.type]), [["a", "Uint<8>"], ["b", "Uint<8>"], ["value", "Field"]]), "unexpected-entry-signature");
    const parameters = new Map(fn.declaration.parameters.map(parameter => [parameter.name, parameter]));
    const ids = new Map<string, Set<string>>([["a", new Set()], ["b", new Set()], ["value", new Set()]]);
    const paths = facts.paths.filter(candidate => candidate.entry === entry);
    require(paths.length === 4, "entry-alternatives-missing");
    const combinations: string[] = [];
    for (const result of paths) {
      require(result.bindings.length === 0, "unexpected-binding");
      require(result.writes.length === 2 * workload.writesPerArm, "unexpected-write-count");
      require(result.sinks.length === result.writes.length && result.sinks.every(sink => sink.kind === "ledger-write"), "unexpected-public-sink-count-or-kind");
      require(result.path.length === 2 && result.path.every(step => step.kind === "branch" && isDeepStrictEqual(step.location, conditionSpan)), "unexpected-branch-trace");
      const rootNames = result.writes.map(write => program.symbols.get(write.ledger)?.name);
      const first = rootNames[0], second = rootNames[workload.writesPerArm];
      combinations.push(`${first},${second}`);
      for (const [index, write] of result.writes.entries()) {
        writes++;
        const name = index < workload.writesPerArm ? first : second;
        require((name === "first" || name === "second") && rootNames[index] === name, "mixed-mutually-exclusive-arm-effects");
        const expectedStart = expectedStarts.get(name ?? "")?.[index % workload.writesPerArm];
        const text = `${name} = disclose(value)`;
        require(write.location.file === path && write.location.start === expectedStart && write.location.end === (expectedStart ?? -1) + text.length, "wrong-assignment-source-span");
        require(write.region.length === 0 && isDeepStrictEqual(write.callPath, [entry, helper.symbol.id]), "wrong-write-region-or-call-path");
        require(isDeepStrictEqual(write.after.flows.map(flow => flow.source.name).sort(), ["a", "b", "value"]), "wrong-write-source-set");
        for (const flow of write.after.flows) {
          const parameter = parameters.get(flow.source.name);
          require(parameter && flow.source.kind === "entry-parameter" && flow.source.symbol === parameter.symbol && isDeepStrictEqual(flow.source.location, parameter.span), "wrong-private-source-origin");
          require(flow.form === (flow.source.name === "value" ? "raw" : "derived"), "wrong-private-source-form");
          require(flow.trace.length > 0 && flow.trace[0].kind === "source" && flow.trace[0].label === flow.source.name && isDeepStrictEqual(flow.trace[0].location, parameter?.span), "wrong-private-source-trace");
          ids.get(flow.source.name)?.add(flow.source.id);
        }
        const sink = result.sinks[index];
        require(sink && sink.name === name && isDeepStrictEqual(sink.location, write.location) && isDeepStrictEqual(sink.callPath, write.callPath) && isDeepStrictEqual(sink.value, write.after), "write-publication-mismatch");
      }
    }
    require(isDeepStrictEqual(combinations.sort(), ["first,first", "first,second", "second,first", "second,second"]), "abstract-arm-combinations-mismatch");
    const entrySources = [...ids.values()].flatMap(group => [...group]);
    require([...ids.values()].every(group => group.size === 1) && new Set(entrySources).size === 3, "entry-source-identity-drift");
    require(entrySources.every(id => !sourcesAcrossEntries.has(id)), "private-sources-conflated-across-entries");
    for (const id of entrySources) sourcesAcrossEntries.add(id);
  }
  require(writes === workload.entries * 4 * 2 * workload.writesPerArm, "total-write-count-mismatch");
  const summaries = (dataflow as unknown as { branchSummaries: ReadonlyMap<string, BranchMutationSummary> }).branchSummaries;
  const alternatives: number[] = [];
  require(summaries instanceof Map, "branch-cache-observation-unavailable");
  if (summaries instanceof Map) for (const summary of (summaries as ReadonlyMap<string, BranchMutationSummary>).values()) {
    alternatives.push(summary.alternatives.length);
    const choices = summary.alternatives.map(alternative => branchJournalEvents(alternative.tail)?.filter(effect => effect.kind === "choice"));
    require(choices.length === 2 && choices.every(events => events?.length === 1), "cached-two-arm-coverage-missing");
    const selected: boolean[] = [];
    for (const events of choices) for (const event of events ?? []) {
      if (event.kind !== "choice") continue;
      selected.push(event.selected);
      require(event.value.constant === undefined && event.value.identity === undefined && event.value.comparison === undefined, "cached-condition-not-unknown-identityless");
      require(isDeepStrictEqual(event.value.flows.map(flow => flow.source.name).sort(), ["a", "b"]), "cached-condition-provenance-mismatch");
    }
    require(isDeepStrictEqual(selected.sort(), [false, true]), "cached-choice-alternatives-conflated");
  }
  const expectedHits = mode === "cached" ? workload.entries * 2 : 0;
  const expectedEntries = mode === "cached" ? workload.entries : 0;
  require(facts.metrics.summaryHits === expectedHits && facts.metrics.statefulSummaryHits === expectedHits && facts.metrics.readSummaryHits === 0, "unexpected-summary-reuse");
  require(facts.metrics.summaryEntries === expectedEntries && summaries?.size === expectedEntries, "unexpected-summary-entry-count");
  require(facts.metrics.summaryEntries <= 256 && facts.metrics.summaryEffects <= 4096, "shared-summary-bounds-exceeded");
  require(mode === "cached" ? facts.metrics.summaryEffects > 0 : facts.metrics.summaryEffects === 0, "unexpected-retained-effects");
  return { failures: [...failures].sort(), paths: facts.paths.length, writes, branchSummaries: summaries?.size ?? 0, alternatives };
}

function worker(path: string, mode: Mode, workload: Workload): void {
  if (readFileSync(path, "utf8") !== workload.source) throw new Error("Benchmark worker accepts only its fixed rendered workload");
  const start = performance.now(), program = new Program(path), frontendMs = performance.now() - start;
  const dataflow = new Dataflow(program, limits.maxSteps, limits.maxPaths, limits.maxValues, "instructions", true, mode === "cached");
  const analysisStarted = performance.now(), facts = dataflow.analyze(), analysisMs = performance.now() - analysisStarted;
  const observations = JSON.stringify({ paths: facts.paths, failedAssertions: facts.failedAssertions, completedEntries: facts.completedEntries }, (_, value) => value instanceof Set ? [...value].sort() : value);
  const sample: Sample = { frontendMs, analysisMs, peakRssMiB: process.resourceUsage().maxRSS / 1024,
    complete: facts.diagnostics.length === 0 && facts.completedEntries.length === program.entries.length,
    observationSha256: digest(observations), diagnostics: facts.diagnostics, metrics: facts.metrics,
    qualification: qualify(program, facts, dataflow, workload, mode, path) };
  process.stdout.write(JSON.stringify(sample));
}

function measure(path: string, workload: Workload, mode: Mode, repetition: number, order: number): Attempt {
  const startedAt = new Date().toISOString(), loadBefore = loadavg(), start = performance.now();
  const child = spawnSync(process.execPath, [`--max-old-space-size=${limits.workerHeapMiB}`, fileURLToPath(import.meta.url), "--worker", path, mode, workload.name], { encoding: "utf8", timeout: limits.workerTimeoutMs, maxBuffer: limits.workerOutputBytes, windowsHide: true });
  const attempt: Attempt = { mode, repetition, order, startedAt, wallMs: performance.now() - start, loadBefore, loadAfter: loadavg(), exitStatus: child.status, signal: child.signal, error: child.error?.message, stderr: child.stderr ?? "" };
  if (child.status !== 0 || child.error) { attempt.invalidStdout = child.stdout ?? ""; return attempt; }
  try {
    const sample = JSON.parse(child.stdout) as Sample;
    if (typeof sample.complete !== "boolean" || typeof sample.observationSha256 !== "string" || sample.observationSha256.length !== 64 || !/^[a-f0-9]{64}$/.test(sample.observationSha256) || !Array.isArray(sample.diagnostics) || !sample.metrics || !sample.qualification
      || ![sample.frontendMs, sample.analysisMs, sample.peakRssMiB, sample.metrics.steps, sample.metrics.summaryHits, sample.metrics.statefulSummaryHits, sample.metrics.readSummaryHits, sample.metrics.summaryEntries, sample.metrics.summaryEffects, sample.qualification.paths, sample.qualification.writes, sample.qualification.branchSummaries].every(value => Number.isFinite(value) && value >= 0)
      || !Array.isArray(sample.qualification.failures) || sample.qualification.failures.some(value => typeof value !== "string") || !Array.isArray(sample.qualification.alternatives) || sample.qualification.alternatives.some(value => !Number.isSafeInteger(value) || value < 0)) throw new Error("Invalid branching-summary worker sample");
    attempt.sample = sample;
  } catch (error) { attempt.error = error instanceof Error ? error.message : String(error); attempt.invalidStdout = child.stdout; }
  return attempt;
}
function summarize(attempts: Attempt[]) {
  const samples = attempts.flatMap(attempt => attempt.sample ? [attempt.sample] : []);
  return { medianAnalysisMs: samples.length === 5 ? samples.map(sample => sample.analysisMs).sort((left, right) => left - right)[2] : null,
    peakRssMiB: samples.length ? Math.max(...samples.map(sample => sample.peakRssMiB)) : null, attempts };
}
function identity(compiler: string) {
  return { analyzerSourceAndLockSha256: analyzerIdentity(), compilerSha256: hashFile(compiler),
    compilerDistribution: ["compactc.bin", "zkir", "zkir-v3"].map(name => ({ name, sha256: hashFile(resolve(dirname(compiler), name)) })),
    benchmarkSourceSha256: hashFile("benchmarks/branching-summaries.ts"), benchmarkBuildSha256: hashFile(fileURLToPath(import.meta.url)),
    changedCoreBuilds: ["dist/src/analysis/summaries.js", "dist/src/dataflow/summaries.js", "dist/src/dataflow/index.js"].map(path => ({ path, sha256: hashFile(path) })) };
}

const args = process.argv.slice(2);
if (args[0] === "--worker") {
  const workload = workloads.find(item => item.name === args[3]);
  if (args.length !== 4 || !["cached", "uncached"].includes(args[2]) || !workload) throw new Error("Invalid branching-summary worker invocation");
  worker(resolve(args[1]), args[2] as Mode, workload);
} else {
  const checkOnly = args[0] === "--check-sources";
  if (checkOnly ? args.length !== 3 || args[1] !== "--compiler" : args.length !== 4 || args[0] !== "--output" || args[2] !== "--compiler") throw new Error("Use branching-summaries --output NEW_FILE --compiler FILE, or --check-sources --compiler FILE");
  const compilerPath = resolve(args[checkOnly ? 2 : 3]), output = checkOnly ? undefined : resolve(args[1]);
  if (output && existsSync(output)) throw new Error("Branching-summary benchmark output already exists; preserve it and choose a new file");
  const beforeIdentity = identity(compilerPath), temporary = mkdtempSync(resolve(tmpdir(), "nightshade-branch-summary-benchmark-")), loadBefore = loadavg();
  try {
    const rows = workloads.map(workload => {
      const path = resolve(temporary, "main.compact"); writeFileSync(path, workload.source);
      const compiler = validateWithCompiler(compilerPath, path);
      const cachedAttempts: Attempt[] = [], uncachedAttempts: Attempt[] = [];
      if (!checkOnly && compiler.valid) for (let repetition = 0; repetition < 5; repetition++) {
        const modes: Mode[] = repetition % 2 ? ["uncached", "cached"] : ["cached", "uncached"];
        for (const [order, mode] of modes.entries()) (mode === "cached" ? cachedAttempts : uncachedAttempts).push(measure(path, workload, mode, repetition, order));
      }
      const cached = summarize(cachedAttempts), uncached = summarize(uncachedAttempts), attempts = [...cachedAttempts, ...uncachedAttempts];
      const samples = attempts.flatMap(attempt => attempt.sample ? [attempt.sample] : []), failures = new Set<string>();
      const observationsMatch = samples.length === 10 && samples.every(sample => sample.observationSha256 === samples[0].observationSha256);
      if (!compiler.valid) failures.add("compiler-validation-failed");
      if (!checkOnly) {
        if (samples.length !== 10) failures.add("missing-or-failed-worker-samples");
        if (attempts.some(attempt => attempt.stderr)) failures.add("unexpected-worker-stderr");
        if (!observationsMatch) failures.add("full-observation-equivalence-unconfirmed");
        if (samples.some(sample => !sample.complete || sample.diagnostics.length)) failures.add("incomplete-analysis");
        if (samples.some(sample => sample.peakRssMiB >= limits.maximumPeakRssMiB || sample.analysisMs >= limits.maximumAnalysisMs)) failures.add("resource-threshold-exceeded");
        for (const sample of samples) for (const failure of sample.qualification.failures) failures.add(failure);
        if (workload.requireLowerSteps && cachedAttempts.some((attempt, index) => !attempt.sample || !uncachedAttempts[index]?.sample || attempt.sample.metrics.steps >= uncachedAttempts[index].sample!.metrics.steps)) failures.add("primary-charged-work-not-lower");
      }
      const qualified = !checkOnly && failures.size === 0;
      return { workload: workload.name, source: workload.source, sourceSha256: digest(workload.source), entries: workload.entries, writesPerArm: workload.writesPerArm, callsPerEntry: 2,
        expectedCachedHits: 2 * workload.entries, expectedPaths: 4 * workload.entries, expectedWritesPerPath: 2 * workload.writesPerArm, requireLowerSteps: workload.requireLowerSteps,
        compiler, qualified, failures: [...failures].sort(), observationsMatch, cached, uncached,
        medianAnalysisSpeedup: qualified && cached.medianAnalysisMs && uncached.medianAnalysisMs !== null ? uncached.medianAnalysisMs / cached.medianAnalysisMs : null };
    });
    let afterIdentity: ReturnType<typeof identity> | null = null, identityError: string | null = null;
    try { afterIdentity = identity(compilerPath); } catch (error) { identityError = error instanceof Error ? error.message : String(error); }
    const identityMatched = afterIdentity !== null && isDeepStrictEqual(beforeIdentity, afterIdentity);
    if (!identityMatched) for (const row of rows) { row.qualified = false; row.failures.push("benchmark-input-identity-drift-or-unavailable"); row.failures.sort(); row.medianAnalysisSpeedup = null; }
    if (output) writeFileSync(output, `${JSON.stringify({ version: "branch-summaries-1", ...beforeIdentity, measuredAt: new Date().toISOString(),
      environment: { node: process.version, platform: platform(), arch: arch(), kernel: release(), cpu: cpus()[0]?.model, cpuCount: cpus().length, totalMemoryMiB: totalmem() / 1024 / 1024, loadBefore, loadAfter: loadavg() },
      limits, compilerPath, postIdentity: { matched: identityMatched, identity: afterIdentity, error: identityError },
      methodology: "Owned compiler-valid single-diamond scalar helper; five fresh processes per mode/workload with alternating first mode. Both modes retain pure summaries; only stateful summaries differ. Sources contain no other helper candidates. The unsigned-ordering flag has private provenance but no Boolean identity in the current domain, allowing the second helper call on each first-call path to reuse a genuinely unknown two-arm cache. Four abstract histories per entry preserve the existing reference overapproximation; they are not four concrete executions or general correlated joins. Qualification checks source identities/spans, ordered writes and public sinks, complete trace observations, two stored alternatives and exact hits. The primary row uses sixteen independent entries with eight assignments per arm, retaining ordinary per-entry budgets. Timed analysis includes lazy lowering but excludes startup, frontend and post-analysis qualification. Raw attempts retain failures/load; the heap limit is a V8 setting, not an RSS cap or sandbox. Lower charged work is required only for the primary row; timing speedup is measured without a speedup acceptance threshold. This separate host baseline does not replace historical effects-2 thresholds or establish release readiness.", rows }, null, 2)}\n`, { flag: "wx" });
    console.log(JSON.stringify(checkOnly ? { mode: "compiler-acceptance-only", identityMatched, rows: rows.map(({ workload, sourceSha256, compiler }) => ({ workload, sourceSha256, compiler })) }
      : rows.map(({ source, cached, uncached, ...row }) => ({ ...row, cached: { medianAnalysisMs: cached.medianAnalysisMs, peakRssMiB: cached.peakRssMiB }, uncached: { medianAnalysisMs: uncached.medianAnalysisMs, peakRssMiB: uncached.peakRssMiB } })), null, 2));
    if (!identityMatched || rows.some(row => checkOnly ? !row.compiler.valid : !row.qualified)) process.exitCode = 1;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}
