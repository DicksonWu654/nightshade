import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, lstatSync, mkdtempSync, openSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { arch, cpus, loadavg, platform, release, tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { analyzeCounterPredicates, type CounterScanResult } from "../src/analysis/counter-scan.js";
import { validateWithCompiler, type CompilerValidation } from "../src/compiler/index.js";
import { Dataflow } from "../src/dataflow/index.js";
import { detectors, type Finding } from "../src/detectors/index.js";
import { scanFile } from "../src/index.js";
import type { Diagnostic } from "../src/model.js";
import { GRAMMAR_BUILD, GRAMMAR_REVISION } from "../src/parser/index.js";
import { resolvePolicies, type Policies } from "../src/policies.js";
import { Program } from "../src/semantic/index.js";
import { SEMANTIC_PROFILE } from "../src/semantic/profile.js";
import { analyzerIdentity } from "./identity.js";

type Mode = "scan-file" | "internal-counter-predicates" | "public-counter-predicates";
type Size = 4 | 6 | 10;
type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
const allModes: Mode[] = ["scan-file", "internal-counter-predicates", "public-counter-predicates"];
const sizes: Size[] = [4, 6, 10];
const selectedDetectors = detectors.map(detector => detector.id);
const workerLimits = { timeoutMs: 30000, maxOutputBytes: 1024 * 1024, maxOldSpaceMiB: 384 };
const bounds = { totalMsExclusive: 10000, peakRssMiBExclusive: 512 };
const baselinePath = "benchmarks/effects-server-counter-query-consumers.json";
const harnessPath = "benchmarks/counter-predicates.ts";
const temporaryPrefix = "nightshade-counter-predicates-";
const digest = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");
const errorText = (error: unknown): string => error instanceof Error ? `${error.name}: ${error.message}` : String(error);

// Keep these bytes identical to the effects-2 stateful-branches workloads.
const sourceFor = (size: Size): string => `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: size }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { ${Array.from({ length: size }, (_, index) => `if (disclose(flag${index})) { count.increment(1); }`).join(" ")} }`;
const policiesFor = (size: Size): Policies => ({ secrets: Array.from({ length: size }, (_, index) => ({ circuit: "entry", parameter: `flag${index}` })), authorization: [{ state: "count", guard: "entry" }] });

/** Preserve every finding field, array order and duplicate; normalize only this
 * harness's generated file/directory names and object-key ordering. */
function normalize(value: unknown, source: string): Json {
  if (typeof value === "string") return value.replaceAll(source, "main.compact").replaceAll(dirname(source), "$fixture");
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(item => normalize(item, source));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, normalize(item, source)]));
  throw new Error("Non-JSON benchmark observation");
}

interface MeasuredSample {
  outcome: "measured";
  mode: Mode;
  sourceSha256: string;
  status: "complete" | "incomplete";
  scope: string;
  selectedDetectors: string[];
  diagnostics: Json;
  diagnosticCodes: string[];
  findings: { normalization: "full-fields-owned-paths-1"; observations: Json; sha256: string; count: number; byDetector: Record<string, number> };
  exact: { pathCount: number; completedEntries: Json; completedEntryCount: number; attemptedEntries: Json };
  predicates: null | { coverage: Json; covered: number; incomplete: number; byMethod: Record<string, number>; work: CounterScanResult["work"]; certificates: Json; workPolicies: Json };
  timing: { frontendMs: number; analysisAndDetectorMs: number; totalMs: number };
  peakRssMiB: number;
}
interface FailedSample {
  outcome: "worker-failure";
  mode: Mode;
  diagnostic: { code: string; message: string };
  exitCode: number | null;
  signal: string | null;
  stderr: string;
  stdout: string;
}
type Sample = MeasuredSample | FailedSample;
interface ModeRow {
  mode: Mode;
  expectedStatus: "complete" | "incomplete";
  scope: string;
  samples: Sample[];
  medianMs: number | null;
  peakRssMiB: number | null;
}
interface Row {
  workload: string;
  sourceSha256: string;
  policies: Policies;
  compiler: CompilerValidation;
  order: Mode[][];
  modes: ModeRow[];
  fullFindingEquivalence: { status: "equal" | "different" | "unavailable" | "not-compared"; reason: string };
  violations: string[];
  qualified: boolean;
}

function observations(findings: Finding[], source: string): MeasuredSample["findings"] {
  const observed = normalize(findings, source);
  const byDetector = Object.fromEntries(selectedDetectors.map(id => [id, 0]));
  for (const finding of findings) byDetector[finding.detectorId] = (byDetector[finding.detectorId] ?? 0) + 1;
  return { normalization: "full-fields-owned-paths-1", observations: observed, sha256: digest(JSON.stringify(observed)), count: findings.length, byDetector };
}

function worker(mode: Mode, size: Size): MeasuredSample {
  const directory = realpathSync(process.cwd());
  if (dirname(directory) !== realpathSync(tmpdir()) || !new RegExp(`^${temporaryPrefix}[A-Za-z0-9]{6}$`).test(basename(directory))) throw new Error("Worker requires the harness-owned temporary directory");
  const source = resolve(directory, "main.compact");
  if (!lstatSync(source).isFile() || lstatSync(source).isSymbolicLink() || readFileSync(source, "utf8") !== sourceFor(size)) throw new Error("Worker accepts only the unchanged fixed owned workload");
  const policies = policiesFor(size);
  let findings: Finding[], diagnostics: Diagnostic[], result: MeasuredSample;
  if (mode !== "internal-counter-predicates") {
    const scan = scanFile(source, { policies, detectors: selectedDetectors, searchPaths: [], experimentalCounterQueries: mode === "public-counter-predicates" });
    if (scan.schemaVersion !== (mode === "public-counter-predicates" ? "1.7.0" : "1.6.0")) throw new Error("Public scan returned a different schema/mode");
    findings = scan.findings; diagnostics = scan.diagnostics;
    result = {
      outcome: "measured", mode, sourceSha256: digest(sourceFor(size)), status: scan.status, scope: scan.scope,
      selectedDetectors: scan.coverage.detectors, diagnostics: normalize(diagnostics, source), diagnosticCodes: diagnostics.map(item => item.code), findings: observations(findings, source),
      exact: { pathCount: scan.metrics.paths, completedEntries: normalize(scan.coverage.completedEntries, source), completedEntryCount: scan.coverage.completedEntries.length, attemptedEntries: normalize(scan.entrypoints, source) },
      predicates: null,
      timing: { frontendMs: scan.metrics.frontendMs, analysisAndDetectorMs: scan.metrics.analysisMs + scan.metrics.detectorMs, totalMs: scan.metrics.totalMs }, peakRssMiB: 0,
    };
    if (scan.schemaVersion === "1.7.0") {
      if (scan.analysis.mode !== "experimental-counter-queries" || scan.analysis.scope !== scan.scope || scan.analysis.contract !== "experimental-counter-scan-1"
        || scan.metrics.detectorMs !== 0) throw new Error("Public predicate contract/timing differs");
      const byMethod: Record<string, number> = {};
      for (const item of scan.analysis.coverage) byMethod[item.method] = (byMethod[item.method] ?? 0) + 1;
      const { preparation, findingChecks, expenditureKnown, ...query } = scan.analysis.queryWork;
      result.exact.attemptedEntries = normalize([...new Set(scan.analysis.coverage.filter(item => item.method === "exact").map(item => item.entry))], source);
      result.predicates = { coverage: normalize(scan.analysis.coverage, source), covered: scan.analysis.coverage.filter(item => item.status === "covered").length,
        incomplete: scan.analysis.coverage.filter(item => item.status !== "covered").length, byMethod,
        work: { preparation, query, findingChecks, queryExpenditureKnown: expenditureKnown }, certificates: null, workPolicies: normalize(scan.analysis.workPolicies, source) };
    }
  } else {
    const started = performance.now();
    const program = new Program(source, []);
    const configured = resolvePolicies(program, policies);
    const frontendMs = performance.now() - started;
    const analysisStarted = performance.now();
    const scan = analyzeCounterPredicates(new Dataflow(program), configured, selectedDetectors);
    const analysisAndDetectorMs = performance.now() - analysisStarted;
    const totalMs = performance.now() - started;
    findings = scan.findings; diagnostics = scan.diagnostics;
    const byMethod: Record<string, number> = {};
    for (const item of scan.coverage) byMethod[item.method] = (byMethod[item.method] ?? 0) + 1;
    result = {
      outcome: "measured", mode, sourceSha256: digest(sourceFor(size)), status: scan.status, scope: scan.scope,
      selectedDetectors: scan.selectedDetectors, diagnostics: normalize(diagnostics, source), diagnosticCodes: diagnostics.map(item => item.code), findings: observations(findings, source),
      exact: { pathCount: scan.exact?.facts.paths.length ?? 0, completedEntries: normalize(scan.exact?.facts.completedEntries ?? [], source), completedEntryCount: scan.exact?.facts.completedEntries.length ?? 0, attemptedEntries: normalize(scan.exact?.entries ?? [], source) },
      predicates: { coverage: normalize(scan.coverage, source), covered: scan.coverage.filter(item => item.status === "covered").length, incomplete: scan.coverage.filter(item => item.status !== "covered").length, byMethod, work: scan.work, certificates: normalize(scan.certificates, source), workPolicies: normalize(scan.workPolicies, source) },
      timing: { frontendMs, analysisAndDetectorMs, totalMs }, peakRssMiB: 0,
    };
  }
  // Node reports maxRSS in KiB; the V8 old-space limit is not an RSS cap.
  result.peakRssMiB = process.resourceUsage().maxRSS / 1024;
  return result;
}

function runWorker(directory: string, mode: Mode, size: Size): Sample {
  const child = spawnSync(process.execPath, ["--max-old-space-size=384", fileURLToPath(import.meta.url), "--worker", mode, String(size)], {
    cwd: directory, env: { ...process.env, COMPACT_PATH: "" }, encoding: "utf8", timeout: workerLimits.timeoutMs, maxBuffer: workerLimits.maxOutputBytes,
  });
  try {
    if (child.error || child.status !== 0 || child.signal || child.stderr) throw new Error(errorText(child.error ?? `Worker exit=${child.status}, signal=${child.signal}, stderr=${child.stderr}`));
    const sample = JSON.parse(child.stdout) as MeasuredSample;
    if (sample.outcome !== "measured" || sample.mode !== mode || sample.sourceSha256 !== digest(sourceFor(size))
      || !["complete", "incomplete"].includes(sample.status) || !Array.isArray(sample.diagnosticCodes) || !Array.isArray(sample.findings?.observations)
      || sample.findings.sha256 !== digest(JSON.stringify(sample.findings.observations)) || sample.findings.count !== sample.findings.observations.length
      || !sample.exact || !sample.timing || Object.values(sample.timing).some(value => !Number.isFinite(value) || value < 0)
      || !Number.isFinite(sample.peakRssMiB) || sample.peakRssMiB <= 0) throw new Error("Invalid worker measurement payload");
    return sample;
  } catch (error) {
    return { outcome: "worker-failure", mode, diagnostic: { code: "benchmark-worker-failure", message: errorText(error) }, exitCode: child.status, signal: child.signal, stderr: child.stderr ?? "", stdout: child.stdout ?? "" };
  }
}

function checkRow(row: Row, size: Size): void {
  if (!row.compiler.valid) row.violations.push("The unchanged source did not pass mandatory compiler qualification");
  for (const mode of row.modes) {
    const measured = mode.samples.filter((sample): sample is MeasuredSample => sample.outcome === "measured");
    if (mode.samples.length !== 5 || measured.length !== 5) row.violations.push(`${mode.mode}: expected five successful fresh processes`);
    mode.medianMs = measured.length === 5 ? measured.map(sample => sample.timing.totalMs).sort((left, right) => left - right)[2] : null;
    mode.peakRssMiB = measured.length ? Math.max(...measured.map(sample => sample.peakRssMiB)) : null;
    for (const [index, sample] of measured.entries()) {
      const prefix = `${mode.mode} sample ${index + 1}`;
      if (sample.status !== mode.expectedStatus || sample.scope !== mode.scope) row.violations.push(`${prefix}: unexpected status/scope`);
      if (JSON.stringify(sample.selectedDetectors) !== JSON.stringify(selectedDetectors)) row.violations.push(`${prefix}: detector selection differs`);
      if (sample.timing.totalMs >= bounds.totalMsExclusive || sample.peakRssMiB >= bounds.peakRssMiBExclusive) row.violations.push(`${prefix}: fresh correctness/status resource bound exceeded`);
      if (mode.expectedStatus === "complete" ? sample.diagnosticCodes.length !== 0 : !sample.diagnosticCodes.length || sample.diagnosticCodes.some(code => code !== "analysis-budget")) row.violations.push(`${prefix}: unexpected diagnostics`);
      if (sample.mode === "scan-file") {
        if (sample.exact.completedEntryCount !== (size === 10 ? 0 : 1) || size !== 10 && sample.exact.pathCount !== 2 ** size) row.violations.push(`${prefix}: unexpected exact path/completion count`);
        if (!Number.isSafeInteger(sample.exact.pathCount) || sample.exact.pathCount < 0 || sample.exact.pathCount > 256) row.violations.push(`${prefix}: exact path count exceeds the default bounded contract`);
        if (sample.predicates !== null) row.violations.push(`${prefix}: ordinary scan unexpectedly claims predicate coverage`);
      } else {
        if (sample.exact.pathCount !== 0 || sample.exact.completedEntryCount !== 0) row.violations.push(`${prefix}: predicate coverage must not become exact path coverage`);
        if (sample.predicates?.covered !== 7 || sample.predicates.incomplete !== 0 || !sample.predicates.work.queryExpenditureKnown) row.violations.push(`${prefix}: expected seven covered detector predicates with known query expenditure`);
        if (sample.findings.count !== size * (size + 1) / 2 + size || sample.findings.byDetector["declared-secret-publication"] !== size * (size + 1) / 2 || sample.findings.byDetector["unguarded-sensitive-state-write"] !== size) row.violations.push(`${prefix}: artificial policy observation/write counts differ`);
      }
    }
    if (measured.length && measured.some(sample => JSON.stringify(sample.findings.observations) !== JSON.stringify(measured[0].findings.observations))) row.violations.push(`${mode.mode}: full finding observations vary between fresh processes`);
  }
  if (size === 10) {
    row.fullFindingEquivalence = { status: "not-compared", reason: "Ordinary exact scanning is incomplete; its partial findings and work are not equivalent complete analysis." };
  } else {
    const ordinary = row.modes[0].samples.filter((sample): sample is MeasuredSample => sample.outcome === "measured" && sample.status === "complete");
    const internal = row.modes[1].samples.filter((sample): sample is MeasuredSample => sample.outcome === "measured" && sample.status === "complete");
    const available = ordinary.length === 5 && internal.length === 5;
    const equal = available && [...ordinary, ...internal].every(sample => JSON.stringify(sample.findings.observations) === JSON.stringify(ordinary[0].findings.observations));
    row.fullFindingEquivalence = { status: available ? equal ? "equal" : "different" : "unavailable", reason: "Compare every normalized finding field, ordered trace, fingerprint and duplicate across all ten complete samples." };
    if (!equal) row.violations.push("Full finding equivalence was not established on the exact-complete workload");
  }
  row.qualified = row.violations.length === 0;
}

function hashFiles(files: string[]): string {
  const hash = createHash("sha256");
  for (const file of [...files].sort()) hash.update(file).update("\0").update(readFileSync(resolve(file))).update("\0");
  return hash.digest("hex");
}

function benchmark(output: string, publicMode: boolean): void {
  const modes: Mode[] = ["scan-file", publicMode ? "public-counter-predicates" : "internal-counter-predicates"];
  const destination = openSync(resolve(output), "wx");
  const report = {
    version: publicMode ? "counter-public-predicates-1" : "counter-predicates-1", purpose: "owned-counter-detector-predicate-correctness-and-status",
    measuredAt: new Date().toISOString(),
    environment: { node: process.version, platform: platform(), arch: arch(), release: release(), cpu: cpus()[0]?.model ?? "unknown", logicalCpus: cpus().length, initialLoadAverage: loadavg(), exclusiveCpuReservation: false },
    methodology: "Five fresh bounded processes per mode and workload; alternate mode order each repetition. Timings cover frontend and analysis/detectors, excluding process startup, compilation and finding normalization. Exact-complete sizes 4/6 require full normalized finding equality. Size 10 records distinct exact-path and detector-predicate scopes; no partial-work equivalence, speedup ratio or historical timing comparison is made. Resource bounds are fresh correctness/status checks, not controlled performance qualification. Historical effects-2 thresholds remain unchanged.",
    policyMeaning: "Every flag is artificially declared secret; count requires a preceding successful call to the void entry circuit. Findings are benchmark policy observations, not vulnerabilities or evidence of exploitability.",
    workerLimits, bounds, selectedDetectors,
    analysisLimits: { maxSteps: 20000, maxPaths: 256, maxValues: 50000, engine: "instructions", pathSemantics: "equivalent-states", summaries: true },
    identity: null as null | Record<string, unknown>,
    baselineReference: null as null | { artifact: string; artifactSha256: string; workloads: { workload: string; sourceSha256: string }[]; purpose: string },
    rows: [] as Row[], failures: [] as string[], qualified: false,
  };
  let temporary: string | undefined;
  try {
    if (!process.env.COMPACTC_TEST) throw new Error("COMPACTC_TEST is mandatory; no unqualified benchmark is run");
    const compiler = realpathSync(resolve(process.env.COMPACTC_TEST));
    const distribution = ["compactc.bin", "zkir", "zkir-v3"].map(file => ({ file, sha256: digest(readFileSync(resolve(dirname(compiler), file))) }));
    report.identity = {
      analyzerSourceAndLockSha256: analyzerIdentity(), harnessSourceSha256: hashFiles([harnessPath, "benchmarks/identity.ts"]),
      analyzerBuiltJavaScriptSha256: hashFiles(readdirSync("dist/src", { recursive: true }).map(String).filter(file => file.endsWith(".js")).map(file => `dist/src/${file}`)),
      executedHarnessSha256: digest(readFileSync(fileURLToPath(import.meta.url))), grammarBuild: GRAMMAR_BUILD, grammarRevision: GRAMMAR_REVISION, semanticProfile: SEMANTIC_PROFILE,
      compiler: { executable: compiler, executableSha256: digest(readFileSync(compiler)), distribution, qualification: "Pinned compiler 0.34.0 / language 0.26.0; --skip-zk on unchanged source before measurement" },
    };
    const historicalBytes = readFileSync(baselinePath);
    const historical = JSON.parse(historicalBytes.toString("utf8")) as { version: string; rows: { workload: string; sourceSha256: string }[] };
    if (historical.version !== "effects-2" || !Array.isArray(historical.rows)) throw new Error("Expected historical effects-2 artifact");
    const workloads = sizes.map(size => {
      const workload = `stateful-branches-${size}`, sourceSha256 = digest(sourceFor(size));
      const previous = historical.rows.filter(row => row.workload === workload);
      if (previous.length !== 1 || previous[0].sourceSha256 !== sourceSha256) throw new Error(`Historical workload/source identity differs: ${workload}`);
      return { workload, sourceSha256 };
    });
    report.baselineReference = { artifact: baselinePath, artifactSha256: digest(historicalBytes), workloads, purpose: "Artifact and unchanged source identity only; historical timings are not compared." };
    temporary = mkdtempSync(resolve(realpathSync(tmpdir()), temporaryPrefix));
    for (const [workloadIndex, size] of sizes.entries()) {
      const source = resolve(temporary, "main.compact");
      writeFileSync(source, sourceFor(size));
      const row: Row = {
        ...workloads[workloadIndex], policies: policiesFor(size), compiler: validateWithCompiler(compiler, source), order: [],
        modes: modes.map(mode => ({ mode, expectedStatus: mode === "scan-file" && size === 10 ? "incomplete" : "complete", scope: mode === "scan-file" ? "experimental-subset" : "selected-detector-predicates", samples: [], medianMs: null, peakRssMiB: null })),
        fullFindingEquivalence: { status: "unavailable", reason: "Measurement has not completed" }, violations: [], qualified: false,
      };
      report.rows.push(row);
      if (readFileSync(source, "utf8") !== sourceFor(size)) throw new Error("Compiler qualification changed the fixed source");
      if (row.compiler.valid) for (let repetition = 0; repetition < 5; repetition++) {
        const order = (repetition + workloadIndex) % 2 ? [...modes].reverse() : [...modes];
        row.order.push(order);
        for (const mode of order) row.modes.find(item => item.mode === mode)!.samples.push(runWorker(temporary, mode, size));
      }
      if (readFileSync(source, "utf8") !== sourceFor(size)) throw new Error("A measurement changed the fixed source");
      checkRow(row, size);
    }
  } catch (error) { report.failures.push(errorText(error)); }
  finally {
    if (temporary) try { rmSync(temporary, { recursive: true, force: true }); } catch (error) { report.failures.push(`Temporary cleanup failed: ${errorText(error)}`); }
    report.qualified = !report.failures.length && report.rows.length === sizes.length && report.rows.every(row => row.qualified);
    try { writeFileSync(destination, JSON.stringify(report, null, 2) + "\n"); } finally { closeSync(destination); }
  }
  console.log(JSON.stringify({ version: report.version, qualified: report.qualified, failures: report.failures, rows: report.rows.map(row => ({ workload: row.workload, compilerValid: row.compiler.valid, qualified: row.qualified, fullFindingEquivalence: row.fullFindingEquivalence, violations: row.violations, modes: row.modes.map(({ samples, ...mode }) => ({ ...mode, samples: samples.length })) })) }, null, 2));
  if (!report.qualified) process.exitCode = 1;
}

const args = process.argv.slice(2);
try {
  if (args[0] === "--worker") {
    if (args.length !== 3 || !allModes.includes(args[1] as Mode) || !sizes.some(size => String(size) === args[2])) throw new Error("Invalid fixed benchmark worker arguments");
    console.log(JSON.stringify(worker(args[1] as Mode, Number(args[2]) as Size)));
  } else {
    const publicMode = args[0] === "--public";
    const options = publicMode ? args.slice(1) : args;
    if (options.length !== 2 || options[0] !== "--output" || !options[1] || options[1].startsWith("--")) throw new Error("Use counter-predicates [--public] --output NEW_FILE");
    benchmark(options[1], publicMode);
  }
} catch (error) {
  console.error(JSON.stringify({ status: "failed", diagnostic: { code: "benchmark-exception", message: errorText(error) } }));
  process.exitCode = 1;
}
