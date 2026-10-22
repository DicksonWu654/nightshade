import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { arch, cpus, platform, tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { Dataflow, Program } from "../src/index.js";
import { validateWithCompiler } from "../src/compiler/index.js";
import { analyzerIdentity } from "./identity.js";

interface Sample {
  frontendMs: number;
  analysisMs: number;
  peakRssMiB: number;
  complete: boolean;
  observationSha256: string;
  diagnostics: string[];
  steps: number;
  statefulSummaryHits: number;
  summaryEffects: number;
}

const args = process.argv.slice(2);
if (args[0] === "--worker") {
  const start = performance.now();
  const program = new Program(args[1]);
  const frontendMs = performance.now() - start;
  const analysisStarted = performance.now();
  const facts = new Dataflow(program, 20000, 256, 50000, "instructions", true, args[2] === "cached").analyze();
  const analysisMs = performance.now() - analysisStarted;
  const observations = JSON.stringify({ paths: facts.paths, failedAssertions: facts.failedAssertions, completedEntries: facts.completedEntries }, (_, value) => value instanceof Set ? [...value].sort() : value);
  const sample: Sample = {
    frontendMs, analysisMs, peakRssMiB: process.resourceUsage().maxRSS / 1024,
    complete: facts.diagnostics.length === 0 && facts.completedEntries.length === program.entries.length,
    observationSha256: createHash("sha256").update(observations).digest("hex"),
    diagnostics: facts.diagnostics.map(diagnostic => diagnostic.code),
    steps: facts.metrics.steps, statefulSummaryHits: facts.metrics.statefulSummaryHits, summaryEffects: facts.metrics.summaryEffects,
  };
  console.log(JSON.stringify(sample));
} else {
  if (args[0] !== "--output" || !args[1] || args.length !== 2 && (args.length !== 4 || args[2] !== "--compiler")) throw new Error("Use summaries --output FILE [--compiler FILE]");
  const temporary = mkdtempSync(resolve(tmpdir(), "nightshade-summary-benchmark-"));
  const prelude = "pragma language_version >= 0.26.0; import CompactStandardLibrary; ";
  const workloads = [
    { name: "derived-scalar-writes-128", source: `${prelude}export ledger stored: Bytes<32>; circuit publish(value: Field): [] { const hash0 = persistentHash<Field>(value); ${Array.from({ length: 8 }, (_, index) => `const hash${index + 1} = persistentHash<Bytes<32>>(hash${index});`).join(" ")} stored = disclose(hash8); } export circuit entry(value: Field): [] { for (const iteration of 0..128) { publish(value); } }` },
    { name: "counter-mutations-128", source: `${prelude}export ledger count: Counter; circuit add(value: Uint<16>): [] { count.increment(disclose(value)); } export circuit entry(value: Uint<16>): Uint<64> { for (const iteration of 0..128) { add(value); } return count.read(); }` },
    { name: "aggregate-and-map-writes-128", source: `${prelude}struct Pair { first: Field; second: Field; } export ledger stored: Pair; export ledger table: Map<Field, Field>; circuit put(key: Field, value: Field): [] { stored = Pair { first: disclose(value), second: disclose(key) }; table.insert(disclose(key), disclose(value)); } export circuit entry(key: Field, value: Field): [] { for (const iteration of 0..128) { put(key, value); } }` },
  ];
  try {
    const rows = workloads.map(workload => {
      const source = resolve(temporary, "main.compact");
      writeFileSync(source, workload.source);
      const compiler = args[3] ? validateWithCompiler(args[3], source) : undefined;
      const cached: Sample[] = [];
      const expanded: Sample[] = [];
      for (let repetition = 0; repetition < 5; repetition++) for (const mode of repetition % 2 ? ["expanded", "cached"] : ["cached", "expanded"]) {
        const result = spawnSync(process.execPath, ["--max-old-space-size=384", fileURLToPath(import.meta.url), "--worker", source, mode], { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
        if (result.status !== 0) throw new Error(`Summary benchmark failed: ${result.error ?? result.stderr}`);
        (mode === "cached" ? cached : expanded).push(JSON.parse(result.stdout) as Sample);
      }
      const median = (samples: Sample[]): number => samples.map(sample => sample.analysisMs).sort((first, second) => first - second)[2];
      const summarize = (samples: Sample[]) => ({ medianAnalysisMs: median(samples), peakRssMiB: Math.max(...samples.map(sample => sample.peakRssMiB)), samples });
      const observationsMatch = [...cached, ...expanded].every(sample => sample.observationSha256 === cached[0].observationSha256);
      const qualified = (compiler?.valid ?? true) && observationsMatch && [...cached, ...expanded].every(sample => sample.complete && sample.diagnostics.length === 0 && sample.peakRssMiB < 512 && sample.analysisMs < 10000) && cached.every(sample => sample.statefulSummaryHits === 127) && expanded.every(sample => sample.statefulSummaryHits === 0);
      return { workload: workload.name, sourceSha256: createHash("sha256").update(workload.source).digest("hex"), compiler, qualified, observationsMatch, cached: summarize(cached), expanded: summarize(expanded), medianAnalysisSpeedup: median(expanded) / median(cached) };
    });
    writeFileSync(resolve(args[1]), JSON.stringify({ version: "stateful-summaries-1", analyzerSourceAndLockSha256: analyzerIdentity(), measuredAt: new Date().toISOString(), environment: { node: process.version, platform: platform(), arch: arch(), cpu: cpus()[0].model }, methodology: "Five fresh processes per mode/workload, alternating order; both modes retain pure summaries. Compare all successful-path, failed-assertion and completed-entry observations including traces. Analysis timings include lazy instruction lowering, not process startup or frontend. Synthetic optimization workloads, not field throughput or security accuracy.", rows }, null, 2) + "\n");
    console.log(JSON.stringify(rows.map(({ cached, expanded, ...row }) => ({ ...row, cached: { medianAnalysisMs: cached.medianAnalysisMs, peakRssMiB: cached.peakRssMiB }, expanded: { medianAnalysisMs: expanded.medianAnalysisMs, peakRssMiB: expanded.peakRssMiB } })), null, 2));
    if (rows.some(row => !row.qualified)) process.exitCode = 1;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}
