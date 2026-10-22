import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { arch, cpus, platform, tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Dataflow, Program, detectors, resolvePolicies } from "../src/index.js";
import { validateWithCompiler } from "../src/compiler/index.js";
import { analyzerIdentity } from "./identity.js";

interface Sample {
  analysisMs: number;
  peakRssMiB: number;
  complete: boolean;
  diagnostics: string[];
  detectorObservationSha256: string;
  steps: number;
  paths: number;
  guardSubsumptions: number;
}

const args = process.argv.slice(2);
if (args[0] === "--worker") {
  const program = new Program(args[1]);
  const start = performance.now();
  const facts = new Dataflow(program, 20000, 256, 50000, "instructions", true, true, args[2] === "covered" ? "guard-cover" : "equivalent-states").analyze();
  const analysisMs = performance.now() - start;
  const authorization = [...program.functions.values()].filter(fn => /^check\d+$/.test(fn.symbol.name)).map(fn => ({ state: "sensitive", guard: fn.symbol.name }));
  const secrets = program.functions.get(program.entries[0])!.declaration.parameters.map(parameter => ({ circuit: "entry", parameter: parameter.name }));
  const policies = resolvePolicies(program, { authorization, secrets });
  const observations = detectors.flatMap(detector => detector.run(facts, policies)).map(finding => JSON.stringify({ detector: finding.detectorId, fingerprint: finding.fingerprint, location: finding.location, source: finding.source, constraint: finding.constraint, message: finding.message })).sort();
  const sample: Sample = {
    analysisMs, peakRssMiB: process.resourceUsage().maxRSS / 1024,
    complete: facts.diagnostics.length === 0 && facts.completedEntries.length === program.entries.length,
    diagnostics: facts.diagnostics.map(diagnostic => diagnostic.code),
    detectorObservationSha256: createHash("sha256").update(JSON.stringify(observations)).digest("hex"),
    steps: facts.metrics.steps, paths: facts.metrics.paths, guardSubsumptions: facts.metrics.guardSubsumptions,
  };
  console.log(JSON.stringify(sample));
} else {
  if (args[0] !== "--output" || !args[1] || args.length !== 2 && (args.length !== 4 || args[2] !== "--compiler")) throw new Error("Use guards --output FILE [--compiler FILE]");
  const temporary = mkdtempSync(resolve(tmpdir(), "nightshade-guard-benchmark-"));
  try {
    const rows = [6, 12].map(size => {
      const source = `pragma language_version >= 0.26.0; export ledger authorized: Boolean; export ledger sensitive: Field; ${Array.from({ length: size }, (_, index) => `circuit check${index}(): [] { assert(authorized, "authorized"); }`).join(" ")} export circuit entry(${Array.from({ length: size }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { assert(authorized, "authorized"); ${Array.from({ length: size }, (_, index) => `if (disclose(flag${index})) { check${index}(); }`).join(" ")} sensitive = 1 as Field; }`;
      const path = resolve(temporary, "main.compact");
      writeFileSync(path, source);
      const compiler = args[3] ? validateWithCompiler(args[3], path) : undefined;
      const covered: Sample[] = [];
      const exact: Sample[] = [];
      for (let repetition = 0; repetition < 5; repetition++) for (const mode of repetition % 2 ? ["exact", "covered"] : ["covered", "exact"]) {
        const child = spawnSync(process.execPath, ["--max-old-space-size=384", fileURLToPath(import.meta.url), "--worker", path, mode], { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
        if (child.status !== 0) throw new Error(`Guard benchmark failed: ${child.error ?? child.stderr}`);
        (mode === "covered" ? covered : exact).push(JSON.parse(child.stdout) as Sample);
      }
      const median = (samples: Sample[]): number => samples.map(sample => sample.analysisMs).sort((first, second) => first - second)[2];
      const summarize = (samples: Sample[]) => ({ medianAnalysisMs: median(samples), peakRssMiB: Math.max(...samples.map(sample => sample.peakRssMiB)), samples });
      const observationsMatch = size === 6 ? [...covered, ...exact].every(sample => sample.detectorObservationSha256 === covered[0].detectorObservationSha256) : undefined;
      const qualified = (compiler?.valid ?? true) && covered.every(sample => sample.complete && sample.diagnostics.length === 0 && sample.paths === 1 && sample.guardSubsumptions === size) && exact.every(sample => sample.guardSubsumptions === 0 && (size === 6 ? sample.complete && sample.paths === 64 && sample.diagnostics.length === 0 : !sample.complete && sample.diagnostics.includes("analysis-budget"))) && observationsMatch !== false && [...covered, ...exact].every(sample => sample.peakRssMiB < 512 && sample.analysisMs < 10000);
      return { workload: `optional-guard-checks-${size}`, sourceSha256: createHash("sha256").update(source).digest("hex"), compiler, qualified, observationsMatch, covered: summarize(covered), exact: summarize(exact) };
    });
    writeFileSync(resolve(args[1]), JSON.stringify({ version: "guard-cover-1", analyzerSourceAndLockSha256: analyzerIdentity(), measuredAt: new Date().toISOString(), environment: { node: process.version, platform: platform(), arch: arch(), cpu: cpus()[0].model }, methodology: "Five fresh processes per mode, alternating order. Both modes retain pure/stateful summaries. Guard cover is an opt-in core API, not the scanner default. Compare detector identities/locations/messages only when both modes complete, not full path enumeration. The exact twelve-branch mode is expected incomplete. Analysis timings include lazy instruction lowering but exclude frontend, detector execution and startup. Synthetic optimization inputs, not independent security labels or a general join benchmark.", rows }, null, 2) + "\n");
    console.log(JSON.stringify(rows.map(({ covered, exact, ...row }) => ({ ...row, covered: { medianAnalysisMs: covered.medianAnalysisMs, peakRssMiB: covered.peakRssMiB }, exact: { medianAnalysisMs: exact.medianAnalysisMs, peakRssMiB: exact.peakRssMiB } })), null, 2));
    if (rows.some(row => !row.qualified)) process.exitCode = 1;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}
