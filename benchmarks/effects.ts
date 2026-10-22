import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir, cpus, platform, arch } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanFile } from "../src/index.js";
import { analyzerIdentity } from "./identity.js";

interface Sample {
  status: string;
  diagnostics: string[];
  metrics: Record<string, number>;
  peakRssMiB: number;
}

interface Row {
  workload: string;
  sourceSha256: string;
  expectedStatus: string;
  qualified: boolean;
  medianMs: number;
  peakRssMiB: number;
  samples: Sample[];
}

const args = process.argv.slice(2);
if (args[0] === "--worker") {
  const result = scanFile(args[1]);
  console.log(JSON.stringify({ status: result.status, diagnostics: result.diagnostics.map(diagnostic => diagnostic.code), metrics: result.metrics, peakRssMiB: process.resourceUsage().maxRSS / 1024 }));
} else {
  if (args[0] !== "--output" || !args[1] || args.length !== 2 && (args.length !== 4 || args[2] !== "--baseline")) throw new Error("Use effects --output FILE [--baseline FILE]");
  if (args[3] && resolve(args[1]) === resolve(args[3])) throw new Error("Comparison output must not overwrite its baseline");
  const environment = { node: process.version, platform: platform(), arch: arch(), cpu: cpus()[0].model };
  const temporary = mkdtempSync(resolve(tmpdir(), "nightshade-effects-"));
  try {
    const workloads = [
      ...[4, 6, 10].map(size => ({
        workload: `stateful-branches-${size}`, expectedStatus: "complete",
        source: `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: size }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { ${Array.from({ length: size }, (_, index) => `if (disclose(flag${index})) { count.increment(1); }`).join(" ")} }`,
      })),
      ...[32, 128, 256].map(size => ({
        workload: `repeated-pure-calls-${size}`, expectedStatus: "complete",
        source: `import CompactStandardLibrary; circuit digest(value: Field): Bytes<32> { return persistentHash<Field>(value); } export circuit entry(value: Field): Bytes<32> { for (const iteration of 0..${size}) { digest(value); } return digest(value); }`,
      })),
      { workload: "keyed-ledger-writes-128", expectedStatus: "complete", source: "import CompactStandardLibrary; export ledger table: Map<Field, Field>; export circuit entry(value: Field): Field { for (const iteration of 0..128) { table.insert(iteration as Field, disclose(value)); } return table.lookup(0 as Field); }" },
    ];
    const rows: Row[] = [];
    for (const workload of workloads) {
      const source = resolve(temporary, "main.compact");
      writeFileSync(source, workload.source);
      const samples: Sample[] = Array.from({ length: 5 }, () => {
        const child = spawnSync(process.execPath, ["--max-old-space-size=384", fileURLToPath(import.meta.url), "--worker", source], { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
        if (child.status !== 0) throw new Error(`Performance worker failed: ${child.error ?? child.stderr}`);
        return JSON.parse(child.stdout) as Sample;
      });
      rows.push({ workload: workload.workload, sourceSha256: createHash("sha256").update(workload.source).digest("hex"), expectedStatus: workload.expectedStatus, qualified: samples.every(sample => sample.status === workload.expectedStatus && (workload.expectedStatus === "complete" ? sample.diagnostics.length === 0 : sample.diagnostics.includes("analysis-budget"))), medianMs: samples.map(sample => sample.metrics.totalMs).sort((first, second) => first - second)[2], peakRssMiB: Math.max(...samples.map(sample => sample.peakRssMiB)), samples });
    }
    const regressions: { workload: string; percent: number }[] = [];
    let comparison: { analyzerSourceAndLockSha256: string; artifactSha256: string; rows: { workload: string; baselineMedianMs: number; percent: number }[];
      coverageChanges: { workload: string; baselineStatus: string; currentStatus: string; baselineMedianMs: number; currentMedianMs: number; timingComparable: false }[] } | undefined;
    if (args[3]) {
      const artifact = readFileSync(resolve(args[3]));
      const baseline = JSON.parse(artifact.toString("utf8")) as { version: string; analyzerSourceAndLockSha256: string; environment: typeof environment; rows: Row[] };
      if (!["effects-2", "effects-3"].includes(baseline.version) || JSON.stringify(baseline.environment) !== JSON.stringify(environment) || baseline.rows.length !== rows.length) throw new Error("Baseline workload version, environment or row count differs; measurements are not comparable");
      if (!/^[a-f0-9]{64}$/.test(baseline.analyzerSourceAndLockSha256 ?? "")) throw new Error("Baseline lacks a valid analyzer identity");
      comparison = { analyzerSourceAndLockSha256: baseline.analyzerSourceAndLockSha256, artifactSha256: createHash("sha256").update(artifact).digest("hex"), rows: [], coverageChanges: [] };
      for (const row of rows) {
        const previous = baseline.rows.find(previous => previous.workload === row.workload);
        if (!previous || previous.sourceSha256 !== row.sourceSha256 || previous.samples.length < 5 || !previous.qualified || !Number.isFinite(previous.medianMs) || previous.medianMs <= 0) throw new Error(`Invalid baseline for ${row.workload}`);
        if (previous.expectedStatus !== row.expectedStatus) {
          if (baseline.version !== "effects-2" || row.workload !== "stateful-branches-10" || previous.expectedStatus !== "incomplete" || row.expectedStatus !== "complete") throw new Error(`Unexpected coverage change for ${row.workload}`);
          comparison.coverageChanges.push({ workload: row.workload, baselineStatus: previous.expectedStatus, currentStatus: row.expectedStatus, baselineMedianMs: previous.medianMs, currentMedianMs: row.medianMs, timingComparable: false });
          continue;
        }
        const percent = 100 * (row.medianMs / previous.medianMs - 1);
        comparison.rows.push({ workload: row.workload, baselineMedianMs: previous.medianMs, percent });
        if (percent > 25) regressions.push({ workload: row.workload, percent });
      }
    }
    writeFileSync(resolve(args[1]), JSON.stringify({ version: "effects-3", analyzerSourceAndLockSha256: analyzerIdentity(), measuredAt: new Date().toISOString(), environment, methodology: "Five fresh processes per workload; engine timings exclude startup. Version 3 requires complete correlated analysis of the unchanged ten-branch source under the original default budgets. Version 2 artifacts retain their historical incomplete result; that row's timing is not compared across the coverage change. Other matching rows preserve the 25% regression threshold. Comparisons require the same runtime/hardware metadata and workload hashes; version 1 is not comparable. These are host-local measurements, not controlled release-performance approval.", comparison, regressions, rows }, null, 2) + "\n");
    console.log(JSON.stringify(rows.map(({ samples, ...row }) => row), null, 2));
    if (rows.some(row => !row.qualified || row.peakRssMiB >= 512 || row.medianMs >= 10000) || regressions.length) process.exitCode = 1;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}
