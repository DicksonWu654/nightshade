import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir, cpus, platform, arch } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanFile } from "../src/index.js";
import { analyzerIdentity } from "./identity.js";

const args = process.argv.slice(2);
if (args[0] === "--worker") {
  const result = scanFile(args[1]);
  console.log(JSON.stringify({ status: result.status, diagnostics: result.diagnostics, metrics: result.metrics, peakRssMiB: process.resourceUsage().maxRSS / 1024 }));
} else {
  if (args[0] !== "--output" || !args[1]) throw new Error("Use performance --output FILE");
  const temporary = mkdtempSync(resolve(tmpdir(), "nightshade-performance-"));
  try {
    const rows = [];
    for (const size of [10, 100, 1000]) {
      const source = resolve(temporary, "main.compact");
      writeFileSync(source, Array.from({ length: size }, (_, index) => `export circuit entry${index}(value: Field): Field { return disclose(value); }`).join("\n"));
      const samples = Array.from({ length: 5 }, () => {
        const child = spawnSync(process.execPath, ["--max-old-space-size=384", fileURLToPath(import.meta.url), "--worker", source], { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
        if (child.status !== 0) throw new Error(`Performance worker failed: ${child.error ?? child.stderr}`);
        return JSON.parse(child.stdout) as { status: string; diagnostics: unknown[]; metrics: Record<string, number>; peakRssMiB: number };
      });
      rows.push({ circuits: size, complete: samples.every(sample => sample.status === "complete"), medianMs: samples.map(sample => sample.metrics.totalMs).sort((left, right) => left - right)[2], peakRssMiB: Math.max(...samples.map(sample => sample.peakRssMiB)), samples });
    }
    const report = { version: "scale-1", analyzerSourceAndLockSha256: analyzerIdentity(), measuredAt: new Date().toISOString(), environment: { node: process.version, platform: platform(), arch: arch(), cpu: cpus()[0].model }, workload: "Independent exported identity circuits; 5 fresh processes per size; engine timings exclude process startup", rows };
    writeFileSync(resolve(args[1]), JSON.stringify(report, null, 2) + "\n");
    console.log(JSON.stringify(rows.map(({ samples, ...row }) => row), null, 2));
    if (rows.some(row => !row.complete || row.peakRssMiB >= 512 || row.medianMs >= 10000)) process.exitCode = 1;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}
