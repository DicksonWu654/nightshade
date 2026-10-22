import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir, platform, arch } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import type { Policies } from "../src/policies.js";
import { analyzerIdentity } from "./identity.js";

const args = process.argv.slice(2);
const option = (name: string): string => {
  const index = args.indexOf(name);
  if (index < 0 || !args[index + 1]) throw new Error(`Required: ${name} VALUE`);
  return args[index + 1];
};
const oz = resolve(option("--oz"));
const compiler = resolve(option("--compiler"));
const output = resolve(option("--output"));
const corpus = resolve("tests/corpus");
const manifest = JSON.parse(readFileSync(resolve(corpus, "manifest.json"), "utf8")) as { version: string; detector: string; cases: { file: string; lines: number[] }[] };
const fixtures: { file: string; lines: number[]; detector: string; policies?: Policies; policyRequired: boolean }[] = manifest.cases.map(fixture => ({ ...fixture, detector: manifest.detector, policyRequired: false }));
let corpusVersion = manifest.version;
if (args.includes("--include-policies")) {
  const policyManifest = JSON.parse(readFileSync(resolve(corpus, "policies-manifest.json"), "utf8")) as { version: string; cases: { name: string; detector: string; line: number; policies: Policies }[] };
  corpusVersion += ` + ${policyManifest.version}`;
  for (const fixture of policyManifest.cases) for (const label of ["vulnerable", "safe"]) fixtures.push({ file: `${label}/${fixture.name}.compact`, lines: label === "vulnerable" ? [fixture.line] : [], detector: fixture.detector, policies: fixture.policies, policyRequired: Object.keys(fixture.policies).length > 0 });
}
const repetitions = 5;
const analyzerHash = analyzerIdentity();

function measure(executable: string, commandArgs: string[]) {
  const times: number[] = [];
  let processResult!: ReturnType<typeof spawnSync>;
  for (let repetition = 0; repetition < repetitions; repetition++) {
    const start = performance.now();
    processResult = spawnSync(executable, commandArgs, { encoding: "utf8", timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
    times.push(performance.now() - start);
  }
  return { processResult, medianMs: Number(times.sort((left, right) => left - right)[Math.floor(times.length / 2)].toFixed(3)) };
}

const compileDirectory = mkdtempSync(resolve(tmpdir(), "nightshade-compile-"));
try {
  const rows = fixtures.map((fixture, index) => {
    const path = resolve(corpus, fixture.file);
    const compiled = spawnSync(compiler, ["--skip-zk", path, resolve(compileDirectory, String(index))], { encoding: "utf8", timeout: 30000 });
    const configPath = resolve(compileDirectory, `case-${index}.json`);
    if (fixture.policies) writeFileSync(configPath, JSON.stringify({ version: 1, roots: [path], policies: fixture.policies }));
    const ours = measure(process.execPath, [resolve("dist/src/cli.js"), "scan", ...(fixture.policies ? ["--config", configPath] : [path]), "--json"]);
    const theirs = measure(oz, ["scan", path]);
    let oursJson;
    let ozJson;
    try { oursJson = JSON.parse(String(ours.processResult.stdout)); } catch { oursJson = undefined; }
    try { ozJson = JSON.parse(String(theirs.processResult.stdout)); } catch { ozJson = undefined; }
    const findings = (oursJson?.findings ?? []) as { detectorId: string; location: { line: number; start: number; end: number } }[];
    const matched = fixture.lines.filter(line => findings.some(finding => finding.detectorId === fixture.detector && finding.location.line === line));
    const unexpected = findings.filter(finding => finding.detectorId !== fixture.detector || !fixture.lines.includes(finding.location.line));
    const instances = Object.entries(ozJson?.detector_responses ?? {}).flatMap(([id, response]) => {
      const value = response as { findings?: { instances?: unknown[] }[] };
      return (value.findings ?? []).flatMap(finding => (finding.instances ?? []).map(instance => ({ id, instance })));
    });
    const errors = Object.values(ozJson?.detector_responses ?? {}).flatMap(response => (response as { errors?: unknown[] }).errors ?? []);
    const ozCompleted = Boolean(ozJson) && theirs.processResult.status === 0 && !(ozJson.errors?.length) && errors.length === 0;
    const bytes = readFileSync(path);
    return {
      file: fixture.file,
      detector: fixture.detector,
      policyRequired: fixture.policyRequired,
      policies: fixture.policies,
      sourceSha256: createHash("sha256").update(bytes).digest("hex"),
      expectedLines: fixture.lines,
      compiler: { valid: compiled.status === 0, error: compiled.status === 0 ? undefined : String(compiled.stderr).slice(0, 2000) },
      ours: { completed: oursJson?.status === "complete", exitCode: ours.processResult.status, medianMs: ours.medianMs, truePositives: matched.length, falsePositives: unexpected.length, falseNegatives: fixture.lines.length - matched.length, diagnostics: oursJson?.diagnostics ?? [], spans: findings.map(finding => ({ line: finding.location.line, start: finding.location.start, end: finding.location.end, source: bytes.subarray(finding.location.start, finding.location.end).toString() })) },
      oz: { completed: ozCompleted, exitCode: theirs.processResult.status, medianMs: theirs.medianMs, findings: instances, stderr: String(theirs.processResult.stderr).slice(0, 2000) },
    };
  });
  const metadata = spawnSync(oz, ["metadata"], { encoding: "utf8" });
  const compilerVersion = spawnSync(compiler, ["--version"], { encoding: "utf8" });
  const languageVersion = spawnSync(compiler, ["--language-version"], { encoding: "utf8" });
  const ozMetadata = JSON.parse(metadata.stdout);
  const result = {
    corpusVersion,
    analyzerSourceAndLockSha256: analyzerHash,
    measuredAt: new Date().toISOString(),
    environment: { node: process.version, platform: platform(), arch: arch(), repetitions, timing: "median wall milliseconds, fresh process per file; includes startup; compilation excluded" },
    compiler: { version: compilerVersion.stdout.trim(), languageVersion: languageVersion.stdout.trim() },
    oz: { releaseAsset: "compact-scanner-ubuntu-latest-v0.0.3.zip", selfReportedVersion: ozMetadata.version, binarySha256: createHash("sha256").update(readFileSync(oz)).digest("hex"), detectorIds: ozMetadata.detectors.map((detector: { id: string }) => detector.id) },
    totals: {
      files: rows.length, expected: rows.reduce((total, row) => total + row.expectedLines.length, 0),
      compilerValid: rows.filter(row => row.compiler.valid).length,
      ours: { truePositives: rows.reduce((total, row) => total + row.ours.truePositives, 0), falsePositives: rows.reduce((total, row) => total + row.ours.falsePositives, 0), falseNegatives: rows.reduce((total, row) => total + row.ours.falseNegatives, 0), incomplete: rows.filter(row => !row.ours.completed).length, totalMedianMs: Number(rows.reduce((total, row) => total + row.ours.medianMs, 0).toFixed(3)) },
      oz: { totalFindings: rows.reduce((total, row) => total + row.oz.findings.length, 0), failedRuns: rows.filter(row => !row.oz.completed).length, totalMedianMs: Number(rows.reduce((total, row) => total + row.oz.medianMs, 0).toFixed(3)) },
      defaultAnalysis: { expected: rows.filter(row => !row.policyRequired).reduce((sum, row) => sum + row.expectedLines.length, 0), truePositives: rows.filter(row => !row.policyRequired).reduce((sum, row) => sum + row.ours.truePositives, 0) },
      policyAnalysis: { expected: rows.filter(row => row.policyRequired).reduce((sum, row) => sum + row.expectedLines.length, 0), truePositives: rows.filter(row => row.policyRequired).reduce((sum, row) => sum + row.ours.truePositives, 0), baselineNote: "OZ receives identical source but has no equivalent configured application policies; do not combine with default-analysis coverage claims" },
    },
    rows,
  };
  writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify(result.totals, null, 2));
  if (result.totals.compilerValid !== rows.length || result.totals.ours.incomplete) process.exitCode = 1;
} finally {
  rmSync(compileDirectory, { recursive: true, force: true });
}
