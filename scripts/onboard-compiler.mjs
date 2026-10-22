#!/usr/bin/env node
/**
 * Onboard a Compact compiler without changing the analyzer's offline default.
 * The command is deliberately evidence-oriented: the downloaded archive and
 * every probe are hashed, and a JSON/Markdown report is written outside the
 * repository unless --output is supplied.
 */
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir, tmpdir } from "node:os";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const toolchainRoot = process.env.COMPACT_TOOLCHAINS ?? join(homedir(), ".cache", "nightshade", "compilers");
const defaultOutput = process.env.COMPACT_ONBOARDING_OUTPUT ?? join(tmpdir(), "nightshade-compiler-onboarding");
const releaseRepo = "LFDT-Minokawa/compact";

function usage() {
  console.log("Usage: node scripts/onboard-compiler.mjs <version|url> [--output DIR] [--previous VERSION] [--corpus DIR]\n" +
    "       node scripts/onboard-compiler.mjs --watch [--repo OWNER/REPO] [--json]");
}
function arg(name, fallback) { const i = process.argv.indexOf(name); return i < 0 ? fallback : process.argv[i + 1]; }
function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: options.timeout ?? 120000, maxBuffer: 2 * 1024 * 1024, cwd: options.cwd ?? root, ...options });
  return { status: result.status, signal: result.signal, stdout: String(result.stdout ?? ""), stderr: String(result.stderr ?? ""), error: result.error?.message };
}
function walk(directory) {
  const files = [];
  if (!existsSync(directory)) return files;
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const path = join(directory, entry.name);
    if (entry.isDirectory() && entry.name !== "node_modules" && entry.name !== ".git") files.push(...walk(path));
    else if (entry.isFile() && extname(entry.name) === ".compact") files.push(path);
  }
  return files;
}
function corpusRows(corpus) {
  if (corpus.endsWith(".json") && existsSync(corpus)) {
    const report = JSON.parse(readFileSync(corpus, "utf8"));
    if (Array.isArray(report.rows) && Array.isArray(report.compilerRejected) && Array.isArray(report.sourcePins)) {
      const pins = new Map(report.sourcePins.map(pin => [pin.name, pin.directory]));
      const rows = [...report.rows.filter(row => row.repository !== "compact-compiler"), ...report.compilerRejected.filter(row => row.repository !== "compact-compiler")];
      return rows.map(row => ({ ...row, path: resolve(pins.get(row.repository) ?? "", row.file) })).filter(row => existsSync(row.path));
    }
  }
  return walk(corpus).map(path => ({ path }));
}
function compilerBinary(directory) {
  for (const candidate of [join(directory, "compactc"), join(directory, "compactc.bin"), directory]) {
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  }
  throw new Error(`No compactc executable found in ${directory}`);
}
function archiveName(version, url) {
  const match = /compactc[_-]([^/]+)_x86_64-unknown-linux-musl\.zip$/.exec(url);
  return match ? `compactc-${match[1]}.zip` : `compactc-${version.replaceAll("/", "_")}.zip`;
}
async function download(url, target) {
  // Keep the shared toolchain directory serialized across evaluator sessions.
  const child = "const fs=require('node:fs'); fetch(process.argv[1],{redirect:'follow'}).then(async r=>{if(!r.ok)throw new Error(String(r.status));fs.writeFileSync(process.argv[2],Buffer.from(await r.arrayBuffer()));}).catch(e=>{console.error(e.message);process.exit(1)});";
  const result = spawnSync("flock", [join(toolchainRoot, ".lock"), process.execPath, "-e", child, url, target], { encoding: "utf8", timeout: 180000 });
  if (result.status !== 0) throw new Error(`Download failed (${result.stderr || result.error || result.status}): ${url}`);
  return readFileSync(target);
}
async function resolveRelease(input) {
  if (/^https?:\/\//.test(input)) return { version: basename(input).replace(/^compactc[_-]/, "").replace(/_x86_64.*$/, ""), url: input, dev: input.includes("dev-") };
  const version = input;
  const owner = version.startsWith("0.28") || version.startsWith("0.29") || version.startsWith("0.30") || version.startsWith("0.31") ? "midnightntwrk" : "LFDT-Minokawa";
  const tag = version.startsWith("0.") ? `compactc-v${version}` : version;
  const url = `https://github.com/${owner}/compact/releases/download/${tag}/compactc_${tag.replace(/^compactc-/, "")}_x86_64-unknown-linux-musl.zip`;
  return { version, url, dev: !version.startsWith("0.") };
}
function profileSnapshot() {
  const source = readFileSync(join(root, "src/semantic/profile.ts"), "utf8");
  return { sha256: sha256(source), profiles: [...source.matchAll(/^\s+"([^"]+)": \{([^\n]+)\}/gm)].map(m => ({ version: m[1], declaration: m[2].trim() })) };
}
function probeCompiler(binary) {
  return { version: run(binary, ["--version"], { timeout: 30000 }), language: run(binary, ["--language-version"], { timeout: 30000 }) };
}
function runCorpus(binary, corpus, output, profileVersion) {
  const rows = [];
  for (const input of corpusRows(corpus)) {
    const file = input.path;
    const target = join(output, "compiler-output", `${rows.length}`);
    mkdirSync(dirname(target), { recursive: true });
    const result = run(binary, ["--skip-zk", file, target], { timeout: 30000 });
    rows.push({ file, status: result.status === 0 ? "accepted" : result.signal ? "timeout" : "rejected", exitCode: result.status, stderr: result.stderr.slice(0, 2000), previousCategory: input.category, previousCompletedEntries: input.completedEntries, previousRuleGaps: (input.ruleCoverage ?? []).filter(item => item.status === "incomplete").map(item => item.detectorId) });
  }
  return rows;
}
function runSuites(profileVersion, binary) {
  const parser = run("npm", ["run", "build:parser", "--", "--verify"], { timeout: 180000 });
  const build = run("npm", ["run", "build"], { timeout: 180000 });
  const compilerTests = run(process.execPath, ["--test", "dist/tests/compiler-profiles.test.js", "dist/tests/compiler-profile-legacy.test.js", "dist/tests/compiler-stable.test.js", "dist/tests/compiler-prerelease.test.js"], {
    timeout: 600000,
    env: { ...process.env, ...(profileVersion === "0.35.0" ? { COMPACTC_035_TEST: binary } : {}) },
  });
  return { parser: { status: parser.status, output: (parser.stdout + parser.stderr).slice(-4000) }, build: { status: build.status, output: (build.stdout + build.stderr).slice(-4000) }, compilerTests: { status: compilerTests.status, output: (compilerTests.stdout + compilerTests.stderr).slice(-4000) }, passed: [parser, build, compilerTests].every(result => result.status === 0) };
}
async function analyzerDeltas(corpus, output, profileVersion) {
  const cli = join(root, "dist/src/cli.js");
  if (!existsSync(cli) || !profileVersion?.startsWith("0.")) return { status: "not-run", reason: "Analyzer profile comparison requires a released compiler profile and built dist" };
  const rows = [];
  for (const input of corpusRows(corpus)) {
    const result = run(process.execPath, [cli, "scan", input.path, "--json", "--compiler-version", profileVersion, "--zkir-version", "2"], { timeout: 60000 });
    let report;
    try { report = JSON.parse(result.stdout); } catch { report = { status: "worker-failure", diagnostics: [{ code: "invalid-json", message: result.stderr.slice(0, 1000) }] }; }
    rows.push({ file: input.path, previousCategory: input.category, previousCompletedEntries: input.completedEntries?.length ?? 0, previousRuleGaps: (input.ruleCoverage ?? []).filter(item => item.status === "incomplete").map(item => item.detectorId), status: report.status, baselineStatus: report.coverage?.baselineStatus, completedEntries: report.coverage?.completedEntries?.length ?? 0, parseFailures: (report.diagnostics ?? []).filter(item => ["parse-error", "input-error", "unsupported-syntax", "unresolved-symbol"].includes(item.code)).map(item => item.code), diagnostics: [...new Set((report.diagnostics ?? []).map(item => item.code))], ruleCertificateGaps: (report.coverage?.rules ?? []).filter(item => item.status === "incomplete").map(item => item.detectorId) });
  }
  return { status: "complete", total: rows.length, newlyRejected: rows.filter(row => row.status !== "complete" && row.previousCategory === "complete").map(row => row.file), parseFailures: rows.filter(row => row.parseFailures.length).map(row => ({ file: row.file, codes: row.parseFailures })), completionChanges: rows.filter(row => row.completedEntries !== row.previousCompletedEntries).map(row => ({ file: row.file, previous: row.previousCompletedEntries, current: row.completedEntries })), ruleCertificateGaps: [...new Set(rows.flatMap(row => row.ruleCertificateGaps))], rows };
}
function diff(previous, current) {
  const oldVersions = new Set(previous?.profiles?.map(item => item.version) ?? []);
  return { newProfiles: current.profiles.filter(item => !oldVersions.has(item.version)).map(item => item.version), profileSourceChanged: previous ? previous.sha256 !== current.sha256 : true };
}
async function watch(repo, json) {
  // Prefer the operator's authenticated, read-only gh session. Public fetch is
  // retained as a fallback for unattended developer machines and is never used
  // to mutate releases.
  const authenticated = spawnSync("gh", ["api", `repos/${repo}/releases`, "--paginate", "--slurp"], { encoding: "utf8", timeout: 30000, maxBuffer: 8 * 1024 * 1024 });
  let releases;
  if (authenticated.status === 0) {
    const pages = JSON.parse(authenticated.stdout);
    releases = pages.flat();
  } else {
    const response = await fetch(`https://api.github.com/repos/${repo}/releases?per_page=100`, { headers: { "User-Agent": "nightshade-compiler-watcher", Accept: "application/vnd.github+json" } });
    if (!response.ok) throw new Error(`Release API failed (${response.status}); gh api fallback: ${authenticated.stderr.trim() || authenticated.error || "not authenticated"}`);
    releases = await response.json();
  }
  const rows = releases.filter(release => !release.draft).map(release => ({ tag: release.tag_name, publishedAt: release.published_at, prerelease: release.prerelease, assets: release.assets.map(asset => ({ name: asset.name, url: asset.browser_download_url, size: asset.size, digest: asset.digest })) }));
  const result = { checkedAt: new Date().toISOString(), repository: repo, releases: rows };
  console.log(json ? JSON.stringify(result, null, 2) : rows.map(row => `${row.tag}\t${row.publishedAt}\t${row.assets.length} assets`).join("\n"));
}
async function main() {
  if (process.argv.includes("--help") || process.argv.length < 3) return usage();
  if (process.argv.includes("--watch")) return watch(arg("--repo", releaseRepo), process.argv.includes("--json"));
  const input = process.argv[2], output = resolve(arg("--output", defaultOutput));
  const release = await resolveRelease(input);
  mkdirSync(output, { recursive: true });
  const versionDir = join(toolchainRoot, release.version); mkdirSync(versionDir, { recursive: true });
  const archive = join(versionDir, archiveName(release.version, release.url));
  const archiveBytes = existsSync(archive) ? readFileSync(archive) : await download(release.url, archive);
  const extracted = join(versionDir, "onboarding-extracted"); mkdirSync(extracted, { recursive: true });
  if (!existsSync(join(extracted, "compactc")) && !existsSync(join(extracted, "compactc.bin"))) execFileSync("unzip", ["-q", "-o", archive, "-d", extracted]);
  const binary = compilerBinary(extracted);
  const probe = probeCompiler(binary);
  const current = profileSnapshot();
  const previous = arg("--previous") ? { profiles: [{ version: arg("--previous") }] } : undefined;
  const corpus = resolve(arg("--corpus", process.env.COMPACT_CORPUS_REPORT ?? join(root, "examples")));
  const profileVersion = input.startsWith("0.") ? input : "0.35.0";
  const suites = runSuites(profileVersion, binary);
  const rows = runCorpus(binary, corpus, output, profileVersion);
  const deltas = await analyzerDeltas(corpus, output, profileVersion);
  const report = { generatedAt: new Date().toISOString(), input, release, archive: { path: archive, sha256: sha256(archiveBytes), bytes: archiveBytes.length }, binary: { path: binary, sha256: sha256(readFileSync(binary)) }, probe, suites, profile: current, diff: diff(previous, current), corpus: { root: corpus, total: rows.length, accepted: rows.filter(row => row.status === "accepted").length, rejected: rows.filter(row => row.status !== "accepted").length, rows }, deltas };
  writeFileSync(join(output, `onboarding-${release.version}.json`), JSON.stringify(report, null, 2) + "\n");
  writeFileSync(join(output, `onboarding-${release.version}.md`), `# Compiler onboarding: ${release.version}\n\n- Archive SHA-256: \`${report.archive.sha256}\`\n- Compiler: \`${probe.version.stdout.trim()}\`; language: \`${probe.language.stdout.trim()}\`\n- Real corpus compiler acceptance: ${report.corpus.accepted}/${report.corpus.total}\n- Newly rejected previously-complete roots: ${report.deltas.newlyRejected?.length ?? "not run"}\n- Parse failures: ${report.deltas.parseFailures?.length ?? "not run"}\n- Completion changes: ${report.deltas.completionChanges?.length ?? "not run"}\n- Rule-certificate gaps: ${report.deltas.ruleCertificateGaps?.length ?? "not run"}\n- Grammar/parser/compiler suites: ${report.suites.passed ? "passed" : "failed"}\n- Profile source changed: ${report.diff.profileSourceChanged}\n- New profiles: ${report.diff.newProfiles.join(", ") || "none"}\n\nA new profile still needs explicit semantic profile metadata, parser/compiler-valid fixtures, rule certificates, and a complete corpus review for every rejected or unsupported source.\n`);
  console.log(JSON.stringify({ output, version: release.version, archiveSha256: report.archive.sha256, compiler: probe.version.stdout.trim(), corpus: report.corpus }, null, 2));
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
