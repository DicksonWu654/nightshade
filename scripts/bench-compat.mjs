#!/usr/bin/env node
// Fixed-source compatibility check. Compiler validation is recorded once in the
// manifest; each run measures the existing built CLI, without compiling contracts.
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { homedir, availableParallelism } from 'node:os';
import { delimiter, dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

// Precision exclusions annotate benchmark findings; they never suppress scans.
// A helper in a nested frame does not make an ordinary entry an intentional mock.
export function precisionScope(app, finding) {
  if (app.repository === 'compact-compiler') return 'compiler-fixture';
  return app.precisionExcludedEntries?.some(entry => entry.entry === finding.callPath?.[0])
    ? 'intentional-helper-exposure' : 'eligible';
}

// Baseline coverage and selected-rule completeness are distinct claims.
export function matchesScanProfile(result, compilerVersion, zkirVersion) {
  if (result?.semanticProfile === `compact-${compilerVersion}-zkir${zkirVersion}`) return true;
  // Unsupported ZKIR3 combinations fail before profile selection. The API's
  // empty failure envelope retains its qualified 0.34 placeholder. Accept that
  // envelope only when it explicitly rejects the request and performs no
  // analysis; never accept findings/work from a different compiler profile.
  const empty = value => Array.isArray(value) && value.length === 0;
  return zkirVersion === 3 && ['0.28.0', '0.29.0', '0.30.0', '0.31.1', '0.33.0-rc.2', '0.35.0-rc.1', '0.35.0'].includes(compilerVersion)
    && result?.semanticProfile === 'compact-0.34.0-zkir3' && result.status === 'incomplete'
    && result.coverage?.baselineStatus === 'incomplete'
    && Array.isArray(result.diagnostics)
    && result.diagnostics.some(issue => issue?.code === 'unsupported-compiler-profile' && !issue.scope)
    && empty(result.findings) && empty(result.entrypoints) && empty(result.coverage.resolved)
    && empty(result.coverage.completedEntries) && empty(result.coverage.detectors)
    && (result.coverage.rules === undefined || empty(result.coverage.rules))
    && (result.ruleObservationWork === undefined || empty(result.ruleObservationWork))
    && ['frontendMs', 'analysisMs', 'detectorMs', 'cfgNodes', 'instructionNodes', 'calls', 'steps', 'sources', 'paths', 'abstractValues',
      'summaryHits', 'summaryEntries', 'statefulSummaryHits', 'readSummaryHits', 'summaryEffects', 'guardSubsumptions']
      .every(key => result.metrics?.[key] === 0);
}

export function scanCategory(result, processError) {
  const roots = result?.coverage?.noEntrypointRoots ?? [];
  const notice = diagnostic => diagnostic.code === 'no-entrypoints-analyzed'
    && diagnostic.message === 'No entrypoints analyzed; declaration checks completed.' && !diagnostic.scope
    && roots.includes(diagnostic.location?.file) && diagnostic.location.start === 0 && diagnostic.location.end === 0
    && diagnostic.location.line === 1 && diagnostic.location.column === 1 && diagnostic.location.endLine === 1 && diagnostic.location.endColumn === 1;
  if (roots.some(root => (result?.diagnostics ?? []).filter(item => notice(item) && item.location.file === root).length !== 1)) return 'other-incomplete';
  const diagnostics = (result?.diagnostics ?? []).filter(diagnostic => !diagnostic.scope && !notice(diagnostic));
  if (processError || !result) return 'other-incomplete';
  const marked = result.coverage?.noEntrypointRoots ?? [];
  const empty = Array.isArray(result.entrypoints) && !result.entrypoints.length;
  if (marked.length && (!empty || result.status !== 'complete' || diagnostics.length || marked.length !== 1
    || result.coverage?.resolved?.length !== 1 || marked[0] !== result.coverage.resolved[0])) return 'other-incomplete';
  if (empty && !marked.length && (result.coverage?.baselineStatus ?? result.status) === 'complete') return 'other-incomplete';
  if (!diagnostics.length && (result.coverage?.baselineStatus ?? result.status) === 'complete') return 'complete';
  if (diagnostics.some(diagnostic => diagnostic.code.startsWith('worker-'))) return 'other-incomplete';
  if (diagnostics.some(diagnostic => diagnostic.code.endsWith('-budget') || diagnostic.code === 'call-depth')) return 'budget';
  if (!result.coverage?.resolved?.length) return 'frontend';
  return 'other-incomplete';
}

export function summarize(rows) {
  const categories = ['complete', 'frontend', 'budget', 'other-incomplete'];
  const findings = rows.flatMap(row => row.findings);
  const timing = selected => {
    const values = selected.map(row => row.elapsedSeconds).sort((a, b) => a - b);
    return values.length ? { medianSeconds: (values[Math.floor((values.length - 1) / 2)] + values[Math.floor(values.length / 2)]) / 2,
      p95Seconds: values[Math.ceil(values.length * 0.95) - 1], maxSeconds: values.at(-1) } : null;
  };
  return { apps: rows.length, ...Object.fromEntries(categories.map(category => [category, rows.filter(row => row.category === category).length])),
    noEntrypointRoots: rows.filter(row => row.completionLabel === "no entrypoints analyzed").length,
    frontendAccepted: rows.filter(row => row.frontendAccepted).length, findings: findings.length,
    selectedRulesComplete: rows.filter(row => (row.selectedRulesStatus ?? (row.category === "complete" ? "complete" : "incomplete")) === "complete").length,
    ruleCoverage: [...new Set(rows.flatMap(row => (row.ruleCoverage ?? []).map(item => item.detectorId)))].map(detectorId => {
      const entries = rows.flatMap(row => row.ruleCoverage ?? []).filter(item => item.detectorId === detectorId);
      return { detectorId, entries: entries.length, complete: entries.filter(item => item.status === "complete").length, notApplicable: entries.filter(item => item.status === "not-applicable").length, incomplete: entries.filter(item => item.status === "incomplete").length };
    }),
    precisionEligibleFindings: findings.filter(finding => finding.precisionScope === 'eligible').length,
    precisionExcludedFindings: findings.filter(finding => ['compiler-fixture', 'intentional-helper-exposure'].includes(finding.precisionScope)).length,
    precisionUnclassifiedFindings: findings.filter(finding => !['eligible', 'compiler-fixture', 'intentional-helper-exposure'].includes(finding.precisionScope)).length,
    timing: { all: timing(rows), complete: timing(rows.filter(row => row.category === 'complete')) } };
}

export function summarizeCorpus(rows, compilerRejected) {
  return { ...summarize(rows), totalApps: rows.length + compilerRejected.length, compilerRejected: compilerRejected.length };
}

export function firstFrontendFailures(rows) {
  return rows.filter(row => !row.frontendAccepted && !row.processError && row.diagnostics.length
    && !row.diagnostics.some(diagnostic => diagnostic.code.startsWith('worker-')))
    .map(row => ({ repository: row.repository, file: row.file, diagnostic: row.diagnostics[0] }));
}

async function main() {
  const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
  const startedAt = new Date();
  const start = performance.now();
  const arguments_ = process.argv.slice(2);
  const options = new Map();
  for (let index = 0; index < arguments_.length; index++) {
    const flag = arguments_[index];
    if (flag === '--help') {
      console.log('npm run bench:compat -- --manifest FILE [--references DIR] [--output NEW_DIRECTORY] [--workers N] [--mode audit|baseline] [--max-paths N] [--max-steps N] [--detectors ID,ID] [--cli BUILT_CLI]\nBaseline mode uses the matching built isolated API with no detectors; audit uses CLI defaults. Uses existing dist, supervised workers, pinned clean external sources and recorded compiler results per version. Writes report.json, table.md and raw scans outside the repository. Findings and known compatibility gaps do not fail the command; setup/process failures do.');
      process.exit(0);
    }
    if (!['--manifest', '--references', '--output', '--workers', '--mode', '--max-paths', '--max-steps', '--detectors', '--cli'].includes(flag) || options.has(flag)) throw new Error(`Unknown or duplicate option: ${flag}`);
    const value = arguments_[++index];
    if (!value || value.startsWith('--')) throw new Error(`${flag} requires a value`);
    if (['--max-paths', '--max-steps', '--workers'].includes(flag) && (!/^[1-9]\d*$/.test(value) || !Number.isSafeInteger(Number(value)))) throw new Error(`${flag} requires a positive safe integer`);
    options.set(flag, value);
  }
  const mode = options.get('--mode') ?? 'audit';
  if (!['audit', 'baseline'].includes(mode)) throw new Error('--mode must be audit or baseline');
  if (mode === 'baseline' && options.has('--detectors')) throw new Error('Baseline mode cannot select detectors');
  if (!options.has('--manifest')) throw new Error('--manifest FILE is required; corpus inputs must be provided explicitly');
  const manifestPath = resolve(options.get('--manifest'));
  const manifestBytes = readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes);
  const workers = Number(options.get('--workers') ?? Math.min(32, availableParallelism()));
  if (workers > 64) throw new Error('--workers must not exceed 64');
  const references = resolve(options.get('--references') ?? join(homedir(), '.cache', 'nightshade', 'references'));
  const output = resolve(options.get('--output') ?? join(references, 'nightshade-compat', startedAt.toISOString().replaceAll(':', '-')));
  if (!relative(repository, output).startsWith('..' + sep)) throw new Error('Compatibility output must be outside the repository');
  if (existsSync(output)) throw new Error(`Refusing to overwrite existing output: ${output}`);
  const cli = resolve(options.get('--cli') ?? join(repository, 'dist/src/cli.js'));
  const buildDirectory = dirname(cli);
  if (!existsSync(cli)) throw new Error('Built CLI missing; run npm run build first');
  const baselineAdapter = resolve(repository, 'scripts/bench-baseline.mjs');
  const baselineIndex = join(buildDirectory, 'index.js');
  if (mode === 'baseline' && !existsSync(baselineIndex)) throw new Error('Baseline mode requires index.js beside the measured CLI');
  const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }).trim();
  const pins = manifest.repositories.map(pin => {
    const directory = join(references, pin.name);
    const commit = git(directory, ['rev-parse', 'HEAD']);
    if (commit !== pin.commit) throw new Error(`${pin.name}: expected ${pin.commit}, found ${commit}`);
    const changes = git(directory, ['status', '--porcelain', '--untracked-files=all']);
    if (changes) throw new Error(`${pin.name}: reference checkout must be clean\n${changes}`);
    return { ...pin, directory };
  });
  for (const app of manifest.apps) {
    const file = join(references, app.repository, app.file);
    if (sha256(readFileSync(file)) !== app.sha256) throw new Error(`Source checksum mismatch: ${app.repository}/${app.file}`);
  }
  // Hash the executed build separately from the source commit. A dirty source tree
  // or stale dist cannot be mistaken for a qualified build of that commit.
  function treeDigest(directory) {
    const hash = createHash('sha256');
    function visit(current) {
      for (const entry of readdirSync(current).sort()) {
        const path = join(current, entry);
        if (statSync(path).isDirectory()) visit(path);
        else { hash.update(relative(directory, path)); hash.update('\0'); hash.update(readFileSync(path)); }
      }
    }
    visit(directory);
    return hash.digest('hex');
  }
  for (const dependency of manifest.dependencyTrees ?? []) {
    if (treeDigest(join(references, dependency.directory)) !== dependency.sha256) throw new Error(`Dependency checksum mismatch: ${dependency.directory}`);
  }
  const analyzer = { sourceCheckoutCommit: git(repository, ['rev-parse', 'HEAD']), sourceCheckoutChanges: git(repository, ['status', '--porcelain']), cli, cliOverride: options.has('--cli'), distSha256: treeDigest(buildDirectory), node: process.version, platform: process.platform, arch: process.arch };
  if (mode === 'baseline') analyzer.baselineAdapter = { path: baselineAdapter, sha256: sha256(readFileSync(baselineAdapter)) };
  mkdirSync(join(output, 'scans'), { recursive: true });
  // An explicit empty configuration makes the default policy/budget selection
  // reproducible even if an app directory happens to carry nightshade.json.
  const config = join(output, 'default-config.json');
  writeFileSync(config, '{"version":1}\n');
  const normalize = text => String(text).replaceAll(references + '/', '');
  const span = location => location && ({ file: normalize(location.file), line: location.line, column: location.column });
  const budgetFlags = ['--max-paths', '--max-steps'].flatMap(flag => options.has(flag) ? [flag, options.get(flag)] : []);
  const detectorFlags = options.has('--detectors') ? ['--detectors', options.get('--detectors')] : [];
  function scan(app, index) {
    return new Promise(resolveResult => {
      const file = join(references, app.repository, app.file);
      const importFlags = app.searchPaths?.length ? ['--compact-path', app.searchPaths.map(path => join(references, path)).join(delimiter)] : [];
      const profile = app.compilerProfile === 'zkir3' ? 3 : 2;
      const args = mode === 'baseline'
        ? [baselineAdapter, baselineIndex, JSON.stringify({ file, options: { compilerVersion: app.compilerVersion, zkirVersion: profile,
          searchPaths: (app.searchPaths ?? []).map(path => join(references, path)),
          ...(options.has('--max-paths') ? { maxPaths: Number(options.get('--max-paths')) } : {}),
          ...(options.has('--max-steps') ? { maxSteps: Number(options.get('--max-steps')) } : {}) } })]
        : [cli, 'scan', file, '--json', '--config', config, '--compiler-version', app.compilerVersion, '--zkir-version', String(profile), ...importFlags, ...budgetFlags, ...detectorFlags];
      const begun = performance.now();
      const child = spawn(process.execPath, args, { cwd: output, env: { ...process.env, COMPACT_PATH: '' }, stdio: ['ignore', 'pipe', 'pipe'] });
      const stdout = [], stderr = [];
      let outputBytes = 0, processError;
      child.stdout.on('data', bytes => {
        outputBytes += bytes.length;
        if (outputBytes > 32 * 1024 * 1024) { processError = 'CLI output exceeded 32 MiB'; child.kill('SIGKILL'); }
        else stdout.push(bytes);
      });
      child.stderr.on('data', bytes => stderr.push(bytes));
      child.on('error', error => { processError = error.message; });
      const timer = setTimeout(() => { processError = 'CLI did not exit within 75 seconds'; child.kill('SIGKILL'); }, 75000);
      child.on('close', (exitCode, signal) => {
        clearTimeout(timer);
        const raw = Buffer.concat(stdout).toString();
        const rawFile = `scans/${String(index + 1).padStart(3, '0')}.json`;
        writeFileSync(join(output, rawFile), raw);
        const errorText = Buffer.concat(stderr).toString();
        if (errorText) writeFileSync(join(output, rawFile + '.stderr'), errorText);
        let result;
        try { result = JSON.parse(raw); }
        catch { processError ??= 'CLI returned invalid JSON'; }
        if (![0, 1, 2].includes(exitCode)) processError ??= `CLI exit ${exitCode}, signal ${signal}`;
        if (result && (!Array.isArray(result.diagnostics) || !Array.isArray(result.findings) || !Array.isArray(result.coverage?.resolved) || !['complete', 'incomplete'].includes(result.status))) processError ??= 'CLI result lacks required fields';
        if (result && !matchesScanProfile(result, app.compilerVersion, profile)) processError ??= 'CLI returned the wrong semantic profile';
        const diagnostics = (Array.isArray(result?.diagnostics) ? result.diagnostics : []).map(diagnostic => ({ code: diagnostic.code, message: normalize(diagnostic.message), location: span(diagnostic.location), ...(diagnostic.scope ? { scope: diagnostic.scope } : {}) })) ?? [];
        const category = scanCategory(result, processError);
        const findings = (Array.isArray(result?.findings) ? result.findings : []).map(finding => ({ detectorId: finding.detectorId, severity: finding.severity, message: finding.message, location: span(finding.location), callPath: finding.callPath, fingerprint: finding.fingerprint, precisionScope: precisionScope(app, finding) })) ?? [];
        resolveResult({ ...app, requestedSemanticProfile: `compact-${app.compilerVersion}-zkir${profile}`, reportedSemanticProfile: result?.semanticProfile,
          category, ...(category === "complete" && result?.coverage?.noEntrypointRoots?.length ? { completionLabel: "no entrypoints analyzed", noEntrypointRoots: result.coverage.noEntrypointRoots } : {}), frontendAccepted: !!result?.coverage?.resolved?.length, ...(processError ? { processError } : {}), exitCode, elapsedSeconds: Number(((performance.now() - begun) / 1000).toFixed(3)), completedEntries: result?.coverage?.completedEntries?.length ?? 0, entrypoints: result?.entrypoints?.length ?? 0, diagnostics, findings, selectedRulesStatus: result?.status, ruleCoverage: result?.coverage?.rules ?? [], metrics: result?.metrics, rawFile });
      });
    });
  }
  const apps = manifest.apps.filter(app => app.compilerExitCode === 0);
  const rows = new Array(apps.length);
  let next = 0;
  await Promise.all(Array.from({ length: workers }, async () => {
    for (;;) {
      const index = next++;
      if (index >= apps.length) break;
      rows[index] = await scan(apps[index], index);
    }
  }));
  const buildChangedDuringRun = treeDigest(buildDirectory) !== analyzer.distSha256
    || !!analyzer.baselineAdapter && sha256(readFileSync(baselineAdapter)) !== analyzer.baselineAdapter.sha256;
  const compilerRejected = manifest.apps.filter(app => app.compilerExitCode !== 0);
  const groups = pins.map(pin => ({ repository: pin.name, kind: pin.kind, ...summarizeCorpus(rows.filter(row => row.repository === pin.name), compilerRejected.filter(row => row.repository === pin.name)) }));
  const versionGroups = pins.flatMap(pin => [...new Set(manifest.apps.filter(app => app.repository === pin.name).map(app => app.compilerVersion))].sort().map(compilerVersion => ({
    repository: pin.name, compilerVersion, languageVersion: manifest.compilerProfiles[compilerVersion].languageVersion,
    ...summarizeCorpus(rows.filter(row => row.repository === pin.name && row.compilerVersion === compilerVersion), compilerRejected.filter(row => row.repository === pin.name && row.compilerVersion === compilerVersion)),
  })));
  const report = { analysisMode: mode === 'baseline' ? 'baseline' : options.has('--detectors') ? 'selected-detectors' : 'audit', startedAt: startedAt.toISOString(), elapsedSeconds: Number(((performance.now() - start) / 1000).toFixed(3)), analyzer, manifestPath, population: manifest.population ?? null, manifestSha256: sha256(manifestBytes), compilerEvidence: manifest.compilerProfiles, sourcePins: pins, dependencyTrees: manifest.dependencyTrees ?? [], workers, buildChangedDuringRun, overrides: Object.fromEntries(budgetFlags.reduce((pairs, flag, index) => index % 2 ? pairs : [...pairs, [flag, Number(budgetFlags[index + 1])]], [])), summary: summarize(rows), realApplications: summarizeCorpus(rows.filter(row => row.repository !== 'compact-compiler'), compilerRejected.filter(row => row.repository !== 'compact-compiler')), groups, versionGroups, firstFrontendFailures: firstFrontendFailures(rows), rows, compilerRejected, excludedLibraries: manifest.excludedLibraries, excludedRepositories: manifest.excludedRepositories ?? [] };
  if (detectorFlags.length) report.overrides.detectors = options.get('--detectors').split(',');
  writeFileSync(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  const cell = text => String(text ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
  const position = location => location ? `${location.file}:${location.line}` : '';
  const table = [
    `Source checkout: ${analyzer.sourceCheckoutCommit.slice(0, 12)}${analyzer.sourceCheckoutChanges ? " (dirty)" : ""}; measured CLI: ${cli}; ${analyzer.node}; ${report.elapsedSeconds}s; ${workers} workers. Budget overrides: ${budgetFlags.length ? budgetFlags.join(" ") : "none"}.`,
    `Detector selection: ${mode === 'baseline' ? 'none (baseline only)' : options.get('--detectors') ?? 'audit default'}.`,
    '',
    'Existing dist was measured (SHA-256 recorded in report.json); the command does not build. Sources are fixed, clean checkouts. Compiler validity is recorded per-version --skip-zk evidence, not recompiled each run. Each scan selects its recorded compiler and ZKIR profile.',
    '',
    `Whole real corpus baseline: ${report.realApplications.complete}/${report.realApplications.totalApps} complete; ${report.realApplications.compilerRejected} compiler rejected. Scanner-qualified subset: ${report.realApplications.complete}/${report.realApplications.apps}.`,
    '',
    '| Source | Compiler / language | All apps | Complete | Frontend | Budget | Other incomplete | Findings | Compiler rejected |',
    '|---|---|---:|---:|---:|---:|---:|---:|---:|',
    ...versionGroups.map(row => `| ${row.repository} | ${row.compilerVersion} / ${row.languageVersion} | ${row.totalApps} | ${row.complete} | ${row.frontend} | ${row.budget} | ${row['other-incomplete']} | ${row.findings} | ${row.compilerRejected} |`),
    '',
    mode === 'baseline' ? 'Baseline-only run selects no detectors; selected-rule status does not certify security rules.' : `Selected rules: ${rows.filter(row => row.repository !== 'compact-compiler' && row.selectedRulesStatus === 'complete').length}/${report.realApplications.totalApps} real roots complete for all selected rules. Rule-specific unavailable entries remain in report.json; baseline completion does not certify those rules.`,
    '',
    'Precision exclusions retain all findings and coverage: compiler fixtures are a separate conformance tier; pinned OZ internal-helper mock entries are excluded from real-app precision. Eligible findings still require adjudication; absence of findings is not a measured precision rate.',
    '',
    '| Source | Frontend accepted | Precision-eligible findings | Excluded findings | Complete-only median / p95 seconds |',
    '|---|---:|---:|---:|---|',
    ...groups.map(row => `| ${row.repository} | ${row.frontendAccepted}/${row.apps} | ${row.precisionEligibleFindings} | ${row.precisionExcludedFindings} | ${row.timing.complete ? `${row.timing.complete.medianSeconds.toFixed(3)} / ${row.timing.complete.p95Seconds.toFixed(3)}` : 'n/a'} |`),
    '',
    '| App | Compiler profile | Scan | Entries | First diagnostic | Findings | Seconds |',
    '|---|---|---|---:|---|---:|---:|',
    ...rows.map(row => `| ${cell(row.repository + '/' + row.file)} | ${row.compilerVersion} ${row.compilerProfile} | ${row.completionLabel ?? row.category} | ${row.completedEntries}/${row.entrypoints} | ${cell(row.processError ?? (row.diagnostics[0] ? `${row.diagnostics[0].code}: ${row.diagnostics[0].message} (${position(row.diagnostics[0].location)})` : ''))} | ${row.findings.length} | ${row.elapsedSeconds} |`),
    '',
    'First front-end failures (including front-end budgets; later blockers are not yet observed):',
    '',
    '| App | First front-end diagnostic |',
    '|---|---|',
    ...report.firstFrontendFailures.map(row => `| ${cell(row.repository + '/' + row.file)} | ${cell(`${row.diagnostic.code}: ${row.diagnostic.message} (${position(row.diagnostic.location)})`)} |`),
    '',
    'Compiler-rejected inputs remain in the whole-corpus denominator and outside the scanner-qualified subset:',
    '',
    '| App | Compiler profile | First compiler rejection |',
    '|---|---|---|',
    ...compilerRejected.map(row => `| ${cell(row.repository + '/' + row.file)} | ${row.compilerVersion} ${row.compilerProfile} | ${cell(row.compilerError)} |`),
    '',
    `Excluded library-only files: ${manifest.excludedLibraries.length}; exact paths are retained in report.json and the input manifest.`,
    ''
  ];
  writeFileSync(join(output, 'table.md'), table.join('\n'));
  console.log(JSON.stringify({ elapsedSeconds: report.elapsedSeconds, summary: report.summary, groups, output }, null, 2));
  if (buildChangedDuringRun || rows.some(row => row.processError || row.diagnostics.some(diagnostic => diagnostic.code.startsWith('worker-')))) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
