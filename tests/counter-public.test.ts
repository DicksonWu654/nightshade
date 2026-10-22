import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import childProcess, { type SpawnOptions } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { Ajv } from "ajv";
import AjvDraft04 from "ajv-draft-04";
import { Dataflow, Program, scanFile, scanFileIsolated, mergeResults, emptyResult, type ScanOptions, type ScanResult, type ExperimentalCounterScanResult, type Policies } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { detectors } from "../src/detectors/index.js";
import { readConfiguration, applyWorkflow, exitStatus } from "../src/config.js";
import { human, sarif } from "../src/reporting/index.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const experimental = { experimentalCounterQueries: true };
const auditHygiene = new Set([
  "unnecessary-disclose",
  "time-dependence",
  "unused-declaration",
  "always-true-assertion",
  "dead-code",
  "constant-condition",
  "shadowing",
]);
const defaultDetectorIds = detectors.filter(detector => detector.defaultEnabled !== false && detector.id !== "openzeppelin-preconditions" && !auditHygiene.has(detector.id)).map(detector => detector.id);
const source = (size: number, reset = false, returned = false) => `pragma language_version 0.26.0;
import CompactStandardLibrary;
export ledger count: Counter;
export ledger phase: Uint<8>;
circuit guard(): [] { assert(true, "fixture guard"); }
circuit helper(value: Field): Field { return value + 1; }
export circuit entry(unused: Field, ${Array.from({ length: size }, (_, i) => `flag${i}: Boolean`).join(",")}): [] {
${reset ? "count.resetToDefault();" : ""}
${Array.from({ length: size }, (_, i) => `if (disclose(flag${i})) { count.increment(${i % 2 ? 65535 : 0}); }`).join("\n")}
${returned ? "return [];" : ""}}
`;
const configured = (size: number): Policies => ({ secrets: [{ circuit: "entry", parameter: "unused" }, ...Array.from({ length: size }, (_, i) => ({ circuit: "entry", parameter: `flag${i}` }))],
  authorization: [{ state: "count", guard: "guard" }], transitions: [{ state: "phase", from: "0", to: "1" }],
  workBudgets: [{ circuit: "entry", maxUnits: 1 }, { circuit: "helper", maxUnits: 1 }] });
const run = (...args: string[]) => spawnSync(process.execPath, [resolve("dist/src/cli.js"), ...args], { encoding: "utf8", timeout: 15000 });
function counter(result: ScanResult): ExperimentalCounterScanResult {
  assert.equal(result.schemaVersion, "1.7.0");
  if (result.schemaVersion !== "1.7.0") throw new Error("Expected experimental report");
  return result;
}
function compile(file: string): void {
  const result = validateWithCompiler(process.env.COMPACTC_TEST!, file);
  assert.equal(result.valid, true, result.error);
}
const withoutTimings = (report: ScanResult) => ({ ...report, metrics: Object.fromEntries(Object.entries(report.metrics).filter(([key]) => !key.endsWith("Ms"))) });

for (let size = 1; size <= 8; size++) test(`${size}-choice public predicate scan preserves complete exact finding objects`, qualified, () => {
  withFiles({ "main.compact": source(size, size % 2 === 0, size % 2 !== 0) }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const policies = configured(size);
    const exact = scanFile(file, { policies });
    const result = counter(scanFile(file, { ...experimental, policies }));
    assert.equal(exact.status, "complete", JSON.stringify(exact.diagnostics));
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings, exact.findings);
    assert.deepEqual(result.analysis.coverage.map(row => row.detector), defaultDetectorIds);
    assert.ok(result.analysis.coverage.every(row => row.status === "covered" && row.root === realpathSync(file)));
    assert.deepEqual(result.coverage.completedEntries, []);
    assert.equal(result.metrics.paths, 0);
    assert.equal(result.metrics.detectorMs, 0);
    assert.ok(result.metrics.analysisMs > 0);
    assert.equal(result.analysis.queryWork.expenditureKnown, true);
    assert.equal(result.analysis.queryWork.witnesses, size);
    assert.equal(result.analysis.workPolicies.length, 2);
    assert.ok(result.analysis.workPolicies.every(row => row.status === "covered" && row.root === realpathSync(file)));
    assert.equal(result.compilerValidated, false, "Predicate coverage never implies compiler validation");
    assert.deepEqual(withoutTimings(scanFile(file, { policies, experimentalCounterQueries: false })), withoutTimings(exact));
    assert.equal("analysis" in exact, false);
  });
});

test("unchanged ten-branch source has 65 synthetic findings and all default predicate obligations without exact completion", qualified, () => {
  const text = `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: 10 }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { ${Array.from({ length: 10 }, (_, index) => `if (disclose(flag${index})) { count.increment(1); }`).join(" ")} }`;
  withFiles({ "main.compact": text }, directory => {
    const file = resolve(directory, "main.compact");
    const policies: Policies = { secrets: Array.from({ length: 10 }, (_, index) => ({ circuit: "entry", parameter: `flag${index}` })), authorization: [{ state: "count", guard: "entry" }] };
    const exact = new Dataflow(new Program(file)).analyze();
    assert.deepEqual(exact.completedEntries, []);
    assert.ok(exact.diagnostics.some(row => row.code === "analysis-budget"));
    const result = counter(scanFile(file, { ...experimental, policies, compiler: process.env.COMPACTC_TEST }));
    assert.equal(result.compilerValidated, true, result.compiler?.error);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 65);
    assert.equal(result.findings.filter(row => row.detectorId === "declared-secret-publication").length, 55);
    assert.equal(result.findings.filter(row => row.detectorId === "unguarded-sensitive-state-write").length, 10);
    assert.deepEqual(result.analysis.coverage.map(row => row.detector), defaultDetectorIds);
    assert.ok(result.analysis.coverage.every(row => row.status === "covered"));
    assert.deepEqual(result.coverage.completedEntries, []);
    assert.equal(result.metrics.paths, 0);
    assert.equal(result.analysis.queryWork.witnesses, 10);
    const expected = Array.from({ length: 10 }, (_, site) => Array.from({ length: site + 1 }, (_, secret) => `flag${secret}:${text.indexOf("count.increment(1)", text.indexOf(`if (disclose(flag${site}))`))}`)).flat().sort();
    assert.deepEqual(result.findings.filter(row => row.detectorId === "declared-secret-publication").map(row => `${/Secret (\w+) influences/.exec(row.message)![1]}:${row.location.start}`).sort(), expected);
    const noPolicies = counter(scanFile(file, experimental));
    assert.equal(noPolicies.status, "complete");
    assert.deepEqual(noPolicies.findings, []);
    assert.deepEqual(noPolicies.analysis.coverage.map(row => row.detector), defaultDetectorIds);
    assert.ok(noPolicies.analysis.coverage.every(row => row.status === "covered"));
    assert.ok(human(noPolicies).includes(`${defaultDetectorIds.length}/${defaultDetectorIds.length} selected detector predicate(s) covered; 0/1 entrypoint(s) completed by exact fallback`));
  });
});

test("mixed exact and query entries preserve full findings, caller provenance and work-policy multiplicity", qualified, () => {
  withFiles({ "main.compact": source(2) + 'constructor() { phase = 0; } export circuit later(flag: Boolean): [] { entry(0 as Field, flag, flag); }' }, directory => {
    const file = resolve(directory, "main.compact"); compile(file);
    const policies = configured(2);
    policies.workBudgets = [{ circuit: "entry", maxUnits: 1 }, { circuit: "entry", maxUnits: 2 }];
    const exact = scanFile(file, { policies });
    const result = counter(scanFile(file, { ...experimental, policies }));
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings, exact.findings);
    assert.equal(result.coverage.completedEntries.length, 2);
    assert.ok(result.metrics.paths > 0);
    assert.equal(result.analysis.coverage.length, 3 * defaultDetectorIds.length);
    assert.ok(result.analysis.coverage.some(row => row.method === "exact"));
    assert.ok(result.analysis.coverage.some(row => row.method === "counter-query"));
    const work = result.findings.filter(row => row.detectorId === "circuit-work-budget");
    assert.equal(work.length, 2);
    assert.equal(work[0].fingerprint, work[1].fingerprint);
    assert.deepEqual(work.map(row => row.metadata.budget), [1, 2]);
    assert.ok(result.findings.filter(row => row.detectorId === "unguarded-sensitive-state-write").every(row => row.callPath.join("/") === "later/entry"));
  });
});

test("lookalike continuation, assertion and helper effects use exact fallback", qualified, () => {
  for (const suffix of ['guard();', 'assert(disclose(flag0), "later");', 'count.read();']) withFiles({ "main.compact": source(2, false, true).replace("return [];", `${suffix} return [];`) }, directory => {
    const file = resolve(directory, "main.compact"); compile(file);
    const exact = scanFile(file, { policies: configured(2) });
    const result = counter(scanFile(file, { ...experimental, policies: configured(2) }));
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings, exact.findings);
    assert.deepEqual(result.coverage.completedEntries, exact.coverage.completedEntries);
    assert.equal(result.analysis.queryWork.witnesses, 0);
    assert.ok(result.analysis.coverage.every(row => row.method === "exact" || row.method === "source-work"));
  });
});

test("incomplete fallback and unavailable helper work cannot be hidden by covered query predicates", () => {
  withFiles({ "main.compact": source(2) + 'export circuit expensive(values: Vector<8, Field>): [] {} circuit hidden(): [] { hidden(); }' }, directory => {
    const result = counter(scanFile(resolve(directory, "main.compact"), { ...experimental, maxValues: 4, policies: { workBudgets: [{ circuit: "hidden", maxUnits: 100 }] } }));
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(row => row.code === "value-budget"));
    assert.ok(result.diagnostics.some(row => row.code === "work-estimate-unavailable"));
    assert.ok(result.analysis.coverage.some(row => row.status === "covered"));
    assert.ok(result.analysis.coverage.some(row => row.status === "incomplete"));
    assert.equal(result.analysis.workPolicies[0].status, "incomplete");
  });
});

test("original transfer budgets and unknown query expenditure remain explicit", () => {
  withFiles({ "main.compact": source(2) }, directory => {
    const file = resolve(directory, "main.compact");
    for (const budget of [{ maxSteps: 1 }, { maxValues: 1 }]) {
      const result = counter(scanFile(file, { ...experimental, ...budget }));
      assert.equal(result.status, "incomplete");
      assert.ok(result.diagnostics.length);
      assert.equal(result.analysis.queryWork.expenditureKnown, false);
      assert.deepEqual(result.coverage.completedEntries, []);
    }
    const structural = counter(scanFile(file, { ...experimental, maxSteps: 1, maxValues: 1, maxPaths: 1, detectors: ["impossible-assertion"] }));
    assert.equal(structural.status, "complete");
    assert.equal(structural.analysis.coverage.length, 1);
    assert.equal(structural.analysis.coverage[0].method, "structural-absence");
    assert.equal(structural.analysis.queryWork.witnesses, 0);
    assert.equal(structural.analysis.queryWork.expenditureKnown, true);
  });
});

test("API rejects empty experimental selection and nonboolean opt-ins while retaining frontend failure mode", () => {
  withFiles({ "main.compact": source(1), "invalid.compact": 'export circuit entry(): [] { missing(); }' }, directory => {
    const file = resolve(directory, "main.compact");
    const empty = counter(scanFile(file, { ...experimental, detectors: [] }));
    assert.equal(empty.status, "incomplete"); assert.equal(empty.diagnostics[0].code, "invalid-config");
    assert.equal(scanFile(file, { detectors: [] }).status, "complete", "Default exact selection behavior is unchanged");
    for (const value of ["true", 1, null, [], {}]) {
      const invalid = scanFile(file, { experimentalCounterQueries: value } as unknown as ScanOptions);
      assert.equal(invalid.status, "incomplete"); assert.equal(invalid.diagnostics[0].code, "invalid-config");
    }
    for (const filename of ["invalid.compact", "missing.compact"]) {
      const result = counter(scanFile(resolve(directory, filename), experimental));
      assert.equal(result.status, "incomplete"); assert.ok(result.diagnostics.length);
      assert.deepEqual(result.analysis.coverage, []); assert.deepEqual(result.coverage.completedEntries, []);
    }
  });
});

test("experimental merge uses root/entry/detector identity and canonical scan roots", qualified, () => {
  withFiles({ "Shared.compact": `module Shared { ${source(1).replace('pragma language_version 0.26.0;', '')} }`, "first.compact": 'import "Shared"; export { entry, count, phase };', "second.compact": 'import "Shared"; export { entry, count, phase };' }, directory => {
    const first = resolve(directory, "first.compact"), second = resolve(directory, "second.compact"), alias = resolve(directory, "alias.compact");
    compile(first); compile(second);
    symlinkSync(first, alias);
    const a = counter(scanFile(first, experimental)), b = counter(scanFile(second, experimental)), linked = counter(scanFile(alias, experimental));
    assert.equal(a.status, "complete", JSON.stringify(a.diagnostics));
    assert.equal(b.status, "complete", JSON.stringify(b.diagnostics));
    assert.notDeepEqual(a.entrypoints, b.entrypoints, "Shared module declarations retain compilation-unit identities");
    assert.deepEqual(linked.analysis.coverage, a.analysis.coverage);
    const merged = counter(mergeResults([a, b, linked]));
    assert.equal(merged.status, "complete"); assert.equal(merged.analysis.coverage.length, 2 * defaultDetectorIds.length);
    assert.deepEqual(new Set(merged.analysis.coverage.map(row => row.root)), new Set([first, second]));
    assert.equal(merged.analysis.queryWork.witnesses, a.analysis.queryWork.witnesses * 3);
    // Exercise the report tuple-key contract independently of today's symbol-ID format.
    const collidingEntry = structuredClone(b);
    collidingEntry.analysis.coverage.forEach(row => { row.entry = a.entrypoints[0]; });
    assert.equal(counter(mergeResults([a, collidingEntry])).analysis.coverage.length, 2 * defaultDetectorIds.length);
    const uncertain = structuredClone(a); uncertain.analysis.queryWork.expenditureKnown = false;
    assert.equal(counter(mergeResults([a, uncertain])).analysis.queryWork.expenditureKnown, false);
    assert.equal(mergeResults([scanFile(first), scanFile(second)]).schemaVersion, "1.6.0");
    assert.equal(emptyResult().schemaVersion, "1.6.0");
    assert.equal(mergeResults([]).schemaVersion, "1.6.0");
  });
});

test("exact detector failures retain original entry completion and diagnostic mutations", () => {
  withFiles({ "main.compact": source(1) }, directory => {
    const file = resolve(directory, "main.compact"), detector = detectors[0], original = detector.run;
    const before = scanFile(file, { detectors: [detector.id] });
    try {
      detector.run = facts => {
        facts.diagnostics.push({ code: "synthetic-detector-diagnostic", message: "Deliberate diagnostic before detector failure", location: facts.program.rootSource.ast.span });
        throw new Error("Deliberate detector failure");
      };
      const result = scanFile(file, { detectors: [detector.id] });
      assert.equal(result.schemaVersion, "1.6.0"); assert.equal(result.status, "incomplete");
      assert.deepEqual(result.entrypoints, before.entrypoints);
      assert.deepEqual(result.coverage.completedEntries, before.coverage.completedEntries);
      assert.deepEqual(result.scanned, before.scanned);
      assert.deepEqual(result.coverage.attempted, before.coverage.attempted);
      assert.deepEqual(result.coverage.parsed, before.coverage.parsed);
      assert.deepEqual(result.diagnostics.map(row => row.code), ["synthetic-detector-diagnostic", "analysis-error"]);
      assert.equal(result.metrics.instructionNodes, before.metrics.instructionNodes);
    } finally { detector.run = original; }
  });
});

test("coverage conflicts and mixed report modes are explicitly incomplete", () => {
  withFiles({ "main.compact": source(1) }, directory => {
    const file = resolve(directory, "main.compact");
    const result = counter(scanFile(file, { ...experimental, policies: configured(1) }));
    for (const kind of ["method", "status", "contract"] as const) {
      const changed = structuredClone(result);
      if (kind === "method") changed.analysis.coverage[0].method = "unavailable";
      else if (kind === "status") changed.analysis.coverage[0].status = "incomplete";
      else changed.analysis.coverage[0].contract = "different-contract";
      const merged = counter(mergeResults([result, changed, result]));
      assert.equal(merged.status, "incomplete");
      assert.equal(merged.diagnostics.filter(row => row.code === "counter-coverage-conflict").length, 1);
      const conflict = merged.analysis.coverage.find(row => row.detector === result.analysis.coverage[0].detector)!;
      assert.equal(conflict.status, "incomplete"); assert.equal(conflict.method, "unavailable"); assert.equal(conflict.contract, undefined);
    }
    const changed = structuredClone(result); changed.analysis.workPolicies[0].status = "incomplete";
    const work = counter(mergeResults([result, changed, result]));
    assert.equal(work.status, "incomplete"); assert.ok(work.diagnostics.some(row => row.code === "counter-work-policy-conflict"));
    assert.ok(work.analysis.workPolicies.some(row => row.status === "incomplete"));
    const mixed = counter(mergeResults([scanFile(file), result]));
    assert.equal(mixed.status, "incomplete"); assert.ok(mixed.diagnostics.some(row => row.code === "mixed-analysis-modes"));
    assert.deepEqual(mixed.analysis.coverage, counter(mergeResults([result])).analysis.coverage);
  });
});

test("schemas distinguish modes and reject absent or malformed experimental accounting", () => {
  const ajv = new Ajv({ strict: false, allErrors: true });
  const old = ajv.compile(JSON.parse(readFileSync("docs/schema/report.schema.json", "utf8")));
  const current = ajv.compile(JSON.parse(readFileSync("docs/schema/report-counter.schema.json", "utf8")));
  withFiles({ "main.compact": source(2) }, directory => {
    const file = resolve(directory, "main.compact"), exact = scanFile(file), result = counter(scanFile(file, experimental));
    for (const report of [result, scanFile(file, { ...experimental, maxSteps: 1 }), scanFile("missing.compact", experimental), mergeResults([exact, result])]) {
      assert.equal(current(report), true, JSON.stringify(current.errors)); assert.equal(old(report), false);
    }
    assert.equal(old(exact), true); assert.equal(current(exact), false);
    for (const mutate of [
      (report: any) => { delete report.analysis; },
      (report: any) => { report.analysis.scope = "whole-entry"; },
      (report: any) => { report.analysis.contract = "unrecognized"; },
      (report: any) => { report.analysis.queryWork.expenditureKnown = "true"; },
      (report: any) => { report.analysis.queryWork.query = -1; },
      (report: any) => { delete report.analysis.coverage[0].root; },
      (report: any) => { report.analysis.coverage[0].method = "representative-complete"; },
      (report: any) => { report.analysis.coverage[0].unknown = true; },
    ]) { const malformed = structuredClone(result); mutate(malformed); assert.equal(current(malformed), false); }
  });
});

test("official SARIF retains experimental coverage and independent compiler validity", { skip: !process.env.SARIF_SCHEMA }, () => {
  const ajv = new AjvDraft04.default({ strict: false, allErrors: true, validateFormats: false });
  const validate = ajv.compile(JSON.parse(readFileSync(process.env.SARIF_SCHEMA!, "utf8")));
  withFiles({ "main.compact": source(2) }, directory => {
    const file = resolve(directory, "main.compact");
    for (const result of [scanFile(file, { ...experimental, policies: configured(2) }), scanFile(file, { ...experimental, maxSteps: 1 }), scanFile("missing.compact", experimental)]) {
      const output = sarif(result) as any;
      assert.equal(validate(output), true, JSON.stringify(validate.errors));
      assert.equal(output.runs[0].properties.scope, "selected-detector-predicates");
      assert.equal(output.runs[0].properties.analysis.mode, "experimental-counter-queries");
      assert.deepEqual(output.runs[0].properties.exactCompletedEntries, result.coverage.completedEntries);
      assert.equal(output.runs[0].invocations[0].executionSuccessful, result.status === "complete");
    }
  });
});

test("[timing] isolated opt-in preserves report mode, findings and query accounting including timeout", async context => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-counter-public-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = resolve(directory, "main.compact"); writeFileSync(file, source(2));
  const options = { ...experimental, policies: configured(2) };
  const direct = counter(scanFile(file, options)), isolated = counter(await scanFileIsolated(file, options));
  assert.equal(isolated.status, "complete", JSON.stringify(isolated.diagnostics));
  assert.deepEqual(isolated.findings, direct.findings); assert.deepEqual(isolated.coverage, direct.coverage); assert.deepEqual(isolated.analysis, direct.analysis);
  for (const limits of [{ timeoutMs: 1 }, { maxOutputBytes: 1024 }]) {
    const failed = counter(await scanFileIsolated(file, options, limits));
    assert.equal(failed.status, "incomplete"); assert.match(failed.diagnostics[0].code, /^worker-(timeout|output-budget)$/);
    assert.deepEqual(failed.coverage.completedEntries, []); assert.deepEqual(failed.analysis.coverage, []);
    assert.equal(failed.analysis.queryWork.expenditureKnown, false);
  }
});

test("worker protocol rejects mismatched schemas, scopes and experimental contracts", async context => {
  const spawn = childProcess.spawn;
  let response: object = emptyResult();
  // A fixed synthetic worker response exercises the parent protocol without adding a worker/plugin option.
  const mocked = context.mock.method(childProcess, "spawn", (command: string, _args: readonly string[], options: SpawnOptions) =>
    spawn(command, ["-e", "process.stdout.write(process.argv[1]);", JSON.stringify(response)], options));
  syncBuiltinESMExports();
  try {
    const correct = emptyResult(true);
    for (const options of [{}, experimental]) {
      const matching = options === experimental ? correct : emptyResult();
      response = matching;
      assert.equal((await scanFileIsolated("synthetic.compact", options)).status, "complete");
      response = options === experimental ? emptyResult() : correct;
      const report = await scanFileIsolated("synthetic.compact", options);
      assert.equal(report.status, "incomplete"); assert.equal(report.diagnostics[0].code, "worker-protocol");
      assert.equal(report.schemaVersion, options === experimental ? "1.7.0" : "1.6.0");
    }
    for (const mutate of [
      (report: any) => { report.scope = "experimental-subset"; },
      (report: any) => { report.analysis.mode = "exact"; },
      (report: any) => { report.analysis.scope = "whole-entry"; },
      (report: any) => { report.analysis.contract = "unknown"; },
      (report: any) => { delete report.analysis.queryWork.expenditureKnown; },
      (report: any) => { report.analysis.queryWork.witnesses = -1; },
    ]) {
      const changed = structuredClone(correct); mutate(changed); response = changed;
      const report = counter(await scanFileIsolated("synthetic.compact", experimental));
      assert.equal(report.status, "incomplete"); assert.equal(report.diagnostics[0].code, "worker-protocol");
      assert.equal(report.analysis.queryWork.expenditureKnown, false);
    }
  } finally { mocked.mock.restore(); syncBuiltinESMExports(); }
});

test("config booleans and CLI flag are explicit, default exact mode remains unchanged", () => {
  for (const value of [true, false, "true", 1, 0, null, [], {}]) withFiles({ "main.compact": source(2), "config.json": JSON.stringify({ version: 1, roots: ["main.compact"], experimentalCounterQueries: value }) }, directory => {
    const config = resolve(directory, "config.json");
    if (typeof value !== "boolean") {
      assert.throws(() => readConfiguration(config));
      const result = run("--config", config, "--json"); assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).status, "incomplete");
    } else {
      assert.equal(readConfiguration(config).options.experimentalCounterQueries, value);
      const result = run("--config", config, "--fail-on", "none", "--json"); assert.equal(result.status, 0, result.stdout);
      assert.equal(JSON.parse(result.stdout).schemaVersion, value ? "1.7.0" : "1.6.0");
      const overridden = run("--config", config, "--experimental-counter-queries", "--fail-on", "none", "--json"); assert.equal(overridden.status, 0);
      assert.equal(JSON.parse(overridden.stdout).schemaVersion, "1.7.0");
    }
  });
  assert.equal(readConfiguration().options.experimentalCounterQueries, undefined);
});

test("[timing] CLI errors, invalid config, baseline refusal and no-entrypoint preserve requested experimental mode", () => {
  withFiles({ "main.compact": source(2), "library.compact": "module Helper { export circuit helper(): [] {} }", "config.json": JSON.stringify({ version: 1, experimentalCounterQueries: true, unsupported: true }) }, directory => {
    const file = resolve(directory, "main.compact");
    for (const flags of [["--nonsense"], ["--experimental-counter-queries"], ["--max-steps", "0"], ["--detectors", "unknown-rule"], ["--fail-on", "nonsense"], ["--experimental-counter-queries=false"], ["--timeout-ms", "1", "--fail-on", "none"]]) {
      const result = run(file, "--experimental-counter-queries", "--json", ...flags);
      assert.equal(result.status, 2, result.stdout); const report = counter(JSON.parse(result.stdout)); assert.equal(report.status, "incomplete");
    }
    const configuredError = run(file, "--config", resolve(directory, "config.json"), "--json");
    assert.equal(configuredError.status, 2); counter(JSON.parse(configuredError.stdout));
    const baseline = resolve(directory, "baseline.json");
    const incomplete = run(file, "--experimental-counter-queries", "--max-steps", "1", "--write-baseline", baseline, "--json");
    assert.equal(incomplete.status, 2); counter(JSON.parse(incomplete.stdout)); assert.equal(existsSync(baseline), false);
    const library = run(resolve(directory, "library.compact"), "--experimental-counter-queries", "--json");
    const report = counter(JSON.parse(library.stdout)); assert.equal(report.status, "complete");
    assert.deepEqual(report.coverage.noEntrypointRoots, [resolve(directory, "library.compact")]);
    assert.deepEqual(report.diagnostics.map((issue: { code: string }) => issue.code), ["no-entrypoints-analyzed"]);
    // Informational rules are default-on; the ordinary fixture contains
    // unused declarations, so the default fail-on=info exit is intentional.
    const ordinary = run(file, "--profile", "hygiene", "--json"); assert.equal(ordinary.status, 1); assert.equal(JSON.parse(ordinary.stdout).schemaVersion, "1.6.0");
  });
});

test("experimental workflow preserves thresholds, baseline visibility and suppression diagnostics", () => {
  withFiles({ "main.compact": source(2), "config.json": JSON.stringify({ version: 1, roots: ["main.compact"], experimentalCounterQueries: true, policies: configured(2) }) }, directory => {
    const file = resolve(directory, "main.compact"), configFile = resolve(directory, "config.json"), baseline = resolve(directory, "baseline.json");
    const first = run("--config", configFile, "--write-baseline", baseline, "--json"); assert.equal(first.status, 1, first.stdout);
    const next = run("--config", configFile, "--baseline", baseline, "--json"); assert.equal(next.status, 0);
    assert.ok(counter(JSON.parse(next.stdout)).findings.every(row => row.baselineState === "unchanged"));
    assert.equal(run("--config", configFile, "--write-baseline", baseline, "--json").status, 2);
    const result = counter(scanFile(file, { ...experimental, policies: configured(2) })), config = readConfiguration();
    assert.equal(exitStatus(result, config), 1);
    config.failOn = "none"; assert.equal(exitStatus(result, config), 0);
    config.suppressions = result.findings.map(row => ({ fingerprint: row.fingerprint, reason: "Synthetic qualified policy evidence" }));
    applyWorkflow(result, config); assert.ok(result.findings.every(row => row.suppression));
    config.suppressions = [{ fingerprint: "0".repeat(64), reason: "Obsolete synthetic suppression" }];
    applyWorkflow(result, config); assert.equal(result.status, "incomplete"); assert.equal(exitStatus(result, config), 2);
  });
});
