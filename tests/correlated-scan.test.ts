import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { scanFile, Dataflow, Program, detectors, type Policies } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { human } from "../src/reporting/index.js";
import { hygieneOnlyDetectors, withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const parameters = Array.from({ length: 10 }, (_, index) => `flag${index}: Boolean`).join(",");
const body = Array.from({ length: 10 }, (_, index) => `if (disclose(flag${index})) { count.increment(1); }`).join(" ");
const header = "import CompactStandardLibrary; export ledger count: Counter; ";
const entry = (name = "entry") => `export circuit ${name}(${parameters}): [] { ${body} }`;
const unchanged = header + entry();
function fixture(source: string, run: (file: string) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), compiler = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(compiler.valid, true, compiler.error); run(file);
  });
}

test("default scan completes the unchanged ten-branch source while exact path evidence remains separate", qualified, () => {
  fixture(unchanged, file => {
    const program = new Program(file), flow = new Dataflow(program), reference = flow.analyze();
    assert.deepEqual(reference.completedEntries, []);
    assert.ok(reference.diagnostics.some(item => item.code === "analysis-budget"));
    const analyzed = flow.analyzeWithCorrelatedQueries([]);
    assert.deepEqual(analyzed.exact.completedEntries, []); assert.deepEqual(analyzed.exact.paths, []);
    assert.equal(analyzed.correlated.length, 1); assert.equal(analyzed.correlated[0].graph.entry, program.entries[0]);
    const result = scanFile(file);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.coverage.completedEntries, program.entries);
    assert.deepEqual(result.findings, []); assert.deepEqual(result.diagnostics, []);
    const historical = detectors.filter(detector => detector.defaultEnabled !== false && detector.id !== "openzeppelin-preconditions").map(detector => detector.id);
    assert.deepEqual(result.coverage.detectors, historical.filter(id => !hygieneOnlyDetectors.has(id)));
    const hygiene = scanFile(file, { profile: "hygiene" });
    assert.equal(hygiene.status, "complete", JSON.stringify(hygiene.diagnostics));
    assert.deepEqual(hygiene.coverage.completedEntries, program.entries);
    assert.deepEqual(hygiene.coverage.detectors, historical);
    assert.deepEqual(hygiene.findings, []);
    assert.ok(result.metrics.steps <= 20000 && result.metrics.paths <= 256 && result.metrics.abstractValues <= 50000);
    assert.match(human(result), /1\/1 entrypoint\(s\) completed/);
  });
});

test("default correlated consumers report all 65 policy observations under unchanged shared allowances", qualified, () => {
  fixture(unchanged, file => {
    const policies: Policies = { secrets: Array.from({ length: 10 }, (_, index) => ({ circuit: "entry", parameter: `flag${index}` })), authorization: [{ state: "count", guard: "entry" }] };
    const result = scanFile(file, { policies });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.diagnostics, []); assert.equal(result.coverage.completedEntries.length, 1);
    assert.equal(result.findings.filter(item => item.detectorId === "declared-secret-publication").length, 55);
    assert.equal(result.findings.filter(item => item.detectorId === "unguarded-sensitive-state-write").length, 10);
    assert.ok(result.metrics.steps <= 20000 && result.metrics.paths <= 256 && result.metrics.abstractValues <= 50000);
    const predicateOnly = scanFile(file, { policies, experimentalCounterQueries: true });
    assert.deepEqual(result.findings, predicateOnly.findings, "Witness-backed findings retain the existing public consumer contract");
    assert.deepEqual(predicateOnly.coverage.completedEntries, [], "Restricted predicate coverage stays distinct");
  });
});

test("instruction-level conditional joins also avoid expanded historical paths", qualified, () => {
  fixture(`export ledger first: Field; export circuit entry(${parameters}): [] {
${Array.from({ length: 10 }, (_, index) => `first = disclose(flag${index}) ? 1 as Field : 2 as Field;`).join("\n")}
}`, file => {
    const program = new Program(file);
    assert.equal(program.functions.get(program.entries[0])!.cfg.nodes.filter(node => node.kind === "branch").length, 0);
    assert.equal(program.instructionCFG(program.entries[0]).nodes.filter(node => node.kind === "branch").length, 10);
    const result = scanFile(file);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.coverage.completedEntries, program.entries);
    assert.deepEqual(result.diagnostics, []); assert.ok(result.metrics.steps <= 20000);
  });
});

test("correlated scans preserve first-match precedence for duplicate secret policies", qualified, () => {
  fixture(unchanged, file => {
    const allowed: NonNullable<Policies["secrets"]>[number] = { circuit: "entry", parameter: "flag0", allowedForms: ["raw", "derived"] };
    const forbidden = { circuit: "entry", parameter: "flag0" };
    for (const secrets of [[allowed, forbidden], [forbidden, allowed]]) {
      const result = scanFile(file, { policies: { secrets } });
      const firstOnly = scanFile(file, { policies: { secrets: [secrets[0]] } });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.deepEqual(result.findings, firstOnly.findings);
      assert.equal(result.findings.length, secrets[0] === allowed ? 0 : 10);
    }
  });
});

test("dead stateless branches retain cheap ordinary liveness merging", qualified, () => {
  const parameters = Array.from({ length: 20 }, (_, index) => `flag${index}: Boolean`).join(",");
  const branches = Array.from({ length: 20 }, (_, index) => `if (flag${index}) { disclose(flag${index}); }`).join(" ");
  fixture(`export circuit entry(${parameters}): [] { ${branches} }`, file => {
    const result = scanFile(file, { maxPaths: 64 });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.metrics.paths, 1);
    assert.ok(result.metrics.steps < 200, "No graph attempt should consume this inexpensive exact entry's work allowance");
  });
});

test("shared query and construction exhaustion cannot report entry completion", qualified, () => {
  fixture(unchanged, file => {
    for (const budgets of [{ maxSteps: 1 }, { maxPaths: 1 }, { maxValues: 1 }]) {
      const result = scanFile(file, budgets);
      assert.equal(result.status, "incomplete", JSON.stringify(budgets));
      assert.deepEqual(result.coverage.completedEntries, []);
      assert.ok(result.diagnostics.some(item => /budget/.test(item.code)));
    }
  });
  let allowance = 0;
  fixture(header + entry(), file => {
    const complete = scanFile(file);
    assert.equal(complete.status, "complete");
    // Measure the full first-entry cost, including the successful observation
    // required by impossible-assertion; graph construction alone is insufficient.
    allowance = complete.metrics.abstractValues + 1;
  });
  fixture(header + entry() + "\n" + entry("second"), file => {
    const program = new Program(file), isolatedEntry = new Program(file);
    const one = new Dataflow(isolatedEntry).analyzeWithCorrelatedQueries([], true);
    assert.equal(one.correlated.length, 2);
    const limited = scanFile(file, { maxValues: allowance });
    assert.equal(limited.status, "incomplete");
    assert.deepEqual(limited.coverage.completedEntries, [program.entries[0]], "Later entries share the remaining value allowance");
    assert.ok(limited.diagnostics.some(item => /budget/.test(item.code)));
  });
});
