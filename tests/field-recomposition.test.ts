import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { fieldRecompositionFindings, fieldRecompositionReview } from "../src/detectors/field-recomposition.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { observeRules } from "../src/analysis/rule-observations.js";
import { resolvePolicies } from "../src/policies.js";

const source = `witness operand(): Field;
export ledger stored: Field;
export circuit ledgerLookalike(r: Field, x: Field): [] { assert(x == stored * (256 as Field) + r, "relation"); }
export circuit same(q: Field, x: Field): [] { assert(x == q * (256 as Field) + q, "relation"); }
export circuit negated(q: Uint<248>, r: Uint<8>, x: Field): [] { assert(!(x != (q as Field) * (256 as Field) + (r as Field)), "relation"); }
export circuit wide(q: Uint<248>, r: Uint<8>, x: Field): [] { assert(x == (q as Field) * (256 as Field) + (r as Field), "relation"); }
export circuit guarded(q: Uint<248>, r: Uint<8>, x: Field): [] { assert(q < (256 as Uint<248>), "bound"); assert(x == (q as Field) * (256 as Field) + (r as Field), "relation"); }
export circuit tight(q: Uint<240>, r: Uint<8>, x: Field): [] { assert(x == (q as Field) * (256 as Field) + (r as Field), "relation"); }
export circuit unconstrained(q: Field, r: Field, x: Field): [] { assert(x == q * (256 as Field) + r, "relation"); }
export circuit alias(q: Field, small: Uint<8>, r: Uint<8>, x: Field): [] { assert(q == (small as Field), "alias"); assert(x == q * (256 as Field) + (r as Field), "relation"); }
export circuit lookalike(q: Uint<248>, r: Uint<8>, x: Field): Boolean { return disclose(x == (q as Field) * (256 as Field) + (r as Field)); }
export circuit separate(x: Field): [] { const a = operand(); const b = operand(); const tiny = a as Uint<8>; assert(x == b * (256 as Field) + (tiny as Field), "relation"); }
export circuit branches(q: Uint<248>, r: Uint<8>, x: Field, choose: Boolean): [] { if (disclose(choose)) { const tiny = q as Uint<8>; assert(x == (tiny as Field) * (256 as Field) + (r as Field), "small"); } else { assert(x == (q as Field) * (256 as Field) + (r as Field), "wide"); } }
`;
const observe = (program: Program, engine: "instructions" | "expressions", cached: boolean) => new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,true,"all",false,false,false,true,false,false,false,false,false,true).analyze();
const envelopeCases = (JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")) as {
  recompositionEnvelope35: { cases: { file: string; lines: number[] }[] };
}).recompositionEnvelope35.cases;

for (const [directory, prefix, variants] of [
  ["drafts/recomposition35/owned", "field-envelope-envelope", [["positive", [7]], ["corrected", []], ["lookalike", []]]],
  // Frozen controls retain their source-derived matching expectations. A
  // quotient-only bound and a nonzero check do not certify an integer envelope.
  ["synthetic-regressions/validation16", "field-envelope", [["positive", [6]], ["corrected", [7]], ["lookalike", [7]]]],
] as const) for (const [variant, lines] of variants) test(`owned quotient/remainder envelope: ${prefix}-${variant}`, async () => {
  const file = resolve(`tests/corpus/${directory}/${prefix}-${variant}.compact`);
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const program = new Program(file);
  let oracle: ReturnType<typeof fieldRecompositionFindings> | undefined;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = observe(program, engine, cached);
    const findings = fieldRecompositionFindings(facts);
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
    const expected = directory === "drafts/recomposition35/owned"
      ? envelopeCases.find(item => resolve("tests/corpus", item.file) === file)!.lines : lines;
    assert.deepEqual(findings.map(item => item.location.line), expected);
    assert.ok(findings.every(item => item.severity === "info" && item.metadata.pathFeasibility === "not-proven"));
    oracle ??= findings;
    assert.deepEqual(findings, oracle, `${engine}/${cached}`);
  }
  const selected = scanFile(file, { detectors: [fieldRecompositionReview.id] });
  assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
  assert.deepEqual(selected.findings, oracle);
  assert.deepEqual(selected.coverage.completedEntries, program.entries);
  const supervised = await scanFileIsolated(file, { detectors: [fieldRecompositionReview.id] });
  assert.equal(supervised.status, "complete", JSON.stringify(supervised.diagnostics));
  assert.deepEqual(supervised.findings, selected.findings);
  assert.deepEqual(supervised.coverage, selected.coverage);
  const defaults = scanFile(file);
  assert.equal(defaults.status, "complete", JSON.stringify(defaults.diagnostics));
  assert.deepEqual(defaults.findings.filter(item => item.detectorId === fieldRecompositionReview.id), selected.findings);
});
test("addition-only source certifies absence while helper multiplication retains recomposition evidence", () => withFiles({
  "addition.compact": "export circuit sum(q: Field, r: Field): Field { return disclose(q + r); }",
  "helper.compact": `circuit scaled(q: Field): Field { return q * (256 as Field); }
export circuit check(q: Uint<248>, r: Uint<8>, x: Field): [] {
  assert(x == scaled(q as Field) + (r as Field), "relation");
}`,
}, directory => {
  for (const [name, expected] of [["addition", 0], ["helper", 1]] as const) {
    const file = resolve(directory, `${name}.compact`);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    if (name === "addition") {
      const ordinary = new Dataflow(program).analyze();
      assert.deepEqual(fieldRecompositionFindings(ordinary), []);
      assert.deepEqual(ordinary.diagnostics, []);
    }
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observe(program, engine, cached);
      assert.equal(fieldRecompositionFindings(facts).length, expected);
      assert.deepEqual(facts.diagnostics, []);
    }
    const report = scanFile(file, { detectors: [fieldRecompositionReview.id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.findings.length, expected);
    assert.ok(report.coverage.rules!.every(row => row.status === (name === "addition" ? "not-applicable" : "complete")));
  }
}));

test("owned recomposition respects exact operands, aliases, calls and branch histories", () => withFiles({ "main.compact": source }, directory => {
  const file = resolve(directory,"main.compact");
  if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST,file); assert.equal(result.valid,true,result.error); }
  const program = new Program(file);
  for (const engine of ["instructions","expressions"] as const) for (const cached of [false,true]) {
    const facts = observe(program,engine,cached);
    assert.equal(facts.diagnostics.length,0);
    const findings = fieldRecompositionFindings(facts);
    assert.equal(facts.diagnostics.length,0);
    assert.deepEqual(findings.map(f => program.symbols.get(f.metadata.entry as string)!.name).sort(), ["branches","negated","separate","unconstrained","wide"]);
    assert.ok(findings.every(f => f.metadata.pathFeasibility === "not-proven"));
    assert.equal(fieldRecompositionFindings(facts,1).length,0);
    assert.ok(facts.diagnostics.some(d => d.scope?.detectorId === fieldRecompositionReview.id));
  }
  const unfinished = observe(program,"instructions",true);
  unfinished.paths = []; unfinished.completedEntries = [];
  assert.equal(fieldRecompositionFindings(unfinished).length,0);
  assert.ok(unfinished.diagnostics.some(d => d.scope?.detectorId === fieldRecompositionReview.id));
  const missing = new Dataflow(program).analyze();
  assert.deepEqual(fieldRecompositionFindings(missing),[]);
  assert.ok(missing.diagnostics.some(d => d.scope?.detectorId === fieldRecompositionReview.id));
  assert.equal(fieldRecompositionReview.defaultEnabled,true);
}));

test("selected scans and compiler-valid toy positive/corrected/lookalike fixtures", () => {
  for (const [name,count] of [["positive",1],["corrected",0],["lookalike",0]] as const) {
    const file = resolve(`tests/corpus/known-bugs/toy-field-recomposition-${name}.compact`);
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST,file); assert.equal(result.valid,true,result.error); }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file,{ detectors: [fieldRecompositionReview.id], experimentalCounterQueries });
      assert.equal(result.status,"complete", JSON.stringify(result.diagnostics));
      assert.equal(result.findings.length,count);
    }
  }
});


test("unfinished baseline and exhausted rule allowances retain rule-scoped coverage", () => withFiles({ "main.compact": source }, directory => {
  const file = resolve(directory, "main.compact");
  const program = new Program(file);
  const observed = observeRules(program, [fieldRecompositionReview], resolvePolicies(program, {}), {}, new Set());
  assert.equal(observed.findings.length, 0);
  assert.equal(observed.work[0].metrics.steps, 0);
  const unavailable = observed.coverage.filter(row => row.status === "incomplete");
  assert.ok(unavailable.length > 0);
  assert.ok(unavailable.every(row => row.evidence === "unavailable" && row.diagnosticCodes.includes("field-recomposition-baseline-incomplete")));
  assert.ok(observed.diagnostics.every(issue => issue.scope?.detectorId === fieldRecompositionReview.id));
  const budget = observeRules(program, [fieldRecompositionReview], resolvePolicies(program, {}), { maxValues: 1 });
  assert.equal(budget.findings.length, 0);
  assert.ok(budget.coverage.some(row => row.status === "incomplete"));
  assert.ok(budget.diagnostics.every(issue => issue.scope?.detectorId === fieldRecompositionReview.id));
}));

test("helper-site grouping preserves separate supplied identities and histories", () => withFiles({ "main.compact": `
import CompactStandardLibrary;
witness quotient(): Uint<248>;
witness remainder(): Uint<8>;
circuit relation(q: Field, r: Field, value: Field): [] {
  assert(value == q * (256 as Field) + r, "relation");
}
export circuit check(value: Field, flag: Boolean): [] {
  const a = quotient(); const b = quotient();
  const ra = remainder(); const rb = remainder();
  if (disclose(flag)) { relation(a as Field, ra as Field, value); }
  else { relation(b as Field, rb as Field, value); }
}
` }, directory => {
  const file = resolve(directory, "main.compact");
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const program = new Program(file);
  const fingerprints: string[] = [];
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = observe(program, engine, cached);
    const findings = fieldRecompositionFindings(facts);
    assert.deepEqual(facts.diagnostics, []);
    assert.equal(findings.length, 1);
    const histories = findings[0].metadata.histories as { quotientIdentity: string; remainderIdentity: string; branches: { kind: string; label: string }[] }[];
    assert.equal(histories.length, 2);
    assert.equal(new Set(histories.map(row => row.quotientIdentity)).size, 2);
    assert.equal(new Set(histories.map(row => row.remainderIdentity)).size, 2);
    assert.ok(histories.every(row => row.branches.length === 2 && row.branches.filter(step => step.kind === "branch").length === 1));
    assert.deepEqual(histories.map(row => row.branches.find(step => step.kind === "branch")!.label).sort(), ["condition may be false", "condition may be true"]);
    fingerprints.push(findings[0].fingerprint);
  }
  assert.equal(new Set(fingerprints).size, 1);
}));
