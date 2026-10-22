import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { sourceObservations } from "../src/analysis/source-observations.js";
import { duplicatedBranchTail as rule } from "../src/detectors/informational.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `pragma language_version >= 0.26.0; import CompactStandardLibrary;
export ledger round: Counter; export ledger saved: Field;
`;
const run = (body: string) => `export circuit run(flag: Boolean, value: Field): [] { ${body} }`;

function check(source: string, expected: number, histories?: number[]) {
  withFiles({ "main.compact": header + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiler = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiler.valid, true, compiler.error);
    }
    const program = new Program(file);
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.equal(findings.length, expected);
      assert.ok(findings.every(item => item.severity === "info" && item.confidence === "high"
        && item.metadata.evidence === "resolved-source-duplicated-terminating-tail"));
      if (histories) assert.deepEqual(facts.paths.map(path => path.writes.length).sort(), histories);
      oracle ??= findings;
      assert.deepEqual(findings, oracle, `${engine}/${cached}`);
    }
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings, oracle);
    assert.deepEqual(scanFile(file).findings.filter(item => item.detectorId === rule.id), oracle);
  });
}

test("duplicated terminating tail reports alternative writes, retaining one real write per history", () => {
  check(run(`if (disclose(flag)) { round.increment(1); return []; }
    round.increment(1); return [];`), 1, [1, 1]);
  check(run(`if (disclose(flag)) { saved = disclose(value); round.increment(1); return []; }
    saved = disclose(value); round.increment(1); return [];`), 1, [2, 2]);
  check(`circuit helper(value: Field): [] { saved = disclose(value); }
    ${run(`if (disclose(flag)) { helper(value); return []; } helper(value); return [];`)}`, 1, [1, 1]);
});

test("branch-specific setup and the else route retain their actual effects", () => {
  check(run(`if (disclose(flag)) { saved = 1 as Field; round.increment(1); return []; }
    round.increment(1); return [];`), 1, [1, 2]);
  check(run(`if (disclose(flag)) { saved = 1 as Field; }
    else { round.increment(1); return []; } round.increment(1); return [];`), 1, [1, 2]);
  check(`export circuit result(flag: Boolean, value: Field): Field {
    if (disclose(flag)) { round.increment(1); return value; }
    round.increment(1); return value;
  }`, 1, [1, 1]);
});

test("different operands, return values, symbols and intervening statements stay quiet", () => {
  check(run(`if (disclose(flag)) { round.increment(2); return []; }
    round.increment(1); return [];`), 0, [1, 1]);
  check(`export circuit result(flag: Boolean, value: Field): Field {
    if (disclose(flag)) { round.increment(1); return 1 as Field; }
    round.increment(1); return value;
  }`, 0, [1, 1]);
  check(run(`if (disclose(flag)) { const value = 1 as Field; saved = value; return []; }
    saved = disclose(value); return [];`), 0, [1, 1]);
  check(run(`if (disclose(flag)) { round.increment(1); return []; }
    saved = 1 as Field; round.increment(1); return [];`), 0, [1, 2]);
  check(run(`if (disclose(flag)) { round.increment(1); }
    round.increment(1); return [];`), 0, [1, 2]);
  check(`circuit amount(value: Uint<16>): Uint<16> { return value; }
    ${run(`if (disclose(flag)) { round.increment(map(amount, [1 as Uint<16>])[0]); return []; }
      round.increment(map(amount, [1 as Uint<16>])[0]); return [];`)}`, 0, [1, 1]);
});

test("constant-excluded branches, dead suffixes and unreachable continuation stay quiet", () => {
  check(run(`if (false) { round.increment(1); return []; }
    round.increment(1); return [];`), 0, [1]);
  check(run(`if (disclose(flag)) { assert(false, "stop");
    round.increment(1); return []; } round.increment(1); return [];`), 0, [1]);
  check(run(`if (disclose(flag)) { assert(1 == 2, "stop");
    round.increment(1); return []; } round.increment(1); return [];`), 0, [1]);
  check(run(`if (disclose(flag)) { assert(disclose(false), "stop");
    round.increment(1); return []; } round.increment(1); return [];`), 0, [1]);
  check(run(`if (disclose(flag)) { round.increment(1); assert(1 == 2, "stop"); return []; }
    round.increment(1); assert(1 == 2, "stop"); return [];`), 0, []);
  withFiles({ "main.compact": header + run(`if (disclose(flag)) { round.increment(1); return []; }
    else { return []; } round.increment(1); return [];`) }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, false);
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.status, "incomplete");
    assert.deepEqual(report.diagnostics.map(item => item.code), ["unreachable-statement"]);
    assert.deepEqual(report.findings, []);
  });
});

test("generic physical-site claims require the pattern in every instantiated body", () => {
  check(`circuit helper<#N>(flag: Boolean): [] {
    if (N == 0) {
      if (disclose(flag)) { round.increment(1); return []; }
      round.increment(1); return [];
    }
    round.increment(2); return [];
  }
  export circuit run(flag: Boolean, value: Field): [] { helper<0>(flag); helper<1>(flag); }`, 0, [2, 2]);
});

test("resolved imported helpers retain physical evidence without treating unresolved library APIs as analyzed", () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; import "Library";
      export circuit run(flag: Boolean): [] { choose(flag); }`,
    "Library.compact": `pragma language_version >= 0.26.0;
      module Library { import CompactStandardLibrary; export ledger round: Counter;
        export circuit choose(flag: Boolean): [] {
          if (disclose(flag)) { round.increment(1); return []; }
          round.increment(1); return [];
        }
        export circuit unused(flag: Boolean): [] {
          if (disclose(flag)) { round.increment(2); return []; }
          round.increment(2); return [];
        }
      }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiler = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiler.valid, true, compiler.error);
    }
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.findings.length, 1);
    assert.equal(report.findings[0].location.file, resolve(directory, "Library.compact"));
    assert.equal(report.findings[0].metadata.scope, "resolved-compilation-unit-source-observations");
  });
});

test("physical imported generic claims intersect every resolved instance, including unused callers", () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; import "Library";
      circuit unused(flag: Boolean): [] { choose<1>(flag); }
      export circuit run(flag: Boolean): [] { choose<0>(flag); }`,
    "Library.compact": `pragma language_version >= 0.26.0;
      module Library { import CompactStandardLibrary; ledger round: Counter;
        export circuit choose<#N>(flag: Boolean): [] {
          if (N == 0) {
            if (disclose(flag)) { round.increment(1); return []; }
            round.increment(1); return [];
          }
          return [];
        }
      }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiler = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiler.valid, true, compiler.error);
    }
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings, []);
  });
});

test("source observation allowance remains exact and fail-closed", () => {
  withFiles({ "main.compact": header + run(`if (disclose(flag)) { round.increment(1); return []; }
    round.increment(1); return [];`) }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    const full = sourceObservations(program);
    assert.equal(full.complete, true);
    assert.equal(full.observations.filter(item => item.kind === rule.id).length, 1);
    assert.deepEqual(sourceObservations(program, full.work), full);
    const short = sourceObservations(program, full.work - 1);
    assert.equal(short.complete, false);
    assert.deepEqual(short.observations, []);
    assert.equal(scanFile(file, { detectors: [rule.id], maxSteps: 1 }).status, "incomplete");
  });
});
