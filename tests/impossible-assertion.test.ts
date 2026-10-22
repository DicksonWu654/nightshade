import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { impossibleAssertion } from "../src/detectors/rules.js";
import { analyzeCorrelatedEntry } from "../src/dataflow/correlated.js";
import { queryCorrelatedGraph } from "../src/dataflow/correlated-queries.js";
import { withFiles } from "./helpers.js";

const certainty = (facts: AnalysisFacts) => impossibleAssertion.run(facts).map(finding => finding.metadata.certainty);
function checked(source: string, check: (program: Program, file: string) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    check(new Program(file), file);
  });
}
function compare(source: string, expected: string[], check?: (facts: AnalysisFacts) => void): void {
  checked(source, (program, file) => {
    let reaches: AnalysisFacts["assertionReaches"] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(certainty(facts), expected);
      check?.(facts);
      if (reaches) assert.deepEqual(facts.assertionReaches, reaches);
      else reaches = facts.assertionReaches;
    }
    const scan = scanFile(file, { detectors: ["impossible-assertion"] });
    assert.equal(scan.status, "complete");
    assert.deepEqual(scan.findings.map(finding => finding.metadata.certainty).sort(), [...expected].sort());
  });
}
const everyReach = "fails-on-every-reaching-path", noSuccess = "no-successful-path";

test("a contradictory assertion site is reported even when another branch succeeds", () => {
  compare(`export circuit entry(flag: Boolean): [] {
    if (!flag) { assert(flag, "guard"); }
    else { assert(flag, "guard"); }
  }`, [everyReach]); // Distinct physical sites: the first is always contradictory.
});

test("ordinary guards and literal-false rejection branches are quiet", () => {
  compare(`circuit guard(flag: Boolean): [] { assert(flag, "guard"); }
export circuit entry(flag: Boolean): [] {
  if (flag) { guard(true); } else { guard(false); }
}`, [], facts => assert.equal(facts.failedAssertions.length, 1));
  compare(`export circuit entry(flag: Boolean): [] {
  if (!flag) { assert((false), "intentional rejection"); }
}`, [], facts => assert.equal(facts.failedAssertions.length, 1));
});

test("constant-expression and contradictory-guard true positives retain assertion locations", () => {
  compare(`export circuit entry(): [] { assert(1 > 2, "always wrong"); }`, [everyReach], facts => {
    const finding = impossibleAssertion.run(facts)[0];
    assert.equal(finding.location.start, facts.failedAssertions[0].location.start);
  });
  compare(`export circuit entry(flag: Boolean): [] {
  assert(flag, "first"); assert(!flag, "contradiction");
}`, [everyReach]);
  compare(`export circuit entry(flag: Boolean): [] {
  assert(flag, "first"); assert(flag, "consistent");
}`, []);
});

test("an assertion that passes before later aborts is not universally failing", () => {
  compare(`circuit guard(flag: Boolean): [] { assert(flag, "shared"); }
export circuit entry(flag: Boolean): [] {
  if (flag) { guard(true); assert(false, "later abort"); }
  else { guard(false); }
}`, [noSuccess], facts => assert.ok(facts.assertionReaches.find(reach => !reach.literalFalse)!.maySucceed));
});

test("shared helper observations include successful callers and generic instances", () => {
  compare(`circuit guard(flag: Boolean): [] { assert(flag, "shared"); }
export circuit bad(): [] { guard(false); }
export circuit good(): [] { guard(true); }`, [noSuccess]);
  compare(`module Guard<T> { export circuit guard(flag: Boolean): [] { assert(flag, "shared"); } }
import Guard<Field> prefix A_; import Guard<Boolean> prefix B_;
export circuit bad(): [] { A_guard(false); }
export circuit good(): [] { B_guard(true); }`, [noSuccess]);
});

test("repeated loop reaches retain an earlier successful assertion observation", () => {
  compare(`export circuit entry(): [] {
  for (const i of 0..2) { assert(i == 0, "first only"); }
}`, [noSuccess]);
});

test("wholly disabled entries report once, including non-assertion checked failures", () => {
  compare(`export circuit entry(): [] { assert(false, "disabled"); }`, [noSuccess]);
  compare(`export circuit entry(value: Field): Uint<8> {
  assert(value == (256 as Field), "too large"); return value as Uint<8>;
}`, [noSuccess]);
});

test("an unselected caller blocks universal helper proof across module instances", () => {
  checked(`module Guard<T> { export circuit guard(flag: Boolean): [] { assert(flag, "shared"); } }
import Guard<Field> prefix A_; import Guard<Boolean> prefix B_;
export circuit bad(): [] { A_guard(false); }
export circuit good(): [] { B_guard(true); }`, program => {
    const bad = program.entries.find(entry => program.symbols.get(entry)!.name === "bad")!;
    const facts = new Dataflow(program).analyzeSubset([bad]);
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(certainty(facts), [noSuccess]);
  });
});

test("incomplete caller coverage cannot be used as universal failure evidence", () => {
  checked(`circuit guard(flag: Boolean): [] { assert(flag, "shared"); }
export circuit bad(): [] { guard(false); }
export circuit good(flag: Boolean): [] {
  for (const i of 0..20) { disclose(flag); } guard(true);
}`, program => {
    const facts = new Dataflow(program, 30).analyze();
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    assert.deepEqual(certainty(facts), [noSuccess]);
    const exhausted = new Dataflow(program, 1).analyze();
    assert.ok(exhausted.diagnostics.length);
    assert.deepEqual(certainty(exhausted), []);
  });
});

test("unrelated unselected entries do not suppress a complete assertion proof", () => {
  checked(`export circuit bad(): [] { assert(1 > 2, "always wrong"); }
export circuit unrelated(flag: Boolean): [] { assert(flag, "guard"); }`, program => {
    const bad = program.entries.find(entry => program.symbols.get(entry)!.name === "bad")!;
    assert.deepEqual(certainty(new Dataflow(program).analyzeSubset([bad])), [everyReach]);
  });
});

test("unselected callback callers block universal helper proof", () => {
  checked(`circuit guard(flag: Boolean): Boolean { assert(flag, "shared"); return true; }
export circuit bad(): Boolean { return guard(false); }
export circuit good(): Vector<1, Boolean> { return map(guard, [true]); }`, program => {
    const bad = program.entries.find(entry => program.symbols.get(entry)!.name === "bad")!;
    assert.deepEqual(certainty(new Dataflow(program).analyzeSubset([bad])), [noSuccess]);
  });
});

const branches = Array.from({ length: 9 }, (_, index) => `if (disclose(b${index})) { state = 256 as Field; }`).join("\n");
const parameters = Array.from({ length: 9 }, (_, index) => `b${index}: Boolean`).join(", ");
test("assertion-free correlated entries require successful-path evidence", () => {
  checked(`export ledger state: Field;
export circuit entry(${parameters}): Uint<8> {
  state = 256 as Field; ${branches} return state as Uint<8>;
}`, (program, file) => {
    const exact = new Dataflow(program).analyze();
    assert.deepEqual(exact.diagnostics, []);
    assert.deepEqual(certainty(exact), [noSuccess]);
    const scan = scanFile(file, { detectors: ["impossible-assertion"] });
    assert.equal(scan.status, "complete");
    assert.deepEqual(scan.findings.map(finding => finding.metadata.certainty), [noSuccess]);
    const limited = scanFile(file, { maxSteps: 100 });
    assert.equal(limited.status, "incomplete");
    assert.deepEqual(limited.findings, []);
  });
  checked(`export ledger state: Field;
export circuit entry(${parameters}): Field {
  state = 256 as Field; ${branches} return state;
}`, (program, file) => {
    const facts = new Dataflow(program).analyzeWithCorrelatedQueries([], true);
    assert.equal(facts.correlated.length, 1);
    assert.deepEqual(facts.exact.completedEntries, []);
    assert.deepEqual(certainty(facts.exact), []);
    const scan = scanFile(file);
    assert.equal(scan.status, "complete");
    assert.deepEqual(scan.findings, []);
  });
});

test("rejected query observations consume the same allowance as successful-entry probes", () => {
  checked(`import CompactStandardLibrary;
export ledger count: Counter; export ledger first: Field; export ledger second: Field;
export circuit entry(a: Boolean, b: Boolean, x: Field): [] {
  count.resetToDefault();
  if (disclose(a)) { first = disclose(x); count.decrement(1); }
  if (disclose(b)) { second = disclose(x); count.decrement(1); }
}`, program => {
    const built = analyzeCorrelatedEntry(program, program.entries[0], { maxFrontier: 2 });
    assert.equal(built.status, "complete");
    if (built.status !== "complete") return;
    const source = [...program.symbols.values()].find(symbol => symbol.kind === "parameter" && symbol.name === "x")!.id;
    const predicates = [{ kind: "public-flow" as const, source, forms: ["raw" as const, "derived" as const] }];
    const query = queryCorrelatedGraph(built.graph, predicates, { maxWitnesses: 2 });
    assert.equal(query.status, "complete");
    if (query.status !== "complete") return;
    assert.equal(query.work.witnesses, 2);
    assert.equal(query.witnesses.length, 0);
    const combined = new Dataflow(program, 20000, 2).analyzeWithCorrelatedQueries(predicates, true);
    assert.equal(combined.correlated.length, 0, "No third observation may bypass the allowance");
    assert.ok(combined.exact.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    assert.deepEqual(combined.exact.completedEntries, []);
    assert.deepEqual(certainty(combined.exact), []);
    const reference = new Dataflow(program).analyze();
    assert.deepEqual(reference.diagnostics, []);
    assert.equal(reference.paths.length, 1, "A larger exact allowance retains the both-false successful history");
  });
});
