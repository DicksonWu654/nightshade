import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile, type AnalysisFacts } from "../src/index.js";
import { sourceObservations } from "../src/analysis/source-observations.js";
import { estimateWork } from "../src/analysis/work.js";
import { informationalDetectors, alwaysTrueAssertion, timeDependence } from "../src/detectors/informational.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function checked(source: string, inspect: (program: Program, file: string) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    inspect(new Program(file), file);
  });
}
function observations(program: Program, kind: string) {
  const result = sourceObservations(program);
  assert.equal(result.complete, true);
  return result.observations.filter(item => item.kind === kind);
}

test("large independent namespaces retain complete source observations within the unchanged allowance", () => {
  const source = Array.from({ length: 1000 }, (_, index) =>
    `export circuit entry${index}(value: Field): Field { return disclose(value); }`).join("\n");
  checked(source, (program, file) => {
    const result = sourceObservations(program);
    assert.equal(result.complete, true);
    assert.deepEqual(result.observations, []);
    assert.deepEqual(sourceObservations(program, result.work), result);
    const exhausted = sourceObservations(program, result.work - 1);
    assert.equal(exhausted.complete, false);
    assert.deepEqual(exhausted.observations, []);
    const report = scanFile(file);
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.coverage.completedEntries.length, 1000);
    assert.deepEqual(report.findings, []);
  });
});
function modes(program: Program, inspect: (facts: AnalysisFacts) => void): void {
  let baseline: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
    inspect(facts);
    baseline ??= facts.assertionReaches;
    assert.deepEqual(facts.assertionReaches, baseline);
  }
}

test("unused ledger, witness and private circuit distinguish references and exported APIs", () => {
  checked(`import CompactStandardLibrary;
ledger unusedState: Field; witness unusedWitness(): Field;
circuit unusedHelper(): Field { return 1 as Field; }
ledger usedState: Field; witness usedWitness(): Field;
circuit helper(): Field { return usedState + usedWitness(); }
export circuit libraryApi(): Field { return disclose(helper()); }`, program => {
    assert.deepEqual(observations(program, "unused-declaration").map(item => item.metadata.symbol).sort(), ["unusedHelper", "unusedState", "unusedWitness"]);
    const exhausted = sourceObservations(program, 0);
    assert.equal(exhausted.complete, false);
    assert.deepEqual(exhausted.observations, []);
  });
});

test("references in an uninstantiated generic body are not lost", () => {
  checked(`witness w(): Field;
circuit unused<T>(x: T): Field { return w(); }
export circuit entry(): Field { return 1 as Field; }`, program => {
    assert.equal(observations(program, "unused-declaration").some(item => item.metadata.symbol === "w"), false);
  });
});

test("explicit and inline exports both preserve nested library APIs", () => {
  checked(`module Inline { export circuit api(): Field { return 1 as Field; } }
module Listed { circuit api(): Field { return 1 as Field; } export { api }; }
export circuit entry(): Field { return 1 as Field; }`, program => {
    assert.deepEqual(observations(program, "unused-declaration"), []);
  });
});

test("unlinked modules can export inherited bindings without making APIs look unused", () => {
  for (const imported of [false, true]) checked(`circuit api(): Field { return 1 as Field; }
module Library { export { api }; }
${imported ? "import Library prefix L_;" : ""}
export circuit entry(): Field { return 2 as Field; }`, program => {
    assert.deepEqual(observations(program, "unused-declaration"), []);
  });
});

test("shadowing follows imported aliases and nearest lexical bindings", () => {
  checked(`module Library { export circuit value(): Field { return 1 as Field; } }
import Library prefix L_;
export circuit entry(L_value: Field): Field { return L_value; }`, program => {
    const found = observations(program, "shadowing");
    assert.equal(found.length, 1);
    assert.equal(found[0].metadata.shadowedKind, "circuit");
  });
});

test("generic physical-source claims intersect across all instantiated bodies", () => {
  checked(`circuit choice<#N>(): Field {
  if (N == 0) { return 1 as Field; } else { return 2 as Field; }
}
export circuit zero(): Field { return choice<0>(); }
export circuit one(): Field { return choice<1>(); }`, program => {
    assert.deepEqual(observations(program, "constant-condition"), []);
    assert.deepEqual(observations(program, "dead-code"), []);
  });
  checked(`circuit choice<#N>(flag: Boolean): Field {
  if (N == 0 || flag) { return 1 as Field; } else { return 2 as Field; }
}
export circuit zero(flag: Boolean): Field { return choice<0>(flag); }
export circuit one(flag: Boolean): Field { return choice<1>(flag); }`, program => {
    assert.deepEqual(observations(program, "constant-condition"), []);
    assert.deepEqual(observations(program, "dead-code"), []);
  });
});

test("typed constants distinguish known branches and empty loops from unknown conditions", () => {
  checked(`import CompactStandardLibrary;
export ledger round: Counter;
export circuit entry(flag: Boolean): [] {
  const yes = 1 < 2;
  if (yes) { round.increment(1); } else { round.increment(2); }
  for (const i of 0..0) { round.increment(3); }
  if (disclose(flag)) { round.increment(4); }
}`, program => {
    assert.equal(observations(program, "constant-condition").length, 1);
    assert.equal(observations(program, "dead-code").length, 2);
  });
});

test("ledger writes and loop mutation do not invent source constants or update snapshots", () => {
  checked(`ledger current: Boolean;
export circuit entry(flag: Boolean): Field {
  const snapshot = current;
  current = disclose(flag);
  if (snapshot) { return 1 as Field; } else { return 2 as Field; }
}`, program => assert.deepEqual(observations(program, "constant-condition"), []));
  checked(`ledger current: Boolean;
export circuit entry(flag: Boolean): Field {
  for (const i of 0..2) { current = disclose(flag); }
  if (current) { return 1 as Field; } else { return 2 as Field; }
}`, program => assert.deepEqual(observations(program, "constant-condition"), []));
});

test("shadowing compares resolved lexical scopes without conflating sibling bindings", () => {
  checked(`ledger value: Field;
export circuit shadow(value: Field): Field { return value; }
export circuit siblings(flag: Boolean): Field {
  if (flag) { const local = 1 as Field; return local; }
  else { const local = 2 as Field; return local; }
}`, program => {
    const found = observations(program, "shadowing");
    assert.equal(found.length, 1);
    assert.equal(found[0].metadata.shadowedKind, "ledger");
  });
});

test("disclosure review distinguishes public operands and private operands/control", () => {
  checked(`import CompactStandardLibrary;
export ledger round: Counter;
witness privateValue(): Field;
export circuit entry(flag: Boolean): Field {
  round.increment(disclose(1));
  const publicValue = disclose(1 as Field);
  disclose(privateValue());
  if (flag) { return disclose(1 as Field); }
  else { return disclose(publicValue); }
}`, program => assert.equal(observations(program, "unnecessary-disclose").length, 2));
});

test("always-true assertions use pre-enforcement evidence in both engines and cache modes", () => {
  checked(`circuit guard(flag: Boolean): [] { assert(flag, "check"); }
export circuit entry(flag: Boolean): [] {
  assert(flag, "first"); assert(flag, "already constrained");
  assert(1 < 2, "constant"); guard(true); guard(true);
}`, program => modes(program, facts => {
    assert.deepEqual(alwaysTrueAssertion.run(facts).map(item => item.location.line).sort(), [1, 3, 4]);
    assert.equal(facts.assertionReaches.find(item => item.location.line === 3 && item.mayFail)?.mayFail, true);
  }));
});

test("assertion universality includes failing callers, generic instances and later aborts", () => {
  checked(`module Guard<T> { export circuit guard(flag: Boolean): [] { assert(flag, "check"); } }
import Guard<Field> prefix A_; import Guard<Boolean> prefix B_;
export circuit good(): [] { A_guard(true); }
export circuit bad(): [] { B_guard(false); }`, program => modes(program, facts => assert.deepEqual(alwaysTrueAssertion.run(facts), [])));
  checked(`circuit guard(flag: Boolean): [] { assert(flag, "check"); }
export circuit entry(flag: Boolean): [] {
  if (flag) { guard(false); } else { guard(true); assert(false, "later"); }
}`, program => modes(program, facts => assert.deepEqual(alwaysTrueAssertion.run(facts), [])));
});

test("unselected and budget-exhausted callers veto universal assertion claims", () => {
  checked(`circuit guard(flag: Boolean): [] { assert(flag, "check"); }
export circuit good(): [] { guard(true); }
export circuit unknown(flag: Boolean): [] {
  for (const i of 0..20) { disclose(flag); } guard(flag);
}`, (program, file) => {
    const good = program.entries.find(id => program.symbols.get(id)!.name === "good")!;
    assert.deepEqual(alwaysTrueAssertion.run(new Dataflow(program).analyzeSubset([good])), []);
    const facts = new Dataflow(program, 30).analyze();
    assert.ok(facts.diagnostics.some(item => item.code === "analysis-budget"));
    assert.deepEqual(alwaysTrueAssertion.run(facts), []);
    assert.equal(scanFile(file, { detectors: [alwaysTrueAssertion.id], maxSteps: 1 }).status, "incomplete");
  });
});

test("time dependence is a canonical kernel operation on a successful history", () => {
  checked(`import CompactStandardLibrary;
circuit expired(): Boolean { return blockTimeGt(0); }
module Fake { export circuit blockTimeGt(value: Uint<64>): Boolean { return value > 0; } }
import Fake prefix F_;
export circuit clock(): Boolean { return expired(); }
export circuit rejected(): [] { assert(expired(), "time"); assert(false, "disabled"); }
export circuit namesake(value: Uint<64>): Boolean { return F_blockTimeGt(value); }`, (program, file) => {
    modes(program, facts => {
      const found = timeDependence.run(facts);
      assert.equal(found.length, 1);
      assert.equal(found[0].metadata.entry, "clock");
    });
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [timeDependence.id], experimentalCounterQueries });
      assert.equal(result.status, "complete");
      assert.equal(result.findings.length, 1);
    }
  });
});

test("circuit-cost threshold is source work, and estimates have an explicit work allowance", () => {
  checked(`import CompactStandardLibrary;
export ledger round: Counter;
export circuit increment(): [] {
  for (const i of 0..40) { for (const j of 0..64) { round.increment(1); } }
}`, (program, file) => {
    assert.equal(estimateWork(program, program.entries[0], 1), undefined);
    assert.ok(estimateWork(program, program.entries[0])!.units > 10000);
    const result = scanFile(file, { detectors: ["circuit-cost"] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].metadata.model, "expanded-syntax-upper-bound-v1");
    assert.equal(result.findings[0].metadata.estimateOnly, true);
  });
});
