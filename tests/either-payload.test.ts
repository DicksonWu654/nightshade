import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { eitherPayloadMismatch as rule, detectEitherPayloads } from "../src/detectors/either-payload.js";
import { eitherTargets } from "../src/semantic/either-targets.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
export ledger stored: Field;
export ledger count: Counter;
`;
const input = "value: Either<Field, Field>";

function fixture(source: string, expected: string[], prefix = header, extras: Record<string, string> = {}): void {
  withFiles({ "main.compact": prefix + source, ...extras }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all", false, false, false, true, false, true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
      assert.deepEqual(findings.map(item => item.metadata.entry).sort(), [...expected].sort());
      assert.equal(facts.metrics.summaryHits + facts.metrics.readSummaryHits + facts.metrics.statefulSummaryHits, 0, "receiver evidence deliberately bypasses summaries");
      baseline ??= findings;
      assert.deepEqual(findings, baseline);
    }
    // Differential oracle: a conservative absence certificate never covers an
    // entry with an exact finding (see rule-certificates.ts).
    for (const entry of program.entries) {
      const certificate = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true, "all", false, false, false, true, false, true)
        .conservativeRuleCertificate(entry, "either");
      const name = program.symbols.get(entry)!.name;
      if (certificate.status === "absent") assert.equal(expected.includes(name), false, `${name} has an exact finding but a either absence certificate`);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.deepEqual(scan.findings.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)), baseline);
    }
  });
}

test("only consequential selections of a known inactive native Either arm report", () => {
  fixture(`export circuit wrongLeft(${input}): [] { assert(!value.is_left, "right"); stored = disclose(value.left); }
export circuit wrongRight(${input}): [] { assert(value.is_left, "left"); stored = disclose(value.right); }
export circuit correct(${input}): [] { assert(!value.is_left, "right"); stored = disclose(value.right); }
export circuit unchecked(${input}): [] { stored = disclose(value.left); }
export circuit unused(${input}): [] { assert(!value.is_left, "right"); const unused = value.left; }
export circuit returned(${input}): Field { assert(!value.is_left, "right"); return disclose(value.left); }`, ["wrongLeft", "wrongRight", "returned"]);
});

test("late atomic rejection and tag checks retain the receiver snapshot through dead locals and joins", () => {
  fixture(`circuit payload(${input}): Field { return value.left; }
export circuit lateWrong(${input}, branch: Boolean): [] {
  stored = disclose(payload(value)); assert(!value.is_left, "right");
  if (disclose(branch)) { count.increment(1); } else { count.increment(2); }
}
export circuit lateCorrect(${input}, branch: Boolean): [] {
  stored = disclose(payload(value)); assert(value.is_left, "left");
  if (disclose(branch)) { count.increment(1); } else { count.increment(2); }
}
export circuit rejected(${input}): [] { assert(!value.is_left, "right"); stored = disclose(payload(value)); assert(value.is_left, "left"); }`, ["lateWrong"]);
});

test("assertion and control gates preserve consequences independent of the write value", () => {
  fixture(`export circuit gated(${input}, candidate: Field): [] {
  assert(!value.is_left, "right"); assert(value.left == candidate, "authorization"); count.increment(1);
}
export circuit gatedAfter(${input}, candidate: Field): [] {
  assert(!value.is_left, "right"); count.increment(1); assert(value.left == candidate, "authorization");
}
export circuit controlled(${input}): [] {
  assert(!value.is_left, "right"); if (disclose(value.left == (0 as Field))) { count.increment(1); }
}
export circuit corrected(${input}, candidate: Field): [] { assert(value.is_left, "left"); assert(value.left == candidate, "authorization"); count.increment(1); }`, ["gated", "gatedAfter", "controlled"]);
});

test("reconstruction selects its own tag and preserves transformed wrong-arm dependencies", () => {
  fixture(`export circuit rebuiltCorrect(${input}): [] {
  assert(!value.is_left, "right");
  const rebuilt = Either<Field, Field> { is_left: true, left: value.left, right: 0 as Field };
  stored = disclose(rebuilt.left);
}
export circuit rebuiltWrong(${input}): [] {
  assert(value.is_left, "left");
  const rebuilt = Either<Field, Field> { is_left: false, left: value.left, right: value.right };
  stored = disclose(rebuilt.left);
}
export circuit constructorCorrect(${input}): [] {
  assert(!value.is_left, "right"); const rebuilt = left<Field, Field>(value.left); stored = disclose(rebuilt.left);
}
export circuit transformed(${input}): [] {
  assert(!value.is_left, "right"); const rebuilt = left<Field, Field>(value.left + (1 as Field)); stored = disclose(rebuilt.left);
}`, ["rebuiltWrong", "transformed"]);
});

test("canonical aliases and nested aggregates preserve native identity; same-shaped structs stay quiet", () => {
  fixture(`struct Mimic { is_left: Boolean, left: Field, right: Field }
export circuit aliased(value: Choice<Field, Field>): [] { assert(!value.is_left, "right"); const alias = value; stored = disclose(alias.left); }
export circuit lookalike(value: Mimic): [] { assert(!value.is_left, "right"); stored = disclose(value.left); }
export circuit aggregate(value: Choice<[Field, Field], Field>): [] { assert(!value.is_left, "right"); stored = disclose(value.left[1]); }`, ["aliased", "aggregate"], `import { Either as Choice, Counter } from CompactStandardLibrary;
export ledger stored: Field;
export ledger count: Counter;
`);
});

test("pattern and parameter projections use the same typed receiver evidence", () => {
  fixture(`circuit payload({left: part}: Either<Field, Field>): Field { return part; }
export circuit destructured(${input}): [] { assert(!value.is_left, "right"); const {left: part} = value; stored = disclose(part); }
export circuit parameter(${input}): [] { assert(!value.is_left, "right"); stored = disclose(payload(value)); }`, ["destructured", "parameter"]);
});

test("ledger snapshots cannot borrow a tag from replacement live storage", () => {
  fixture(`export ledger choice: Either<Field, Field>;
export circuit stale(): [] {
  const old = choice; assert(!old.is_left, "old right"); choice = disclose(left<Field, Field>(1 as Field)); stored = disclose(old.left);
}
export circuit current(): [] {
  assert(!choice.is_left, "old right"); choice = disclose(left<Field, Field>(1 as Field)); stored = disclose(choice.left);
}`, ["stale"]);
});

test("independent dynamic lookups are may-alias, never a shared tag certificate", () => {
  fixture(`export ledger choices: Map<Field, Either<Field, Field>>;
export circuit independent(first: Field, second: Field): [] {
  const a = choices.lookup(disclose(first)); const b = choices.lookup(disclose(second)); assert(!a.is_left, "a right"); stored = disclose(b.left);
}
export circuit proved(first: Field, second: Field): [] {
  const a = choices.lookup(disclose(first)); const b = choices.lookup(disclose(second)); assert(!a.is_left, "a right"); assert(!b.is_left, "b right"); stored = disclose(b.left);
}`, ["proved"]);
});

test("missing evidence and exhausted observation allowances are explicitly incomplete", () => {
  withFiles({ "main.compact": header + `export circuit entry(${input}): [] { assert(!value.is_left, "right"); stored = disclose(value.left); }` }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    const ordinary = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(ordinary), []);
    assert.ok(ordinary.diagnostics.some(item => item.code === "either-evidence-unavailable"));
    const scan = scanFile(file, { detectors: [rule.id], maxValues: 3 });
    assert.equal(scan.status, "incomplete");
    assert.ok(scan.diagnostics.some(item => /budget/.test(item.code)));
    assert.equal(scanFile(file).findings.some(item => item.detectorId === rule.id), true);
  });
});

test("imported nominal aliases and nested helpers preserve receiver and invocation identity", () => {
  fixture(`circuit outer(value: Selection): Field { return project(value); }
export circuit entry(a: Selection, b: Selection): [] {
  assert(!a.is_left, "a right"); assert(b.is_left, "b left");
  stored = disclose(outer(a)); stored = disclose(outer(b));
}`, ["entry"], `import CompactStandardLibrary;
import { Selection, project } from "types";
export ledger stored: Field;
`, { "types.compact": `module types {
import CompactStandardLibrary;
export type Selection = Either<Field, Field>;
export circuit project(value: Selection): Field { return value.left; }
}
` });
});

test("selection-dependent storage addresses are consequential even when stored data is constant", () => {
  fixture(`export ledger records: Map<Field, Field>;
export circuit entry(${input}): [] {
  assert(!value.is_left, "right"); records.insert(disclose(value.left), 1 as Field);
}`, ["entry"]);
});

test("retained read capacity is bounded and exhaustion stays incomplete", () => {
  withFiles({ "main.compact": header + `export circuit entry(${input}): [] {
  assert(!value.is_left, "right"); for (const i of 0..256) { stored = disclose(value.left); } stored = disclose(value.left);
}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "incomplete");
    assert.ok(scan.diagnostics.some(item => item.code === "either-evidence-budget"), JSON.stringify(scan.diagnostics));
  });
});

test("nonrejecting branches, helper-local branches and tautologies do not gate post-join writes", () => {
  fixture(`circuit branchOnly(${input}): [] { if (disclose(value.left == (0 as Field))) { const unused = 1; } }
export circuit joined(${input}): [] {
  assert(!value.is_left, "right"); if (disclose(value.left == (0 as Field))) { const unused = 1; } count.increment(1);
}
export circuit helperJoined(${input}): [] { assert(!value.is_left, "right"); branchOnly(value); count.increment(1); }
export circuit tautology(${input}): [] { assert(!value.is_left, "right"); assert(value.left == value.left, "same"); count.increment(1); }
export circuit tautologicalControl(${input}): [] { assert(!value.is_left, "right"); if (disclose(value.left == value.left)) { count.increment(1); } }`, []);
});

test("consequence traversal exhaustion does not return a partial clean certificate", () => {
  withFiles({ "main.compact": header + `export circuit entry(${input}): [] { assert(!value.is_left, "right"); stored = disclose(value.left); }` }, directory => {
    const facts = new Dataflow(new Program(resolve(directory, "main.compact")), 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true, "all", false, false, false, true, false, true).analyze();
    assert.equal(facts.diagnostics.length, 0);
    assert.equal(rule.run(facts).length, 1);
    assert.deepEqual(detectEitherPayloads(facts, 1), []);
    assert.ok(facts.diagnostics.some(item => item.code === "either-finding-budget"));
  });
});

for (const [version, compiler] of [
  ["0.30.0", process.env.COMPACTC_030_TEST], ["0.31.1", process.env.COMPACTC_031_TEST],
  ["0.34.0", process.env.COMPACTC_TEST], ["0.35.0-rc.1", process.env.COMPACTC_035_RC1_TEST],
] as const) test(`receiver-tag mismatch agrees with the pinned ${version} ZKIR2 profile`, () => {
  withFiles({ "main.compact": header + `export circuit wrong(${input}): [] { assert(!value.is_left, "right"); stored = disclose(value.left); }
export circuit corrected(${input}): [] { assert(!value.is_left, "right"); stored = disclose(value.right); }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (compiler) {
      const compiled = validateWithCompiler(compiler, file, [], 30000, 2, version);
      assert.equal(compiled.valid, true, `${version}: ${compiled.error}`);
    }
    const scan = scanFile(file, { compilerVersion: version, detectors: [rule.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(item => item.metadata.entry), ["wrong"]);
  });
});

test("short-circuit assertion refinement preserves enforcement and excludes literal absorbers", () => {
  fixture(`circuit checked(${input}, candidate: Field): Boolean { return value.left == candidate && true; }
export circuit andGate(${input}, candidate: Field): [] { assert(!value.is_left, "right"); assert((value.left == candidate) && true, "admission"); count.increment(1); }
export circuit orGate(${input}, candidate: Field): [] { assert(!value.is_left, "right"); assert((value.left == candidate) || false, "admission"); count.increment(1); }
export circuit helperGate(${input}, candidate: Field): [] { assert(!value.is_left, "right"); assert(checked(value, candidate), "admission"); count.increment(1); }
export circuit controlAnd(${input}, candidate: Field): [] { assert(!value.is_left, "right"); if (disclose((value.left == candidate) && true)) { count.increment(1); } }
export circuit absorbed(${input}, candidate: Field, flag: Boolean): [] { assert(!value.is_left, "right"); assert(((value.left == candidate) || true) == flag, "other"); count.increment(1); }
export circuit same(${input}): [] { assert(!value.is_left, "right"); assert((value.left == value.left) && true, "same"); count.increment(1); }`, ["andGate", "orGate", "helperGate", "controlAnd"]);
});

test("receiver observation requests cannot silently use correlated may-history certificates", () => {
  withFiles({ "main.compact": header + `export circuit entry(${input}): [] { assert(!value.is_left, "right"); stored = disclose(value.left); }` }, directory => {
    const flow = new Dataflow(new Program(resolve(directory, "main.compact")), 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true, "all", false, false, false, true, false, true);
    const observed = flow.analyzeWithCorrelatedQueries([], false, true);
    assert.equal(observed.correlated.length + observed.sources.length, 0);
    assert.equal(observed.exact.diagnostics.length, 0);
    assert.equal(rule.run(observed.exact).length, 1);
  });
});

test("bounded native-type applicability keeps unrelated programs quiet without dropping relevant patterns", () => {
  withFiles({ "main.compact": header + `circuit unreachable(${input}): Field { return value.left; }
export circuit entry(): [] { count.increment(1); }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    assert.equal(eitherTargets(program).applicable, false);
    assert.equal(eitherTargets(program, 1).complete, false);
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(facts), []);
    assert.equal(facts.diagnostics.length, 0);
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(program.root, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.equal(scan.findings.length, 0);
    }
  });
  withFiles({ "main.compact": header + `struct Wrapper { payload: Either<Field, Field> }
export circuit entry(value: Wrapper): [] { const {payload: {left: part}} = value; stored = disclose(part); }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    assert.equal(eitherTargets(program).applicable, true);
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(item => item.code === "either-evidence-unavailable"));
  });
});

test("nonliteral absorbers and composed tautologies cannot create control consequences", () => {
  fixture(`circuit yes(): Boolean { return true; }
export circuit localConstant(${input}, candidate: Field): [] { assert(!value.is_left, "right"); const yes = true; if (disclose((value.left == candidate) || yes)) { count.increment(1); } }
export circuit helperConstant(${input}, candidate: Field): [] { assert(!value.is_left, "right"); if (disclose((value.left == candidate) || yes())) { count.increment(1); } }
export circuit foldedConstant(${input}, candidate: Field): [] { assert(!value.is_left, "right"); if (disclose((value.left == candidate) || ((0 as Field) == (0 as Field)))) { count.increment(1); } }
export circuit composed(${input}, candidate: Field): [] { assert(!value.is_left, "right"); const choice = (value.left == candidate) && true; if (disclose(choice == choice)) { count.increment(1); } }
export circuit composedReturn(${input}, candidate: Field): Boolean { assert(!value.is_left, "right"); const choice = (value.left == candidate) && true; return disclose(choice == choice); }`, []);
});


test("total indexing and identical effect-free conditional arms do not invent consequences", () => {
  fixture(`circuit effect(): Field { count.increment(1); return 1 as Field; }
export circuit totalIndex(${input}, candidate: Field): [] { assert(!value.is_left, "right"); const choice = (value.left == candidate) || [true][0]; count.increment(1); }
export circuit totalIndexControl(${input}, candidate: Field): [] { assert(!value.is_left, "right"); if (disclose((value.left == candidate) || [true][0])) { count.increment(1); } }
export circuit sameArms(${input}, candidate: Field): [] { assert(!value.is_left, "right"); stored = disclose((value.left == candidate) ? (1 as Field) : (1 as Field)); }
export circuit sameAlias(${input}, candidate: Field, result: Field): [] { assert(!value.is_left, "right"); stored = disclose((value.left == candidate) ? result : result); }
export circuit differentArms(${input}, candidate: Field): [] { assert(!value.is_left, "right"); stored = disclose((value.left == candidate) ? (1 as Field) : (2 as Field)); }
export circuit effectfulArms(${input}, candidate: Field): [] { assert(!value.is_left, "right"); stored = disclose(disclose(value.left == candidate) ? effect() : effect()); }
export circuit sameInactive(${input}, candidate: Field): [] { assert(!value.is_left, "right"); stored = disclose((value.left == candidate) ? value.left : value.left); }`, ["differentArms", "effectfulArms", "sameInactive", "sameInactive"]);
});


test("passing and constructing Either alone require no payload observation", () => {
  withFiles({ "main.compact": header + `circuit pass(value: Either<Field, Field>): Either<Field, Field> { return value; }
export circuit entry(value: Either<Field, Field>): Either<Field, Field> { return pass(disclose(value)); }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    assert.deepEqual(eitherTargets(new Program(file)).applicable, false);
    const result = scanFile(file);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.filter(finding => finding.detectorId === rule.id).length, 0);
  });
});
