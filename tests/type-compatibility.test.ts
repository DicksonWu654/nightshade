import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { AnalysisFacts, Dataflow, Policies, Program, detectors, resolvePolicies, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void = () => {}, policies: Policies = {}, files: Record<string, string> = {}): void {
  withFiles({ ...files, "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const facts = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    const reference = new Dataflow(program, 20000, 256, 50000, "expressions").analyze();
    for (const result of [facts, expanded, reference]) {
      assert.deepEqual(result.diagnostics, []);
      assert.deepEqual(result.completedEntries, program.entries);
    }
    assert.deepEqual(facts.paths, expanded.paths);
    assert.deepEqual(facts.failedAssertions, expanded.failedAssertions);
    assert.deepEqual(facts.failedAssertions, reference.failedAssertions);
    assert.deepEqual(semanticPaths(facts), semanticPaths(reference));
    const configured = resolvePolicies(program, policies);
    const observations = (result: AnalysisFacts) => detectors.flatMap(detector => detector.run(result, configured)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(observations(facts), observations(expanded));
    assert.deepEqual(observations(facts), observations(reference));
    check(facts);
  });
}

const returned = (facts: AnalysisFacts) => facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
const privateReturn = (facts: AnalysisFacts): void => {
  assert.ok(returned(facts).length > 0);
  assert.ok(returned(facts).every(value => value.flows.some(flow => flow.source.name === "secret")));
};

for (const [name, source] of [
  ["local unsigned widening", "export circuit entry(secret: Uint<8>): Uint<16> { const value: Uint<16> = secret; return value; }"],
  ["return unsigned widening", "export circuit entry(secret: Uint<8>): Uint<16> { return secret; }"],
  ["tuple to vector covariance", "export circuit entry(secret: Uint<8>): Vector<2,Uint<16>> { const value: Vector<2,Uint<16>> = [secret,secret]; return value; }"],
  ["vector to tuple covariance", "export circuit entry(secret: Vector<2,Uint<8>>): [Uint<16>,Uint<16>] { return secret; }"],
  ["implicit empty-vector result", "export circuit entry(): Vector<0,Field> {}"],
  ["explicit empty result", "export circuit entry(): [] { return; }"],
  ["mixed empty results", "export circuit entry(flag: Boolean): [] { if (flag) return []; }"],
  ["both branches return", "export circuit entry(secret: Field, flag: Boolean): Field { if (flag) return secret; else return secret; }"],
  ["return through continuation", "export circuit entry(secret: Uint<8>, flag: Boolean): Uint<16> { if (flag) return secret; return secret as Uint<16>; }"],
  ["nested return through continuation", "export circuit entry(secret: Field, first: Boolean, second: Boolean): Field { if (first) { if (second) return secret; } return secret; }"],
  ["inferred anonymous result", "export circuit entry(secret: Uint<8>): Uint<16> { return ((flag: Boolean) => { if (flag) return secret; else return secret as Uint<16>; })(true); }"],
  ["annotated anonymous result", "export circuit entry(secret: Uint<8>): Uint<16> { return ((value: Uint<8>): Uint<16> => value)(secret); }"],
  ["inferred empty anonymous result", "export circuit entry(): [] { return (() => {})(); }"],
  ["struct field widening", "struct Box { value: Uint<16>; } export circuit entry(secret: Uint<8>): Uint<16> { const box = Box { value: secret }; return box.value; }"],
  ["complete positional struct", "struct Box { value: Field; flag: Boolean; } export circuit entry(secret: Field): Field { return Box { secret, false }.value; }"],
  ["struct spread override", "struct Box { value: Field; flag: Boolean; } export circuit entry(secret: Field): Field { const box = Box { value: secret, flag: false }; return Box { ...box, flag: true }.value; }"],
  ["nominal Boolean tests", 'new type Flag = Boolean; export circuit entry(secret: Field, flag: Flag): Field { assert(flag,"required"); if (flag) return secret; else return secret; }'],
  ["nominal Boolean logic", "new type Flag = Boolean; export circuit entry(secret: Flag): Boolean { return !secret || secret && true; }"],
  ["same nominal declaration with different unsigned widths", "new type Word<#N> = Uint<N>; export circuit entry(secret: Word<8>, other: Word<16>): Boolean { return secret < other; }"],
  ["nested nominal unsigned declarations", "new type Word<#N> = Uint<N>; new type Wrapped<T> = T; export circuit entry(secret: Wrapped<Word<8>>, other: Wrapped<Word<16>>): Boolean { return secret >= other; }"],
  ["ordinary unsigned equality widening", "export circuit entry(secret: Uint<8>, other: Uint<16>): Boolean { return secret == other; }"],
  ["tuple-vector equality", "export circuit entry(secret: Vector<2,Uint<8>>): Boolean { return secret == [1 as Uint<16>,2 as Uint<16>]; }"],
  ["scalar write widening", "export ledger value: Uint<16>; export circuit entry(secret: Uint<8>): Uint<16> { value = disclose(secret); return value; }"],
  ["scalar method write widening", "export ledger value: Uint<16>; export circuit entry(secret: Uint<8>): Uint<16> { value.write(disclose(secret)); return value; }"],
  ["Map key and value widening", "import { Map } from CompactStandardLibrary; export ledger table: Map<Uint<16>,Uint<16>>; export circuit entry(secret: Uint<8>): Uint<16> { table.insert(1,disclose(secret)); return table.lookup(1); }"],
  ["Set argument widening", "import { Set } from CompactStandardLibrary; export ledger values: Set<Uint<16>>; export circuit entry(secret: Uint<8>): [] { values.insert(disclose(secret)); values.member(1); values.remove(1); }"],
  ["List argument widening", "import { List } from CompactStandardLibrary; export ledger values: List<Uint<16>>; export circuit entry(secret: Uint<8>): Uint<16> { values.pushFront(disclose(secret)); return values.head().value; }"],
  ["large Counter threshold", "import { Counter } from CompactStandardLibrary; export ledger count: Counter; export circuit entry(): Boolean { return count.lessThan(18446744073709551615); }"],
] as const) test(`compiler-valid value compatibility: ${name}`, () => compare(source));

test("declared return widening controls later overload selection without losing privacy", () => {
  compare("circuit widen(value: Uint<8>): Uint<16> { return value; } circuit select(value: Uint<8>): Uint<16> { return 0; } circuit select(value: Uint<16>): Uint<16> { return value; } export circuit entry(secret: Uint<8>): Uint<16> { return select(widen(secret)); }", privateReturn);
});

test("nested Counter sugar uses a live ADT receiver and exact unsigned arguments", () => {
  compare("import { Map, Counter } from CompactStandardLibrary; export ledger table: Map<Field,Counter>; export circuit entry(): Uint<64> { table.insertDefault(0 as Field); table.lookup(0 as Field) += 1; return table.lookup(0 as Field).read(); }", facts => {
    assert.equal(returned(facts)[0].constant, "1");
    assert.equal(facts.paths[0].writes.length, 2);
  });
});

for (const [name, body] of [
  ["root methods", "count.resetToDefault(); count.increment(3); count.decrement(2); return count.read();"],
  ["root sugar", "count.resetToDefault(); count += 3; count -= 2; return count.read();"],
  ["nested methods", "table.insertDefault(0 as Field); table.lookup(0 as Field).increment(3); table.lookup(0 as Field).decrement(2); return table.lookup(0 as Field).read();"],
  ["nested sugar", "table.insertDefault(0 as Field); table.lookup(0 as Field) += 3; table.lookup(0 as Field) -= 2; return table.lookup(0 as Field).read();"],
] as const) test(`Counter constants after typed mutations: ${name}`, () => {
  compare(`import { Map, Counter } from CompactStandardLibrary; export ledger count: Counter; export ledger table: Map<Field,Counter>; export circuit entry(): Uint<64> { ${body} }`, facts => {
    assert.equal(returned(facts)[0].constant, "1");
    assert.equal(facts.paths[0].writes.length, 3);
  });
});

test("Counter summaries compute constants from current storage rather than cached snapshots", () => {
  compare("import { Counter } from CompactStandardLibrary; export ledger count: Counter; circuit bump(): [] { count.increment(1); } export circuit entry(): Uint<64> { count.resetToDefault(); bump(); bump(); bump(); return count.read(); }", facts => {
    assert.equal(returned(facts)[0].constant, "3");
    assert.ok(facts.metrics.statefulSummaryHits > 0);
  });
});

test("Counter operands are evaluated before the current receiver is updated", () => {
  compare("import { Counter } from CompactStandardLibrary; export ledger count: Counter; circuit bump(): Uint<16> { count.increment(2); return 1; } export circuit entry(): Uint<64> { count.resetToDefault(); count += bump(); return count.read(); }", facts => {
    assert.equal(returned(facts)[0].constant, "3");
  });
});

test("unknown Counter inputs retain private provenance rather than inventing constants", () => {
  compare("import { Counter } from CompactStandardLibrary; export ledger count: Counter; export circuit entry(secret: Uint<16>): Uint<64> { count.resetToDefault(); count += disclose(secret); return count.read(); }", facts => {
    assert.equal(returned(facts)[0].constant, undefined);
    privateReturn(facts);
  });
});

for (const [name, expression, dependent] of [
  ["conditional assertion call", "disclose(flag) ? guard() : true", true],
  ["short-circuit conjunction assertion call", "disclose(flag) && guard()", true],
  ["short-circuit disjunction assertion call", "disclose(flag) || guard()", true],
  ["transitive assertion call", "disclose(flag) ? relay() : true", true],
  ["nested conditional assertion call", "true ? (disclose(flag) ? guard() : true) : false", true],
  ["total conditional", "disclose(flag) ? true : false", false],
  ["total short circuit", "disclose(flag) && total()", false],
] as const) test(`subsequent typed writes preserve abort-sensitive control dependence: ${name}`, () => {
  compare(`export ledger allowed: Boolean; export ledger stored: Boolean; circuit guard(): Boolean { assert(allowed,"allowed"); return true; } circuit relay(): Boolean { return guard(); } circuit total(): Boolean { return true; } export circuit entry(flag: Boolean): [] { ${expression}; stored = true; }`, facts => {
    assert.ok(facts.paths.length > 0);
    for (const path of facts.paths) assert.equal(path.writes[0].after.flows.some(flow => flow.source.name === "flag"), dependent);
  });
});

test("aborting condition evaluation does not extend the condition's own branch scope", () => {
  compare('export ledger allowed: Boolean; export ledger stored: Boolean; circuit checked(value: Boolean): Boolean { assert(allowed,"allowed"); return value; } export circuit entry(flag: Boolean): [] { if (checked(disclose(flag))) {} stored = true; }', facts => {
    assert.equal(facts.paths.length, 1);
    for (const path of facts.paths) assert.equal(path.writes[0].after.flows.length, 0);
  });
});

test("aborting nested conditions retain the enclosing decision through the continuation", () => {
  compare('export ledger allowed: Boolean; export ledger stored: Boolean; circuit checked(value: Boolean): Boolean { assert(allowed,"allowed"); return value; } export circuit entry(flag: Boolean, inner: Boolean): [] { if (disclose(flag)) { if (checked(disclose(inner))) {} } stored = true; }', facts => {
    assert.equal(facts.paths.length, 2);
    for (const path of facts.paths) {
      assert.ok(path.writes[0].after.flows.some(flow => flow.source.name === "flag"));
      assert.ok(path.writes[0].after.flows.every(flow => flow.source.name !== "inner"));
    }
  });
});

test("typed writes retain path-specific guards and secrecy findings", () => {
  const policies: Policies = { authorization: [{ state: "stored", guard: "guard" }], secrets: [{ circuit: "entry", parameter: "secret" }] };
  compare('export ledger allowed: Boolean; export ledger stored: Uint<16>; circuit guard(): [] { assert(allowed,"allowed"); } circuit put(value: Uint<8>): [] { stored = disclose(value); } export circuit entry(secret: Uint<8>, flag: Boolean): [] { if (disclose(flag)) guard(); put(secret); }', facts => {
    const findings = detectors.flatMap(detector => detector.run(facts, resolvePolicies(facts.program, policies)));
    assert.equal(findings.filter(finding => finding.detectorId === "unguarded-sensitive-state-write").length, 1);
    assert.ok(findings.some(finding => finding.detectorId === "declared-secret-publication"));
  }, policies);
});

test("typed imported returns and writes preserve private flow and Unicode spans", () => {
  compare('import "Helper" prefix H_; export circuit entry(secret: Uint<8>): Uint<16> { return H_widen(secret); }', facts => {
    privateReturn(facts);
    const helper = [...facts.program.functions.values()].find(fn => fn.symbol.name === "widen")!;
    const expression = helper.cfg.nodes.find(node => node.kind === "return")!.expr!;
    const source = readFileSync(expression.span.file);
    assert.equal(source.subarray(expression.span.start, expression.span.end).toString(), "value");
    assert.equal(expression.span.column, source.subarray(0, expression.span.start).toString().length + 1);
  }, {}, { "Helper.compact": "module Helper { /* Ω🚀 */ export circuit widen(value: Uint<8>): Uint<16> { return value; } }" });
});

const rejected: [string, string, string][] = [
  ["local Uint is not Field", "export circuit entry(): [] { const value: Field = 1; }", "binding-type-mismatch"],
  ["local narrowing is not implicit", "export circuit entry(secret: Uint<16>): [] { const value: Uint<8> = secret; }", "binding-type-mismatch"],
  ["return Uint is not Field", "export circuit entry(): Field { return 1; }", "return-type-mismatch"],
  ["return narrowing is not implicit", "export circuit entry(secret: Uint<16>): Uint<8> { return secret; }", "return-type-mismatch"],
  ["implicit return needs empty result", "export circuit entry(): Field {}", "return-type-mismatch"],
  ["false assertion does not satisfy return checking", 'export circuit entry(): Field { assert(false,"no"); }', "return-type-mismatch"],
  ["constant branch does not satisfy return checking", "export circuit entry(): Field { if (true) return 1 as Field; }", "return-type-mismatch"],
  ["explicit empty return incompatible", "export circuit entry(): Field { return; }", "return-type-mismatch"],
  ["inferred lambda implicit result", "export circuit entry(secret: Field): Field { return ((flag: Boolean) => { if (flag) return secret; })(true); }", "return-branch-type-mismatch"],
  ["annotated lambda implicit result", "export circuit entry(secret: Field): Field { return ((flag: Boolean): Field => { if (flag) return secret; })(true); }", "return-type-mismatch"],
  ["statement branch result join before widening", "export circuit entry(flag: Boolean): [Uint<16>,Uint<16>] { if(flag) return [1 as Uint<8>,1 as Uint<16>]; else return [1 as Uint<16>,1 as Uint<8>]; }", "return-branch-type-mismatch"],
  ["nested return joins cannot be hidden by a wider outer branch", "export circuit entry(first: Boolean, second: Boolean): [Uint<16>,Uint<16>] { if (first) { if (second) return [1 as Uint<8>,1 as Uint<16>]; else return [1 as Uint<16>,1 as Uint<8>]; } return [1 as Uint<16>,1 as Uint<16>]; }", "return-branch-type-mismatch"],
  ["unreachable statement", "export circuit entry(): Field { return 1 as Field; return true; }", "unreachable-statement"],
  ["unreachable after both branches", "export circuit entry(flag: Boolean): [] { if (flag) return; else return; assert(true,\"dead\"); }", "unreachable-statement"],
  ["unused generic unreachable statement", "circuit unused<T>(value: T): T { return value; return value; } export circuit entry(): [] {}", "unreachable-statement"],
  ["zero-iteration loop return", "export circuit entry(): [] { for (const index of 0..0) { return []; } }", "invalid-loop-return"],
  ["statement Boolean requirement", "export circuit entry(): [] { if (1) return []; }", "boolean-type-mismatch"],
  ["conditional Boolean requirement", "export circuit entry(): Field { return 1 ? 1 as Field : 2 as Field; }", "boolean-type-mismatch"],
  ["assertion Boolean requirement", 'export circuit entry(): [] { assert(1,"not Boolean"); }', "boolean-type-mismatch"],
  ["negation Boolean requirement", "export circuit entry(): Boolean { return !1; }", "boolean-type-mismatch"],
  ["logical Boolean requirement", "export circuit entry(): Boolean { return true && 1; }", "boolean-type-mismatch"],
  ["equality is not arithmetic coercion", "export circuit entry(): Boolean { return 1 == (1 as Field); }", "comparison-type-mismatch"],
  ["Field ordering is not unsigned ordering", "export circuit entry(first: Field,second: Field): Boolean { return first < second; }", "comparison-type-mismatch"],
  ["Boolean ordering", "export circuit entry(): Boolean { return false < true; }", "comparison-type-mismatch"],
  ["distinct nominal ordering", "new type First=Uint<8>; new type Second=Uint<8>; export circuit entry(first:First,second:Second): Boolean { return first < second; }", "comparison-type-mismatch"],
  ["ADT equality", "import { Counter } from CompactStandardLibrary; export circuit entry(): Boolean { return default<Counter> == default<Counter>; }", "ledger-type-context"],
  ["conditional result mismatch", "export circuit entry(flag: Boolean): Field { return flag ? true : 1 as Field; }", "conditional-type-mismatch"],
  ["incomparable conditional tuple results", "export circuit entry(flag: Boolean): [Uint<16>,Uint<16>] { return flag ? [1 as Uint<8>,1 as Uint<16>] : [1 as Uint<16>,1 as Uint<8>]; }", "conditional-type-mismatch"],
  ["unknown field", "struct Box { value: Field; } export circuit entry(value: Box): Field { return value.other; }", "unknown-field"],
  ["scalar has no fields", "export circuit entry(value: Field): Field { return value.other; }", "unknown-field"],
  ["missing struct field", "struct Box { value: Field; } export circuit entry(): Box { return Box {}; }", "missing-struct-field"],
  ["unknown struct initializer field", "struct Box { value: Field; } export circuit entry(): Box { return Box { other: 1 as Field }; }", "invalid-struct-field"],
  ["duplicate struct field", "struct Box { value: Field; } export circuit entry(): Box { return Box { value: 1 as Field, value: 2 as Field }; }", "invalid-struct-field"],
  ["wrong struct field type", "struct Box { value: Field; } export circuit entry(): Box { return Box { value: 1 }; }", "field-type-mismatch"],
  ["different struct spread declaration", "struct First { value: Field; } struct Second { value: Field; } export circuit entry(value: First): Second { return Second { ...value }; }", "invalid-struct-spread"],
  ["scalar state assignment", "export ledger value: Field; export circuit entry(): [] { value = 1; }", "assignment-type-mismatch"],
  ["scalar method write", "export ledger value: Field; export circuit entry(): [] { value.write(1); }", "state-argument-type-mismatch"],
  ["Map key type", "import { Map } from CompactStandardLibrary; export ledger table: Map<Field,Field>; export circuit entry(): [] { table.member(1); }", "state-argument-type-mismatch"],
  ["Map value type", "import { Map } from CompactStandardLibrary; export ledger table: Map<Field,Field>; export circuit entry(): [] { table.insert(1 as Field,1); }", "state-argument-type-mismatch"],
  ["Set value type", "import { Set } from CompactStandardLibrary; export ledger values: Set<Field>; export circuit entry(): [] { values.insert(1); }", "state-argument-type-mismatch"],
  ["List value type", "import { List } from CompactStandardLibrary; export ledger values: List<Field>; export circuit entry(): [] { values.pushFront(1); }", "state-argument-type-mismatch"],
  ["Counter argument too wide", "import { Counter } from CompactStandardLibrary; export ledger count: Counter; export circuit entry(): [] { count.increment(65536); }", "state-argument-type-mismatch"],
  ["Counter threshold too wide", "import { Counter } from CompactStandardLibrary; export ledger count: Counter; export circuit entry(): Boolean { return count.lessThan(18446744073709551616); }", "state-argument-type-mismatch"],
  ["Counter assignment has no write operation", "import { Counter } from CompactStandardLibrary; export ledger count: Counter; export circuit entry(): [] { count = 1; }", "unsupported-state-operation"],
  ["Counter compound assignment argument", "import { Counter } from CompactStandardLibrary; export ledger count: Counter; export circuit entry(): [] { count += 1 as Field; }", "assignment-type-mismatch"],
  ["scalar has no compound increment", "export ledger value: Field; export circuit entry(): [] { value += 1 as Field; }", "unsupported-state-operation"],
  ["struct projection is not storage", "struct Box { value: Field; } export ledger box: Box; export circuit entry(): [] { box.value = 1 as Field; }", "invalid-assignment"],
  ["ordinary Map lookup is not storage", "import { Map } from CompactStandardLibrary; export ledger table: Map<Field,Field>; export circuit entry(): [] { table.lookup(1 as Field) = 1 as Field; }", "invalid-assignment"],
  ["ordinary lookup cannot become a Cell method receiver", "import { Map } from CompactStandardLibrary; export ledger table: Map<Field,Field>; export circuit entry(): [] { table.lookup(1 as Field).write(1 as Field); }", "unsupported-state-operation"],
  ["snapshot cannot become a Cell receiver", "export ledger value: Field; export circuit entry(): [] { const old = value; old.write(1 as Field); }", "unsupported-state-operation"],
  ["bare circuit reference is not a result", "circuit helper(): Field { return 1 as Field; } export circuit entry(): Field { return helper; }", "invalid-value-reference"],
  ["bare witness reference is not a result", "witness secret(): Field; export circuit entry(): Field { return secret; }", "invalid-value-reference"],
  ["bare type reference is not a value", "type Value = Field; export circuit entry(): Field { return Value; }", "invalid-value-reference"],
];

for (const [name, source, code] of rejected) test(`compiler-rejected value compatibility: ${name}`, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, false, source);
      assert.ok(!compiled.error?.includes("Internal error"), compiled.error);
    }
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, code, JSON.stringify(result.diagnostics));
    assert.deepEqual(result.coverage.completedEntries, []);
  });
});

test("invalid imported return reports the defining file and exact UTF-8 span", () => {
  withFiles({ "main.compact": 'import "Helper"; export circuit entry(): Field { return bad(); }', "Helper.compact": "module Helper { /* Ω🚀 */ export circuit bad(): Field { return true; } }" }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, false);
    const diagnostic = scanFile(path).diagnostics[0];
    assert.equal(diagnostic.code, "return-type-mismatch");
    assert.equal(diagnostic.location.file, resolve(directory, "Helper.compact"));
    const source = readFileSync(diagnostic.location.file);
    assert.equal(source.subarray(diagnostic.location.start, diagnostic.location.end).toString(), "return true;");
    assert.equal(diagnostic.location.column, source.subarray(0, diagnostic.location.start).toString().length + 1);
  });
});
