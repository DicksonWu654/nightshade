import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { AnalysisFacts, Dataflow, Program, detectors, resolvePolicies, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { naturalValue, numericBound, parseType, printType } from "../src/semantic/types.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
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
    assert.deepEqual(semanticPaths(facts), semanticPaths(reference));
    const observations = (result: AnalysisFacts) => detectors.flatMap(detector => detector.run(result)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(observations(facts), observations(reference));
    check(facts);
  });
}

function returned(facts: AnalysisFacts) {
  return facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
}

test("natural normalization preserves exact values and rejects unsupported lexical forms", () => {
  for (const number of ["8", "0x8", "0X8", "0o10", "0O10", "0b1000", "0B1000"]) {
    assert.equal(naturalValue(number), 8n);
    assert.equal(printType(parseType(`Vector<${number}, Uint<0 .. 0X100>>`)), "Vector<8,Uint<0..256>>");
    assert.equal(numericBound(`Uint<${number}>`), 256n);
  }
  assert.equal(naturalValue("9007199254740993"), 9007199254740993n);
  assert.equal(naturalValue("08"), 8n);
  for (const value of ["", "-1", "+1", "1.0", "1e2", "0b2", "0o8", "0x", "0XG", "1_000", "Infinity"]) assert.equal(naturalValue(value), undefined);
});

for (const number of ["0x8", "0X8", "0o10", "0O10", "0b1000", "0B1000"]) test(`literal and type ${number} preserve exact constants and argument types`, () => {
  compare(`circuit identity(value: Uint<8>): Uint<8> { return value; } export circuit entry(): [Uint<8>, Uint<8>, Boolean] { return [identity(${number}), ${number} as Uint<${number}>, (${number} as Uint<0 .. 0X100>) == 8]; }`, facts => {
    assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["8", "8", "true"]);
  });
});

for (const bounds of ["0x1..0X3", "0o1..0O3", "0b1..0B11"]) test(`loop bounds ${bounds} preserve iteration values and writes`, () => {
  compare(`export ledger value: Field; export circuit entry(): Field { for (const index of ${bounds}) { value = index as Field; } return value; }`, facts => {
    assert.deepEqual(facts.paths[0].writes.map(write => write.after.constant), ["1", "2"]);
    assert.equal(returned(facts)[0].constant, "2");
  });
});

test("natural-parameter loop bounds and module identity normalize radices", () => {
  compare("module Store<#N> { export ledger value: Field; export circuit put(): [] { for (const index of 0..N) { value = index as Field; } } } import Store<0B10> prefix First_; import Store<0X2> prefix Second_; export circuit entry(): Field { First_put(); return Second_value; }", facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 1);
    assert.deepEqual(facts.paths[0].writes.map(write => write.after.constant), ["0", "1"]);
    assert.equal(returned(facts)[0].constant, "1");
  });
});

test("radix padded strings preserve known commitment randomness and byte values", () => {
  compare('import CompactStandardLibrary; export circuit entry(secret: Field): [Bytes<32>, Bytes<4>] { return disclose([persistentCommit<Field>(secret, pad(0X20, "salt")), pad(0b100, "é")]); }', facts => {
    const items = returned(facts)[0].items!;
    assert.equal(items[1].constant, "c3a90000");
    assert.equal(items[0].commitments![0].randomness.constant, Buffer.from("salt").toString("hex") + "00".repeat(28));
    assert.equal(detectors.find(detector => detector.id === "predictable-commitment-randomness")!.run(facts).length, 1);
  });
});

test("radix constants remain visible to assertion and transition analyses", () => {
  compare('export circuit entry(): [] { assert(0O10 == 0B1001, "unequal"); }', facts => {
    assert.deepEqual(facts.paths, []);
    assert.equal(detectors.find(detector => detector.id === "impossible-assertion")!.run(facts).length, 1);
  });
  compare('export ledger phase: Uint<8>; export circuit entry(): [] { assert(phase == 0X1, "first"); phase = 0B10; }', facts => {
    for (const [from, to] of [["0o1", "0O2"], ["01", "02"], ["1", "2"]]) {
      const policy = resolvePolicies(facts.program, { transitions: [{ state: "phase", from, to }] });
      assert.equal(detectors.find(detector => detector.id === "forbidden-state-transition")!.run(facts, policy).length, 1);
    }
  });
});

for (const generic of [false, true]) test(`${generic ? "specialized" : "literal"} oversized loop bounds never round to zero iterations`, () => {
  const source = generic
    ? "circuit loop<#START, #END>(): [] { for (const index of START..END) { assert(true, \"ok\"); } } export circuit entry(): [] { loop<9007199254740992, 9007199254740993>(); }"
    : 'export circuit entry(): [] { for (const index of 9007199254740992..9007199254740993) { assert(true, "ok"); } }';
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const result = scanFile(path);
    assert.equal(result.diagnostics[0]?.code, "loop-range");
    assert.deepEqual(result.coverage.completedEntries, []);
  });
});

for (const number of ["0b2", "0o8", "0xG", "0X", "01", "0b102"]) test(`malformed source literal ${number} cannot produce a clean scan`, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; export circuit entry(): Field { return ${number} as Field; }` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, false);
    const result = scanFile(path);
    assert.ok(result.diagnostics.length > 0);
    assert.deepEqual(result.coverage.completedEntries, []);
  });
});
