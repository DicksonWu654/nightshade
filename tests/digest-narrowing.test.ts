import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { digestNarrowings, DIGEST_NARROWING_RULE } from "../src/semantic/digest-narrowing.js";
import { checkedDigestNarrowing as rule } from "../src/detectors/digest-narrowing.js";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = "import CompactStandardLibrary; export ledger saved: Bytes<32>;";
function check(source: string, count: number, inspect?: (program: Program, file: string) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file), query = digestNarrowings(program);
    assert.equal(query.complete, true); assert.equal(query.observations.length, count);
    let first: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      const findings = rule.run(facts);
      assert.equal(findings.length, count);
      assert.ok(findings.every(item => item.severity === "info" && item.confidence === "high"
        && item.metadata.successfulReach === "not-proven" && item.metadata.runtimeFailure === "not-proven"));
      if (first) assert.deepEqual(findings, first); else first = findings;
    }
    const baseline = scanFile(file), selected = scanFile(file, { detectors: [DIGEST_NARROWING_RULE] });
    assert.equal(baseline.status, "complete", JSON.stringify(baseline.diagnostics));
    assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
    assert.ok(baseline.findings.every(item => item.detectorId !== DIGEST_NARROWING_RULE));
    assert.equal(selected.findings.length, count);
    inspect?.(program, file);
  });
}
const entry = (body: string, imports = header) => `${imports} export circuit entry(seed: Uint<64>): [] { ${body} }`;

test("canonical persistent and Keccak digests retain exact cast and sink sites", () => {
  check(entry('saved = disclose((persistentHash<Uint<64>>(seed) as Uint<64>) as Bytes<32>);'), 1, program => {
    const row = digestNarrowings(program).observations[0];
    assert.equal(row.primitive, "persistentHash"); assert.equal(row.maximum, "18446744073709551615");
    assert.equal(row.uses[0].kind, "ledger-write");
  });
  check('import CompactStandardLibrary; export circuit entry(seed: Bytes<32>): Uint<64> { return keccak256<Bytes<32>>(seed) as Uint<64>; }', 1);
});

test("immutable aliases, disclosure and re-encoding preserve the unchanged full digest", () => {
  check(entry('const hash = persistentHash<Uint<64>>(seed); const copy = disclose(hash) as Bytes<32>; const narrowed = copy as Uint<128>; const copied = disclose(narrowed); saved = disclose(copied as Bytes<32>);'), 1);
});

test("all supported Uint widths and exclusive custom bounds describe the actual conversion", () => {
  for (const width of [1, 64, 128, 248]) {
    check(`import CompactStandardLibrary; export circuit entry(seed: Uint<64>): Uint<${width}> { return persistentHash<Uint<64>>(seed) as Uint<${width}>; }`, 1,
      program => assert.equal(digestNarrowings(program).observations[0].maximum, String((1n << BigInt(width)) - 1n)));
  }
  check('import CompactStandardLibrary; export circuit entry(seed: Uint<64>): Uint<0..17> { return persistentHash<Uint<64>>(seed) as Uint<0..17>; }', 1,
    program => assert.equal(digestNarrowings(program).observations[0].maximum, "16"));
});

test("canonical import aliases match and application namesakes remain quiet", () => {
  check(entry('saved = disclose((hash<Uint<64>>(seed) as Uint<64>) as Bytes<32>);', 'import { persistentHash as hash } from CompactStandardLibrary; export ledger saved: Bytes<32>;'), 1);
  check(entry('saved = disclose((Mock_persistentHash(seed) as Uint<64>) as Bytes<32>);', `${header} module Mock { export circuit persistentHash(seed: Uint<64>): Bytes<32> { return seed as Bytes<32>; } } import Mock prefix Mock_;`), 0);
});

test("bounded encodings, explicit byte selection and reconstructed digests do not supply full-digest identity", () => {
  check(entry('const encoded = seed as Bytes<32>; saved = disclose((encoded as Uint<64>) as Bytes<32>);'), 0);
  check(entry('const hash = persistentHash<Uint<64>>(seed); saved = disclose((slice<8>(hash, 0) as Uint<64>) as Bytes<32>);'), 0);
  check(entry('const hash = persistentHash<Uint<64>>(seed); const rebuilt = slice<32>(hash, 0); saved = disclose((rebuilt as Uint<64>) as Bytes<32>);'), 0);
});

test("Field conversions, arithmetic, unused casts and checker-only uses remain outside the source route", () => {
  check(entry('saved = disclose((persistentHash<Uint<64>>(seed) as Field) as Bytes<32>);'), 0);
  check(entry('const result = persistentHash<Uint<64>>(seed) as Uint<64>; saved = disclose((result + 0) as Bytes<32>);'), 0);
  check(entry('const unused = persistentHash<Uint<64>>(seed) as Uint<64>; saved = disclose(seed as Bytes<32>);'), 0);
  check(entry('const result = persistentHash<Uint<64>>(seed) as Uint<64>; assert(result == seed, "work target");'), 0);
});

test("explicitly intentional checked conversions remain source facts in the opt-in review", () => {
  check(entry('const hash = persistentHash<Uint<64>>(seed); assert(hash == (seed as Bytes<32>), "intentional target"); saved = disclose((hash as Uint<64>) as Bytes<32>);'), 1);
});

test("helper ledger writes identify the resolved caller and all invoking entries", () => {
  check(`${header} circuit record(seed: Uint<64>): [] { saved = disclose((persistentHash<Uint<64>>(seed) as Uint<64>) as Bytes<32>); }
    export circuit first(seed: Uint<64>): [] { record(seed); } export circuit second(seed: Uint<64>): [] { record(seed); }`, 1, program => {
      const row = digestNarrowings(program).observations[0];
      assert.equal(program.symbols.get(row.caller)!.name, "record");
      assert.deepEqual(row.entries.map(id => program.symbols.get(id)!.name), ["first", "second"]);
    });
});

test("arbitrary helper forwarding and captured outer aliases do not invent exact source origins", () => {
  check(`${header} circuit hash(seed: Uint<64>): Bytes<32> { return persistentHash<Uint<64>>(seed); }
    export circuit entry(seed: Uint<64>): [] { saved = disclose((hash(seed) as Uint<64>) as Bytes<32>); }`, 0);
  check(entry('const hash = persistentHash<Uint<64>>(seed); saved = disclose(((): Uint<64> => hash as Uint<64>)() as Bytes<32>);'), 0);
});

test("source uses are grouped per cast and retain distinct invocation-instance identity", () => {
  check(`${header} export ledger other: Bytes<32>; export circuit entry(seed: Uint<64>): Uint<64> {
    const result = persistentHash<Uint<64>>(seed) as Uint<64>; saved = disclose(result as Bytes<32>); other = disclose(result as Bytes<32>); return result; }`, 1,
    program => assert.deepEqual(digestNarrowings(program).observations[0].uses.map(use => use.kind), ["ledger-write", "ledger-write", "exported-return"]));
});

test("resolved imported module instances retain their source ownership", () => {
  withFiles({ "Store.compact": `module Store<#N> {
    import CompactStandardLibrary;
    export ledger saved: Uint<N>;
    export circuit record(seed: Uint<64>): [] { saved = disclose(persistentHash<Uint<64>>(seed) as Uint<N>); }
  }`, "main.compact": `import "Store"<64> prefix Small_; import "Store"<128> prefix Large_;
    export circuit entry(seed: Uint<64>): [] { Small_record(seed); Large_record(seed); }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error);
    }
    const report = scanFile(file, { detectors: [DIGEST_NARROWING_RULE] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.findings.length, 2);
    assert.equal(new Set(report.findings.map(item => item.metadata.caller)).size, 2);
    assert.deepEqual(report.findings.map(item => item.metadata.targetType).sort(), ["Uint<128>", "Uint<64>"]);
    assert.ok(report.findings.every(item => item.location.file.endsWith("Store.compact")));
  });
});

test("aggregate output does not acquire a scalar route and source reach is not execution proof", () => {
  check('import CompactStandardLibrary; export circuit entry(seed: Uint<64>): [Uint<64>] { return [persistentHash<Uint<64>>(seed) as Uint<64>]; }', 0);
  check(entry('if (false) { saved = disclose((persistentHash<Uint<64>>(seed) as Uint<64>) as Bytes<32>); }'), 1);
});

test("large alias environments consume the observation allowance before copying", () => {
  const aliases = Array.from({ length: 200 }, (_, i) => `const copy${i} = hash;`).join(" ");
  const branches = 'if (true) { 0; }'.repeat(200);
  withFiles({ "main.compact": entry(`const hash = persistentHash<Uint<64>>(seed); ${aliases} ${branches}`) }, directory => {
    const result = digestNarrowings(new Program(resolve(directory, "main.compact")));
    assert.equal(result.complete, false); assert.deepEqual(result.observations, []);
    assert.ok(result.work > 20000);
  });
});

test("experimental Counter coverage identifies source work without creating a predicate certificate", () => {
  check(entry('saved = disclose((persistentHash<Uint<64>>(seed) as Uint<64>) as Bytes<32>);'), 1, (_program, file) => {
    const report = scanFile(file, { detectors: [DIGEST_NARROWING_RULE], experimentalCounterQueries: true });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.ok(report.schemaVersion === "1.7.0");
    assert.equal(report.findings.length, 1);
    assert.ok(report.analysis.coverage.every(row => row.status === "covered" && row.method === "source-work" && row.contract === "digest-source-checked-cast-v1"));
  });
});

test("source query exhaustion discards partial findings rather than certifying absence", () => {
  check(entry('saved = disclose((persistentHash<Uint<64>>(seed) as Uint<64>) as Bytes<32>);'), 1, program => {
    const complete = digestNarrowings(program);
    for (const allowance of [0, 1, complete.work - 1]) {
      const exhausted = digestNarrowings(program, allowance);
      assert.equal(exhausted.complete, false); assert.deepEqual(exhausted.observations, []);
    }
  });
});

test("public scan reports source budget gaps separately from complete baseline analysis", () => {
  withFiles({ "main.compact": entry('saved = disclose((persistentHash<Uint<64>>(seed) as Uint<64>) as Bytes<32>);' + '0;'.repeat(5000)) }, directory => {
    const report = scanFile(resolve(directory, "main.compact"), { detectors: [DIGEST_NARROWING_RULE] });
    assert.equal(report.coverage.baselineStatus, "complete", JSON.stringify(report.diagnostics)); assert.equal(report.status, "incomplete");
    assert.deepEqual(report.findings, []);
    assert.ok(report.diagnostics.some(item => item.code === "digest-narrowing-observation-budget" && item.scope?.detectorId === DIGEST_NARROWING_RULE));
    assert.ok(report.coverage.rules?.every(row => row.status === "incomplete"));
  });
});

test("source-only rule selection preserves the baseline correlated representation", () => {
  const parameters = Array.from({ length: 10 }, (_, i) => `branch${i}: Boolean`).join(", ");
  const branches = Array.from({ length: 10 }, (_, i) => `if (disclose(branch${i})) { total = total + 1; }`).join(" ");
  withFiles({ "main.compact": `export ledger total: Field; export circuit entry(${parameters}): [] { ${branches} }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    const baseline = scanFile(file), selected = scanFile(file, { detectors: [DIGEST_NARROWING_RULE] });
    assert.equal(baseline.coverage.baselineStatus, "complete"); assert.equal(selected.status, "complete");
    assert.deepEqual(selected.coverage.completedEntries, baseline.coverage.completedEntries); assert.deepEqual(selected.findings, []);
  });
});

test("owned Counter triplet compiles and detects only the seeded checked conversion", () => {
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-digest-narrowing-${kind}.compact`);
    assert.match(readFileSync(file, "utf8"), /round.increment\(1\)/);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error);
    }
    const report = scanFile(file, { detectors: [DIGEST_NARROWING_RULE] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [22] : []);
  }
});
