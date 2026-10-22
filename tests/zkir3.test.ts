import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Ajv } from "ajv";
import { Dataflow, Program, scanFile, mergeResults, type AnalysisFacts, type ZkirVersion } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { zkir3Library } from "../src/semantic/stdlib.js";
import { JUBJUB_SCALAR_MODULUS, SECP256K1_BASE_MODULUS, SECP256K1_SCALAR_MODULUS } from "../src/semantic/fields.js";
import { withFiles } from "./helpers.js";

const bytes = (value: bigint) => `Bytes[${Array.from({ length: 32 }, (_, i) => Number(value >> BigInt(i * 8) & 255n)).join(",")}]`;
const returned = (facts: AnalysisFacts) => facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
const factsWithoutMetrics = ({ program, metrics, ...facts }: AnalysisFacts) => ({ ...facts,
  paths: facts.paths.map(path => ({ ...path, path: path.path.map(step => step.kind === "branch" ? { ...step, label: step.label.match(/(?:true|false)$/)?.[0] ?? step.label } : step) })) });

function compare(source: string, check: (facts: AnalysisFacts) => void, version: ZkirVersion = 3): void {
  withFiles({ "main.compact": `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, version);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file, [], undefined, undefined, version);
    let expected: AnalysisFacts | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const analyzer = new Dataflow(program, 40000, 256, 50000, engine, cached, cached);
      const facts = analyzer.analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      check(facts);
      // Keep all value layouts and provenance, including user fields named trace.
      if (expected) assert.deepEqual(factsWithoutMetrics(facts), factsWithoutMetrics(expected));
      else expected = facts;
      assert.deepEqual(analyzer.analyze(), facts, "Reusing an analyzer resets native identities");
    }
  });
}

test("ZKIR3 exports and cross-import native overloads resolve without hiding Jubjub", () => {
  const selection = zkir3Library.ast.declarations.filter(item => item.exported).map(item => `${item.name} as selected_${item.name}`).join(",");
  compare(`import {${selection}} from CompactStandardLibrary;
module A { import {ecMulGenerator,Secp256k1Scalar,Secp256k1Point} from CompactStandardLibrary;
  export circuit generate(s: Secp256k1Scalar): Secp256k1Point { return ecMulGenerator(s); } }
module B { import {ecMulGenerator,JubjubScalar,JubjubPoint} from CompactStandardLibrary;
  export circuit generate(s: JubjubScalar): JubjubPoint { return ecMulGenerator(s); } }
import A prefix A_; import B prefix B_;
export circuit entry(): [Boolean,Boolean] {
  return [A_generate(default<Secp256k1Scalar>) == default<Secp256k1Point>, B_generate(default<JubjubScalar>) == default<JubjubPoint>];
}`, facts => assert.deepEqual(returned(facts)[0].items!.map(value => value.constant), ["true", "true"]));
});

test("foreign field constants use distinct modular arithmetic and canonical byte casts", () => {
  compare(`enum Choice { ZERO, ONE }
export circuit entry(maxBytes: Bytes<32>, reducing: Bytes<32>, baseOne: Secp256k1Base, one: Secp256k1Scalar): [Bytes<32>, Bytes<32>, Bytes<32>, Boolean, Boolean, Bytes<32>, Bytes<32>] {
  assert(maxBytes == ${bytes(SECP256K1_SCALAR_MODULUS - 1n)}, "scalar maximum encoding");
  assert(reducing == ${bytes(SECP256K1_SCALAR_MODULUS + 2n)}, "noncanonical encoding");
  assert(baseOne == true as Secp256k1Base, "base one");
  assert(one == Choice.ONE as Secp256k1Scalar, "scalar one");
  const scalarMax = maxBytes as Secp256k1Scalar;
  return disclose([(scalarMax + one) as Bytes<32>, (default<Secp256k1Base> - baseOne) as Bytes<32>,
    ((reducing as Secp256k1Scalar) * one) as Bytes<32>,
    default<Secp256k1Base> as Boolean, one as Boolean,
    inv(baseOne) as Bytes<32>, neg(one) as Bytes<32>]);
}`, facts => assert.deepEqual(returned(facts)[0].items!.map(value => value.constant), [
    "00".repeat(32), Buffer.from((SECP256K1_BASE_MODULUS - 1n).toString(16), "hex").reverse().toString("hex"),
    "02" + "00".repeat(31), "false", "true", "01" + "00".repeat(31),
    Buffer.from((SECP256K1_SCALAR_MODULUS - 1n).toString(16), "hex").reverse().toString("hex"),
  ]));
});

const byteComparison = `export pure circuit equality(x: Uint<8>): Boolean {
  const a = Bytes[x,${Array(31).fill(0).join(",")}] as Secp256k1Scalar;
  const b = ${bytes(SECP256K1_SCALAR_MODULUS)} as Secp256k1Scalar;
  return a == b;
}`;
test("modular casts discard obsolete byte layouts and keep feasible equality guards", () => {
  compare(`${byteComparison}
export circuit guarded(x: Uint<8>): Bytes<32> {
  const value = Bytes[x,${Array(31).fill(0).join(",")}] as Secp256k1Scalar;
  assert(value == ${bytes(SECP256K1_SCALAR_MODULUS)} as Secp256k1Scalar, "may equal zero");
  return disclose(value as Bytes<32>);
}`, facts => {
    assert.equal(returned(facts).length, 2);
    assert.equal(returned(facts)[0].constant, undefined, "Unknown x can be zero or nonzero");
    assert.equal(returned(facts)[1].constant, "00".repeat(32));
    assert.deepEqual(facts.failedAssertions, []);
    assert.ok(returned(facts)[1].flows.some(flow => flow.source.name === "x"));
  });
});

for (const version of [2, 3] as const) test(`Jubjub conversion preserves the explicit ZKIR${version} profile`, () => {
  const input = 1n << 252n;
  compare(`export circuit entry(): Field { return ((${input} as Field) as JubjubScalar) as Field; }
export circuit bounded(value: Uint<248>): JubjubScalar { return disclose(value as JubjubScalar); }`, facts => {
    assert.equal(returned(facts)[0].constant, String(version === 2 ? input : input % JUBJUB_SCALAR_MODULUS));
    const result = returned(facts)[1];
    assert.equal(result.flows[0].form, "raw");
    assert.equal(result.identity, result.flows[0].source.id, "Uint range fits; preserve raw identity");
  }, version);
});

test("native preconditions survive nested calls, caller guards and repeated observations", () => {
  compare(`export ledger stored: Bytes<32>;
circuit nonzero(s: Secp256k1Scalar): [] { assert((s as Bytes<32>) != default<Bytes<32>>, "nonzero"); }
circuit authorize(flag: Boolean): [] { assert(flag, "allowed"); }
circuit invert(s: Secp256k1Scalar): Secp256k1Scalar { return inv(s); }
export circuit entry(s: Secp256k1Scalar): [Boolean,Boolean,Boolean] {
  nonzero(s);
  const first = invert(s); const second = invert(s);
  return disclose([s == default<Secp256k1Scalar>, first == default<Secp256k1Scalar>, first == second]);
}
export circuit implicit(s: Secp256k1Scalar): Boolean { inv(s); return disclose(s == default<Secp256k1Scalar>); }
export circuit reject(s: Secp256k1Scalar): Secp256k1Scalar { assert(s == default<Secp256k1Scalar>, "zero"); return disclose(invert(s)); }
export circuit writer(s: Secp256k1Scalar, flag: Boolean): [] { authorize(disclose(flag)); stored = disclose(invert(s) as Bytes<32>); }`, facts => {
    assert.equal(facts.paths.length, 3);
    assert.deepEqual(returned(facts)[0].items!.map(value => value.constant), ["false", "false", "true"]);
    assert.equal(returned(facts)[1].constant, "false");
    const write = facts.paths.flatMap(path => path.writes)[0];
    assert.ok(write.after.flows.some(flow => flow.source.name === "s" && flow.trace.some(step => step.kind === "transform" && step.label === "inv")));
    assert.ok(write.guards.some(id => facts.program.functions.get(id)?.symbol.name === "authorize"));
    assert.equal(facts.metrics.summaryHits, 0, "Partial native helpers remain ineligible for value summaries");
  });
});

test("point identity, coordinate rejection and successful-path constraints remain typed", () => {
  compare(`circuit coordinate(p: Secp256k1Point): Secp256k1Base { return secp256k1PointX(p); }
export circuit identities(): [Boolean,Boolean,Field,Field] {
  return [ecMulGenerator(default<Secp256k1Scalar>) == default<Secp256k1Point>,
    ecMulGenerator(true as Secp256k1Scalar) == default<Secp256k1Point>,
    jubjubPointX(default<JubjubPoint>), jubjubPointY(default<JubjubPoint>)];
}
export circuit zero(): Secp256k1Base { return coordinate(ecMulGenerator(default<Secp256k1Scalar>)); }
export circuit defaultY(): Secp256k1Base { return secp256k1PointY(default<Secp256k1Point>); }
export circuit observed(p: Secp256k1Point): [Boolean,Boolean] {
  const first = coordinate(p); const second = coordinate(p);
  return disclose([p == default<Secp256k1Point>, first == second]);
}
export circuit guarded(p: Secp256k1Point): Secp256k1Base {
  assert(p == default<Secp256k1Point>, "caller fixes identity"); return coordinate(p);
}`, facts => {
    assert.equal(facts.paths.length, 2);
    assert.deepEqual(returned(facts)[0].items!.map(value => value.constant), ["true", "false", "0", "1"]);
    assert.deepEqual(returned(facts)[1].items!.map(value => value.constant), ["false", "true"]);
    assert.ok(returned(facts)[1].flows.some(flow => flow.source.name === "p"));
  });
});

test("hashToCurve preserves aliases but separate calls do not imply must-equality", () => {
  compare(`export circuit entry(x: Field): [Boolean,Boolean] {
  const first = hashToCurve<Field>(x); const second = hashToCurve<Field>(x);
  return disclose([first == first, first == second]);
}`, facts => assert.deepEqual(returned(facts)[0].items!.map(value => value.constant), ["true", undefined]));
});

test("branching native calls retain real writes and exhaust ordinary budgets explicitly", () => {
  const source = `export ledger stored: Bytes<32>;
circuit invert(s: Secp256k1Scalar): Secp256k1Scalar { return inv(s); }
export circuit entry(s: Secp256k1Scalar, flag: Boolean): [] {
  if (disclose(flag)) { stored = disclose(invert(s) as Bytes<32>); }
  else { stored = disclose(s as Bytes<32>); }
}`;
  compare(source, facts => {
    assert.equal(facts.paths.length, 2);
    for (const path of facts.paths) {
      assert.equal(path.writes.length, 1);
      assert.deepEqual(new Set(path.writes[0].after.flows.map(flow => flow.source.name)), new Set(["s", "flag"]));
    }
  });
  withFiles({ "main.compact": `import CompactStandardLibrary; ${source}` }, directory => {
    for (const engine of ["instructions", "expressions"] as const) {
      const program = new Program(resolve(directory, "main.compact"), [], undefined, undefined, 3);
      const facts = new Dataflow(program, 2, 256, 50000, engine).analyze();
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
      assert.deepEqual(facts.completedEntries, []);
    }
  });
});

test("foreign domains and compiler-unsupported casts remain explicit front-end diagnostics", () => {
  for (const [parameters, expression, target] of [
    ["s: Secp256k1Scalar", "s + 1", "Secp256k1Scalar"],
    ["s: Secp256k1Scalar,b: Secp256k1Base", "s + b", "Secp256k1Scalar"],
    ["s: Secp256k1Scalar", "s as Uint<8>", "Uint<8>"],
    ["b: Bytes<31>", "b as Secp256k1Scalar", "Secp256k1Scalar"],
    ["s: JubjubScalar", "s + s", "JubjubScalar"],
  ]) withFiles({ "main.compact": `import CompactStandardLibrary; export circuit entry(${parameters}): ${target} { return ${expression}; }` }, directory => {
    const report = scanFile(resolve(directory, "main.compact"), { zkirVersion: 3 });
    assert.equal(report.status, "incomplete");
    assert.ok(["cast-type-mismatch", "arithmetic-type-mismatch"].includes(report.diagnostics[0].code));
    assert.deepEqual(report.coverage.resolved, []);
  });
});

test("ZKIR3 API, CLI, compiler adapter, config and failure reports keep the selected profile", () => {
  withFiles({ "main.compact": "import CompactStandardLibrary; export circuit entry(): Secp256k1Scalar { return true as Secp256k1Scalar; }",
    "nightshade.json": '{"version":1,"zkirVersion":3}' }, directory => {
    const file = resolve(directory, "main.compact"), cli = resolve("dist/src/cli.js");
    const report = scanFile(file, { zkirVersion: 3, compiler: process.env.COMPACTC_TEST });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.compilerValidated, !!process.env.COMPACTC_TEST);
    assert.equal(scanFile(file).status, "incomplete");
    assert.equal(scanFile(file, { zkirVersion: 7 as ZkirVersion }).diagnostics[0].code, "invalid-config");
    const validate = new Ajv().compile(JSON.parse(readFileSync("docs/schema/report.schema.json", "utf8")));
    for (const extra of [[], ["--zkir-version", "3"], ["--max-steps", "1"], ["--heap-mib", "0"]]) {
      const run = spawnSync(process.execPath, [cli, file, "--json", ...extra], { encoding: "utf8", timeout: 30000 });
      const result = JSON.parse(run.stdout);
      assert.equal(result.semanticProfile, "compact-0.34.0-zkir3");
      assert.equal(result.status, extra[0]?.includes("max-steps") || extra[0]?.includes("heap") ? "incomplete" : "complete");
      assert.ok(validate(result), JSON.stringify(validate.errors));
    }
    const mixed = mergeResults([report, scanFile(file)]);
    assert.equal(mixed.semanticProfile, "mixed");
    assert.equal(mixed.status, "incomplete");
    assert.ok(mixed.diagnostics.some(item => item.code === "mixed-semantic-profiles"));
    assert.ok(validate(mixed), JSON.stringify(validate.errors));
  });
});

test("pinned runtime confirms modular equality and native rejection probes", { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned runtime" : false }, () => {
  assert.ok(process.env.COMPACTC_TEST);
  withFiles({ "main.compact": `import CompactStandardLibrary; ${byteComparison}
export pure circuit inverseZero(): Secp256k1Scalar { return inv(${bytes(SECP256K1_SCALAR_MODULUS)} as Secp256k1Scalar); }
export pure circuit identityX(): Secp256k1Base { return secp256k1PointX(ecMulGenerator(default<Secp256k1Scalar>)); }
export pure circuit jubjubY(): Field { return jubjubPointY(default<JubjubPoint>); }` }, directory => {
    const compile = spawnSync(process.env.COMPACTC_TEST!, ["--skip-zk", "--feature-zkir-v3", resolve(directory, "main.compact"), resolve(directory, "compiled")], { encoding: "utf8", timeout: 30000 });
    assert.equal(compile.status, 0, compile.stderr);
    symlinkSync(resolve(process.env.COMPACT_RUNTIME_TEST!, "node_modules"), resolve(directory, "node_modules"), "dir");
    writeFileSync(resolve(directory, "run.mjs"), `import assert from 'node:assert/strict';
import { pureCircuits as p } from './compiled/contract/index.js';
assert.equal(p.equality(0n), true); assert.equal(p.equality(1n), false); assert.equal(p.equality(255n), false);
assert.throws(() => p.inverseZero()); assert.throws(() => p.identityX()); assert.equal(p.jubjubY(), 1n);
`);
    const run = spawnSync(process.execPath, [resolve(directory, "run.mjs")], { encoding: "utf8", timeout: 30000 });
    assert.equal(run.status, 0, run.stderr);
  });
});
