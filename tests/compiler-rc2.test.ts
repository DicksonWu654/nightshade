import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Ajv } from "ajv";
import { resolve } from "node:path";
import { compilerIdentity, validateWithCompiler } from "./compiler-fixtures.js";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { readConfiguration } from "../src/config.js";
import { human, sarif } from "../src/reporting/index.js";
import { checkRc2Identifiers, selectCompilerVersion, type CompilerVersion } from "../src/semantic/profile.js";
import { withFiles, semanticPaths } from "./helpers.js";
import { AnalysisError, type Expr, type Parameter, type ScopeAst, type Statement } from "../src/model.js";

const version = "0.33.0-rc.2" as const;
const compiler = process.env.COMPACTC_033_RC2_TEST;
const location = { file: "main.compact", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
function checked(source: string, valid: boolean, inspect: (file: string) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (compiler) {
      const result = validateWithCompiler(compiler, file, [], 30000, 2, version);
      assert.equal(result.valid, valid, result.error);
      assert.equal(result.version, version);
      assert.equal(result.languageVersion, "0.25.0");
    }
    inspect(file);
  });
}

test("RC2 profile is a pragma fallback, preserves stable defaults and never invents a stable 0.33", () => {
  assert.equal(selectCompilerVersion([], location), "0.34.0");
  assert.equal(selectCompilerVersion(["pragma language_version >= 0.25;"], location), "0.34.0");
  assert.equal(selectCompilerVersion(["pragma language_version 0.25;"], location), version);
  assert.equal(selectCompilerVersion(["pragma compiler_version 0.33;"], location), version);
  assert.equal(selectCompilerVersion([], location, version), version);
  assert.throws(() => selectCompilerVersion([], location, "0.33.0" as CompilerVersion), /Unsupported compiler/);
  assert.throws(() => selectCompilerVersion([], location, version, 3), /ZKIR3/);
});

test("unstamped RC2 compiler identity requires the release binary, not a matching version string", () => {
  withFiles({}, directory => {
    const file = resolve(directory, "compactc");
    for (const reported of ["0.33.0", "0.33.0-rc.2", "0.33.0-rc.2 (566ef0eb6 2026-07-15)"]) {
      writeFileSync(file, `#!/bin/sh\ncase "$1" in --version) printf '%s\\n' '${reported}' ;; --language-version) printf '%s\\n' '0.25.0' ;; *) exit 2 ;; esac\n`);
      chmodSync(file, 0o755);
      assert.equal(compilerIdentity(file).valid, false, reported);
    }
    // Even an exact official launcher cannot authenticate an unpinned sibling binary.
    const launcher = '#!/usr/bin/env bash\nthisdir="$(cd $(dirname $0) ; pwd -P)"\nPATH="$thisdir:$PATH"\nexec "$thisdir/compactc.bin" "$@"\n';
    writeFileSync(resolve(directory, "compactc.bin"), '#!/bin/sh\ncase "$1" in --version) echo 0.33.0 ;; --language-version) echo 0.25.0 ;; esac\n');
    chmodSync(resolve(directory, "compactc.bin"), 0o755);
    writeFileSync(file, launcher);
    assert.equal(compilerIdentity(file).valid, false);
  });
  if (compiler) {
    assert.deepEqual(compilerIdentity(compiler), { valid: true, version, languageVersion: "0.25.0" });
    assert.deepEqual(compilerIdentity(resolve(compiler, "..", "compactc.bin")), { valid: true, version, languageVersion: "0.25.0" });
  }
});

test("bundled RC2 library preserves the exact Apache source and nominal point/Schnorr boundary", () => {
  const bytes = readFileSync("src/stdlib/standard-library-0.33-rc.2.compact");
  assert.equal(createHash("sha256").update(bytes).digest("hex"), "623e0cafcdd015ce52906b8f61d85cac666d5119393102199a175aeac3dce931");
  assert.match(bytes.toString(), /export new type JubjubPoint = Opaque<'JubjubPoint'>/);
  assert.match(bytes.toString(), /export circuit jubjubSchnorrVerify/);
  assert.ok(!bytes.toString().includes("assert(pk !="), "Identity-key guard belongs to 0.35, not RC2");
});

test("RC2 rejects zero-width Uint and implicit Field widening, while accepting singleton ranges", () => {
  for (const source of [
    'export circuit entry(x: Uint<0>): Uint<0> { return x; }',
    'export circuit entry(x: Uint<8>): Field { return x; }',
    'import CompactStandardLibrary; export circuit entry(x: Field): JubjubPoint { return ecMulGenerator(x); }',
  ]) checked(source, false, file => assert.equal(scanFile(file, { compilerVersion: version }).status, "incomplete"));
  checked('export circuit entry(x: Uint<0..1>): Field { return x as Field; }', true,
    file => assert.equal(scanFile(file, { compilerVersion: version }).status, "complete"));
});

test("RC2 primitive scalar works without imports; PublicAddress and old point aliases are not available", () => {
  checked('pragma language_version 0.25; export circuit entry(x: JubjubScalar): JubjubScalar { return x; }', true, file => {
    assert.equal(scanFile(file).status, "complete");
    assert.equal(scanFile(file, { compilerVersion: "0.34.0" }).status, "incomplete");
  });
  for (const name of ["NativePoint", "CurvePoint", "PublicAddress"])
    checked(`import CompactStandardLibrary; export circuit entry(x: ${name}): ${name} { return x; }`, false,
      file => assert.equal(scanFile(file, { compilerVersion: version }).status, "incomplete"));
});

test("RC2 free exported schemas distinguish the primitive scalar, nominal point and forbidden zero width", () => {
  for (const source of [
    'export struct Box<T> { value: JubjubScalar, other: T } export circuit entry(): Field { return 1 as Field; }',
    'import CompactStandardLibrary; export { JubjubPoint }; export circuit entry(x: JubjubPoint): JubjubPoint { return x; }',
    'import CompactStandardLibrary; export new type Box<T> = [T, JubjubPoint]; export circuit entry(): Field { return 1 as Field; }',
  ]) checked(source, true, file => assert.equal(scanFile(file, { compilerVersion: version }).status, "complete"));
  checked('export struct Box<T> { value: Uint<0>, other: T } export circuit entry(): Field { return 1 as Field; }', false,
    file => assert.equal(scanFile(file, { compilerVersion: version }).diagnostics[0].code, "invalid-numeric-type"));
});

test("RC2 scalar keyword cannot bind declarations, parameters, patterns, fields or unused generic locals", () => {
  for (const source of [
    'export circuit JubjubScalar(): [] {}',
    'export circuit Secp256k1Base(): [] {}',
    'export circuit Secp256k1Scalar(): [] {}',
    'circuit unused<T>(): [] { JubjubScalar; } export circuit entry(): [] {}',
    'circuit unused<T>(): [] { const x = T { JubjubScalar: 1 }; } export circuit entry(): [] {}',
    'export circuit entry(JubjubScalar: Field): Field { return JubjubScalar; }',
    'circuit unused<T>(): [] { const JubjubScalar = 1; } export circuit entry(): [] {}',
    'export struct Box<T> { JubjubScalar: T } export circuit entry(): [] {}',
    'export circuit entry([JubjubScalar]: [Field]): [] {}',
    'export struct Box<JubjubScalar> { value: JubjubScalar } export circuit entry(): [] {}',
  ]) checked(source, false, file => assert.equal(scanFile(file, { compilerVersion: version }).diagnostics[0].code, "reserved-identifier"));
});

test("RC2 identifier checks have no nesting limit and keep their first rejection", () => {
  const pairs = Array.from({ length: 21 }, (_, i) => Array.from({ length: 20 - i }, (_, k) => `v[${i}] != v[${i + k + 1}]`)).flat();
  checked(`pragma language_version 0.25; circuit distinct(v: Vector<21, Field>): Boolean { return ${pairs.join(" && ")}; }
export circuit entry(v: Vector<21, Field>): Boolean { return distinct(v); }`, true,
    file => assert.equal(new Program(file, [], undefined, undefined, 2, version).entries.length, 1));
  // The reserved binding follows a 200-level-deep left operand in pre-order.
  checked(`pragma language_version 0.25; export circuit entry(x: Boolean): Boolean { const a = ${Array(200).fill("x").join(" && ")}; const JubjubScalar = a; return JubjubScalar; }`, false,
    file => assert.equal(scanFile(file, { compilerVersion: version }).diagnostics[0].code, "reserved-identifier"));
  checked(`pragma language_version 0.25; export circuit entry(x: Boolean): Boolean { return ${Array(200).fill("x").join(" && ")} && ((JubjubScalar: Boolean): Boolean => JubjubScalar)(x); }`, false,
    file => assert.equal(scanFile(file, { compilerVersion: version }).diagnostics[0].code, "reserved-identifier"));
});

test("RC2 owned wide and deep syntax keeps the allowance and parameter rejection order", () => {
  const span = location;
  const leaf = (): Expr => ({ kind: "literal", span, value: "true", args: [] });
  const scope = (body?: Statement, parameters: Parameter[] = []): ScopeAst => ({ span, imports: [], exports: [], pragmas: [],
    declarations: [{ kind: "circuit", name: "entry", span, exported: true, type: "Boolean", parameters, body }] });
  const rejected = (ast: ScopeAst): string | undefined => {
    try { checkRc2Identifiers(ast); return undefined; } catch (error) {
      if (error instanceof AnalysisError) return error.diagnostic.code;
      throw error;
    }
  };
  const wide: Expr = { kind: "tuple", span, args: Array.from({ length: 200001 }, leaf) };
  assert.equal(rejected(scope({ kind: "return", span, expr: wide })), "profile-syntax-budget");
  // Declaration, statement and tuple charge three nodes; parameter names charge none.
  wide.args.length = 199997;
  assert.equal(rejected(scope({ kind: "return", span, expr: wide })), undefined);
  wide.args.push({ kind: "ref", name: "JubjubScalar", span, args: [] });
  assert.equal(rejected(scope({ kind: "return", span, expr: wide })), "profile-syntax-budget");
  wide.args[0] = { kind: "ref", name: "Secp256k1Base", span, args: [] };
  assert.equal(rejected(scope({ kind: "return", span, expr: wide })), "reserved-identifier");
  const flat: Statement = { kind: "block", span,
    body: Array.from({ length: 200001 }, () => ({ kind: "expr" as const, span, expr: leaf() })) };
  assert.equal(rejected(scope(flat)), "profile-syntax-budget");
  let deep = leaf();
  for (let index = 0; index < 100000; index++) deep = { kind: "binary", name: "&&", span, args: [deep, leaf()] };
  assert.equal(rejected(scope({ kind: "return", span, expr: deep })), "profile-syntax-budget");
  const parameters: Parameter[] = Array.from({ length: 200001 }, () => ({ name: "value", type: "Field", span }));
  assert.equal(rejected(scope(undefined, parameters)), undefined, "Plain parameters retain their existing allowance accounting");
  parameters[parameters.length - 1] = { name: "JubjubScalar", type: "Field", span };
  assert.equal(rejected(scope(undefined, parameters)), "reserved-identifier", "Wide root parameters do not overflow call arguments");
  parameters[0] = { name: "value", type: "Field", span, pattern: { kind: "name", name: "Secp256k1Scalar", span, children: [] } };
  assert.throws(() => checkRc2Identifiers(scope(undefined, parameters)), (error: unknown) =>
    error instanceof AnalysisError && error.diagnostic.code === "reserved-identifier" && error.diagnostic.message.startsWith("Secp256k1Scalar"));
});

test("RC2 import keyword checks apply to prefix/alias tokens, not generated names", () => {
  checked('import { none as Scalar } from CompactStandardLibrary prefix Jubjub; export circuit entry(): [] {}', true,
    file => assert.equal(scanFile(file, { compilerVersion: version }).status, "complete"));
  for (const source of [
    'import CompactStandardLibrary prefix JubjubScalar; export circuit entry(): [] {}',
    'import { none as Secp256k1Base } from CompactStandardLibrary; export circuit entry(): [] {}',
  ]) checked(source, false, file => assert.equal(scanFile(file, { compilerVersion: version }).diagnostics[0].code, "reserved-identifier"));
});

test("RC2 constructor events reject and optimized empty events remain explicitly incomplete", () => {
  checked('import CompactStandardLibrary; constructor() { emit(default<Paused>); } export circuit entry(): [] {}', false,
    file => assert.equal(scanFile(file, { compilerVersion: version }).diagnostics[0].code, "constructor-event"));
  checked('import CompactStandardLibrary; export ledger stored: Field; circuit payload(): Paused { stored = 1 as Field; return Paused {}; } export circuit entry(): [] { emit(payload()); }', true, file => {
    const result = scanFile(file, { compilerVersion: version });
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0].code, "unsupported-empty-event-effects");
  });
});

test("public JSON schemas, human summary and SARIF admit every qualified profile identity", () => {
  const validate = new Ajv({ strict: false }).compile(JSON.parse(readFileSync("docs/schema/report.schema.json", "utf8")));
  withFiles({ "main.compact": 'export circuit entry(): Field { return 1 as Field; }' }, directory => {
    for (const compilerVersion of [version, "0.35.0", "0.35.0-rc.1"] as const) {
      const result = scanFile(resolve(directory, "main.compact"), { compilerVersion });
      assert.equal(result.status, "complete");
      assert.equal(validate(result), true, JSON.stringify(validate.errors));
      assert.match(human(result), new RegExp(`compact-${compilerVersion.replaceAll(".", "\\.")}-zkir2`));
      assert.equal((sarif(result) as { runs: { properties: { semanticProfile: string } }[] }).runs[0].properties.semanticProfile, result.semanticProfile);
    }
  });
});

test("RC2 ledger snapshots, caller guard, provenance and events agree across engines and summary modes", () => {
  checked(`pragma language_version 0.25; import CompactStandardLibrary;
    export ledger owner: Bytes<32>; export ledger saved: Field;
    circuit authorize(): [] { assert(ownPublicKey().bytes == owner, "owner"); }
    circuit remember(x: Field): Field { saved = disclose(x); return saved; }
    export circuit entry(value: Field): Field {
      authorize();
      remember(value); emit(default<Paused>); return remember(saved + 1);
    }`, true, file => {
    const program = new Program(file); assert.equal(program.compilerVersion, version);
    let baseline: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.equal(facts.paths.length, 1);
      const path = facts.paths[0];
      assert.ok(path.writes.every(write => write.guards.length > 0));
      assert.ok(path.writes.every(write => write.after.flows.some(flow => flow.source.name === "value")));
      assert.equal(path.operations!.filter(operation => operation.kind === "event").length, 1);
      baseline ??= semanticPaths(facts); assert.deepEqual(semanticPaths(facts), baseline);
    }
  });
});

test("RC2 opaque points retain component equality, group operations and identity defaults", () => {
  checked(`pragma language_version 0.25; import CompactStandardLibrary;
    export circuit identity(): Boolean {
      return jubjubPointY(default<JubjubPoint>) == (1 as Field) && ecNeg(default<JubjubPoint>) == default<JubjubPoint>;
    }
    export circuit scalar(x: Field): JubjubPoint { return ecMulGenerator(x as JubjubScalar); }`, true, file => {
    const program = new Program(file); let baseline: string[] | undefined;
    assert.ok([...program.nominalTypes.values()].some(type => type.underlying === 'Opaque<"JubjubPoint">'));
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.ok(facts.paths.some(path => path.sinks.some(sink => sink.value.constantKind === "boolean" && sink.value.constant === "true")));
      baseline ??= semanticPaths(facts); assert.deepEqual(semanticPaths(facts), baseline);
    }
  });
});

test("RC2 Schnorr retains identity-key acceptance; keccak is available, never legacy Field multiplication", () => {
  checked(`pragma language_version 0.25; import CompactStandardLibrary;
    export circuit entry(): Boolean {
      return jubjubSchnorrVerify<1>(default<Vector<1, Field>>, default<JubjubSchnorrSignature>, default<JubjubPoint>);
    }
    export circuit digest(value: Field): Bytes<32> { return keccak256<Field>(value); }`, true, file => {
    const program = new Program(file); let baseline: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.ok(facts.paths.some(path => path.sinks.some(sink => sink.value.constantKind === "boolean" && sink.value.constant === "true")));
      assert.equal(facts.failedAssertions.length, 0);
      baseline ??= semanticPaths(facts); assert.deepEqual(semanticPaths(facts), baseline);
    }
  });
});

test("RC2 unsupported ZKIR3 is explicitly incomplete in scans and compiler validation", () => {
  checked('pragma language_version 0.25; export circuit entry(): Field { return 1 as Field; }', true, file => {
    const result = scanFile(file, { compilerVersion: version, zkirVersion: 3 });
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0].code, "unsupported-compiler-profile");
    assert.equal(result.findings.length, 0);
    assert.equal(result.coverage.completedEntries.length, 0);
    if (compiler) assert.equal(validateWithCompiler(compiler, file, [], 30000, 3, version).valid, false);
  });
});

test("RC2 config, CLI, compiler mismatch and supervised worker preserve the exact profile", async () => {
  let pending: ReturnType<typeof scanFileIsolated> | undefined;
  withFiles({ "main.compact": "pragma language_version 0.25; export circuit entry(): Field { return 1 as Field; }", "nightshade.json": '{"version":1,"compilerVersion":"0.33.0-rc.2"}' }, directory => {
    const file = resolve(directory, "main.compact"), config = readConfiguration(resolve(directory, "nightshade.json"));
    assert.equal(config.options.compilerVersion, version);
    const cli = JSON.parse(execFileSync(process.execPath, [resolve("dist/src/cli.js"), "scan", file, "--json", "--compiler-version", version], { encoding: "utf8" }));
    assert.equal(cli.status, "complete"); assert.equal(cli.semanticProfile, `compact-${version}-zkir2`);
    if (compiler) {
      const pinned = scanFile(file, { compiler });
      assert.equal(pinned.compilerValidated, true); assert.equal(pinned.semanticProfile, `compact-${version}-zkir2`);
      assert.equal(scanFile(file, { compiler, compilerVersion: "0.34.0" }).diagnostics[0].code, "compiler-profile-mismatch");
    }
    pending = scanFileIsolated(resolve(directory, "missing.compact"), config.options);
  });
  const missing = await pending!;
  assert.equal(missing.status, "incomplete"); assert.equal(missing.semanticProfile, `compact-${version}-zkir2`);
  const complete = await scanFileIsolated(resolve("tests/corpus/informational/dead-code-corrected.compact"), { compilerVersion: version });
  assert.equal(complete.status, "complete"); assert.equal(complete.semanticProfile, `compact-${version}-zkir2`);
});
