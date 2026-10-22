import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { compilerIdentity, validateWithCompiler } from "./compiler-fixtures.js";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { selectCompilerVersion } from "../src/semantic/profile.js";
import { withFiles, semanticPaths } from "./helpers.js";

// Compilers 0.29.0 / language 0.21.0 (tag v0.29.0, f17a98c) and 0.28.0 /
// language 0.20.0 (tag v0.28.0, dce2f11). Fixtures are validated against the
// release binaries when COMPACTC_029_TEST / COMPACTC_028_TEST are set.
const version = "0.29.0" as const;
const compilers = { "0.29.0": process.env.COMPACTC_029_TEST, "0.28.0": process.env.COMPACTC_028_TEST };
const languages = { "0.29.0": "0.21.0", "0.28.0": "0.20.0" };
const location = { file: "main.compact", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
const header = "pragma language_version 0.21; import CompactStandardLibrary;\n";
const header028 = "pragma language_version 0.20; import CompactStandardLibrary;\n";
function checked(files: Record<string, string>, valid: boolean, inspect: (file: string) => void, profile: "0.29.0" | "0.28.0" = version): void {
  withFiles(files, directory => {
    const file = resolve(directory, "main.compact"), compiler = compilers[profile];
    if (compiler) {
      const result = validateWithCompiler(compiler, file, [], 30000, 2, profile);
      assert.equal(result.valid, valid, `${result.error}`);
      assert.equal(result.version, profile);
      assert.equal(result.languageVersion, languages[profile]);
    }
    inspect(file);
  });
}
const incomplete = (file: string, code: string, profile: "0.29.0" | "0.28.0" = version) => {
  const result = scanFile(file);
  assert.equal(result.semanticProfile, `compact-${profile}-zkir2`);
  assert.equal(result.status, "incomplete");
  assert.equal(result.diagnostics.filter(issue => !issue.scope)[0]?.code, code);
};

test("0.29 profile is a pragma fallback below stable 0.30 and keeps the 0.34 default", () => {
  assert.equal(selectCompilerVersion([], location), "0.34.0");
  assert.equal(selectCompilerVersion(["pragma language_version >= 0.21;"], location), "0.34.0");
  assert.equal(selectCompilerVersion(["pragma language_version >= 0.16 && <= 0.22;"], location), "0.30.0");
  assert.equal(selectCompilerVersion(["pragma language_version 0.21;"], location), version);
  assert.equal(selectCompilerVersion(["pragma language_version >= 0.21 && <= 0.21;"], location), version);
  assert.equal(selectCompilerVersion(["pragma compiler_version 0.29;"], location), version);
  assert.equal(selectCompilerVersion(["pragma language_version >= 0.20;"], location, version), version);
  assert.throws(() => selectCompilerVersion(["pragma language_version 0.22;"], location, version), /No supported compiler/);
  assert.throws(() => selectCompilerVersion(["pragma language_version 0.19;"], location), /No supported compiler/);
  assert.throws(() => selectCompilerVersion([], location, version, 3), /ZKIR3/);
  assert.equal(selectCompilerVersion(["pragma language_version 0.20;"], location), "0.28.0");
  for (const [profile, compiler] of Object.entries(compilers)) if (compiler) assert.deepEqual(compilerIdentity(compiler), { valid: true, version: profile, languageVersion: languages[profile as keyof typeof languages] });
});

test("0.29 struct-backed NativePoint uses the exact library accessors, literals and component equality", () => {
  checked({ "main.compact": `${header}export ledger last: NativePoint;
    export circuit coords(x: Field, y: Field): Boolean {
      const p = constructNativePoint(x, y); const q = NativePoint { x: y, y: x };
      last = disclose(p);
      return nativePointX(p) == x && nativePointY(p) == y && p.x == q.y && p == constructNativePoint(x, y);
    }
    export circuit widen(x: Uint<64>): Field { return x; }` }, true, file => {
    const program = new Program(file);
    assert.equal(program.compilerVersion, version);
    assert.ok([...program.nominalTypes.values()].some(type => type.underlying === "standard-library::SimplePoint"));
    let baseline: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.ok(facts.paths.some(path => path.entry.endsWith("::coords") && path.sinks.some(sink => sink.value.constantKind === "boolean" && sink.value.constant === "true")));
      baseline ??= semanticPaths(facts); assert.deepEqual(semanticPaths(facts), baseline);
    }
  });
});

test("0.29 curve natives, opaque hashing and file lookup diagnose instead of reusing 0.30 models", () => {
  for (const [source, code] of [
    ["export circuit f(x: Field): NativePoint { return ecMulGenerator(x); }", "unsupported-profile-native"],
    ["export circuit f(a: NativePoint, b: NativePoint): NativePoint { return ecAdd(a, b); }", "unsupported-profile-native"],
    ["export circuit f(x: Field): Field { return hashToCurve<Field>(x).x; }", "unsupported-profile-native"],
    ['export circuit f(x: Opaque<"string">): Bytes<32> { return persistentHash<Opaque<"string">>(x); }', "unsupported-opaque-intrinsic"],
  ] as const) checked({ "main.compact": header + source }, true, file => incomplete(file, code));
  checked({ "main.compact": header + "circuit ecAdd(a: Field, b: Field): Field { return a + b; }\nexport circuit g(x: Field): Field { return ecAdd(x, x); }" }, true,
    file => assert.equal(scanFile(file).status, "complete"));
  checked({ "main.compact": `${header}include "lib";\nexport circuit f(): Field { return g(); }`, "lib.compact": "circuit g(): Field { return 1; }" }, true,
    file => incomplete(file, "unsupported-profile-search-order"));
  checked({ "main.compact": `${header}import "Lib";\nexport circuit f(): Field { return g(); }`, "Lib.compact": "module Lib { export circuit g(): Field { return 1; } }" }, true,
    file => incomplete(file, "unsupported-profile-search-order"));
});

test("0.29 rejects later Jubjub names and keeps legacy numeric, loop and event restrictions", () => {
  for (const [source, code] of [
    ["export circuit f(x: Field): JubjubPoint { return ecMulGenerator(x); }", "unresolved-type"],
    ["export circuit f(x: Field, y: Field): Field { return jubjubPointX(constructNativePoint(x, y)); }", "unresolved-symbol"],
    ["export circuit f(x: Field, y: Field): Field { return nativePointX(constructJubjubPoint(x, y)); }", "unresolved-symbol"],
    ['export circuit f(x: Opaque<"JubjubPoint">): Field { return 0; }', "unsupported-opaque-type"],
    ["export circuit f(x: Field): Bytes<32> { return keccak256<Field>(x); }", "unresolved-symbol"],
    ["export circuit f(x: Uint<0>): Field { return x; }", "invalid-numeric-type"],
    ["export circuit f(): Field { for (const i of 0..1001) { } return 0; }", "unsupported-profile-syntax"],
    ["export circuit f(): [] { emit(default<Paused>); }", "unsupported-profile-syntax"],
  ] as const) checked({ "main.compact": header + source }, false, file => incomplete(file, code));
});

test("0.28 library uses capitalized NativePoint accessors and blanks only its external native declarations", () => {
  checked({ "main.compact": `${header028}export circuit f(x: Field, y: Field): Boolean {
      const p = NativePoint { x: x, y: y }; return NativePointX(p) == x && NativePointY(p) == y && p.x == x;
    }
    export circuit g(x: Field): Field { return transientHash<Field>(x) + degradeToTransient(persistentHash<Field>(x)); }` }, true, file => {
    const program = new Program(file); assert.equal(program.compilerVersion, "0.28.0");
    let baseline: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.ok(facts.paths.some(path => path.entry.endsWith("::f") && path.sinks.some(sink => sink.value.constantKind === "boolean" && sink.value.constant === "true")));
      baseline ??= semanticPaths(facts); assert.deepEqual(semanticPaths(facts), baseline);
    }
  }, "0.28.0");
  checked({ "main.compact": header028 + "export circuit f(x: Field, y: Field): Field { return nativePointX(constructNativePoint(x, y)); }" }, false,
    file => incomplete(file, "unresolved-symbol", "0.28.0"), "0.28.0");
  checked({ "main.compact": header028 + "export circuit f(x: Field): NativePoint { return ecMulGenerator(x); }" }, true,
    file => incomplete(file, "unsupported-profile-native", "0.28.0"), "0.28.0");
});

test("redundant self receive requires the auto-receiving 0.29 library, not 0.28", () => {
  const source = (pragma: string) => `pragma language_version ${pragma}; import CompactStandardLibrary;
    export circuit mintSelf(nonce: Bytes<32>): [] {
      const coin = mintShieldedToken(pad(32, "token"), 10, disclose(nonce), right<ZswapCoinPublicKey, ContractAddress>(kernel.self()));
      receiveShielded(coin);
    }`;
  checked({ "main.compact": source("0.21") }, true, file => {
    const result = scanFile(file);
    assert.equal(result.coverage.baselineStatus, "complete");
    assert.deepEqual(result.findings.map(finding => finding.detectorId), ["redundant-self-shielded-receive"]);
  });
  checked({ "main.compact": source("0.20") }, true, file => {
    const result = scanFile(file);
    assert.equal(result.coverage.baselineStatus, "complete");
    assert.deepEqual(result.findings, []);
    assert.deepEqual(result.diagnostics.map(issue => [issue.code, issue.scope?.detectorId]), [["redundant-receive-evidence-unavailable", "redundant-self-shielded-receive"]]);
  }, "0.28.0");
});
