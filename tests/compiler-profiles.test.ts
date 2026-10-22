import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile, scanFileIsolated, mergeResults } from "../src/index.js";
import { selectCompilerVersion, type CompilerVersion } from "../src/semantic/profile.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { readConfiguration } from "../src/config.js";
import { JUBJUB_SCALAR_MODULUS } from "../src/semantic/fields.js";
import { withFiles, semanticPaths } from "./helpers.js";

const compilers: Partial<Record<CompilerVersion, string>> = { "0.30.0": process.env.COMPACTC_030_TEST, "0.31.1": process.env.COMPACTC_031_TEST, "0.34.0": process.env.COMPACTC_TEST };
const old: CompilerVersion[] = ["0.30.0", "0.31.1"];
const location = { file: "owned.compact", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
function checked(source: string, version: CompilerVersion, valid: boolean, inspect: (file: string) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), compiler = compilers[version];
    if (compiler) {
      const result = validateWithCompiler(compiler, file, [], 30000, 2, version);
      assert.equal(result.valid, valid, `${version}: ${result.error}`);
    }
    inspect(file);
  });
}

test("compiler selection honors bounded pragma predicates and explicit toolchain pins", () => {
  for (const [pragma, version] of [["", "0.34.0"], [">= 0.16 && <= 0.22", "0.30.0"], ["0.23", "0.31.1"], [">= 0.22", "0.34.0"], ["(0.22 || 0.23) && < 0.24", "0.31.1"], ["0", "0.34.0"], ["!0.26", "0.35.0"]]) {
    assert.equal(selectCompilerVersion(pragma ? [`pragma language_version ${pragma};`] : [], location), version);
  }
  assert.equal(selectCompilerVersion(["pragma language_version >= 0.22;"], location, "0.30.0"), "0.30.0");
  for (const pragma of ["0.16", ">= 0.99", "0.22 || invalid", "0.23 trailing"]) {
    assert.throws(() => selectCompilerVersion([`pragma language_version ${pragma};`], location), /version|predicate/);
  }
  assert.throws(() => selectCompilerVersion([], location, "0.27.0" as CompilerVersion), /Unsupported compiler/);
  assert.throws(() => selectCompilerVersion(["pragma language_version 0.22;"], location, "0.34.0"), /No supported compiler/);
  assert.throws(() => selectCompilerVersion([], location, "0.30.0", 3), /ZKIR3/);
  assert.throws(() => selectCompilerVersion([`pragma language_version ${"(".repeat(34)}0.22${")".repeat(34)};`], location), /nesting/);
});

test("compiler predicates use upstream wildcard semantics and constrain automatic/explicit selection", () => {
  for (const predicate of ["0.31.1", "0.31", "0", "<= 0.31", "< 0.31", "> 0.31", "!0.30", "(0.30 || 0.31) && >= 0.31.0"]) {
    checked(`pragma compiler_version ${predicate}; export circuit entry(): Field { return 1 as Field; }`, "0.31.1", true, file => {
      assert.equal(scanFile(file, { compilerVersion: "0.31.1" }).status, "complete", predicate);
    });
  }
  checked("pragma compiler_version 0.31; export circuit entry(): Field { return 1 as Field; }", "0.30.0", false, file => {
    assert.equal(scanFile(file).semanticProfile, "compact-0.31.1-zkir2");
    assert.equal(scanFile(file, { compilerVersion: "0.30.0" }).diagnostics[0].code, "unsupported-compiler-version");
  });
  for (const source of ["pragma potato 0.23;", "pragma compiler_version 0.99;"]) checked(`${source} export circuit entry(): [] {}`, "0.31.1", false,
    file => assert.equal(scanFile(file).status, "incomplete"));
  checked("pragma language_version 0; export circuit entry(): [] {}", "0.31.1", true, file => assert.equal(scanFile(file).status, "complete"));
  checked("pragma language_version !0.26; export circuit entry(): [] {}", "0.31.1", true,
    file => assert.equal(scanFile(file).semanticProfile, "compact-0.35.0-zkir2"));
});

test("imports cannot silently change the selected compiler profile", () => {
  withFiles({ "main.compact": 'pragma language_version 0.22; import "Library"; export circuit entry(): Field { return api(); }',
    "Library.compact": 'pragma language_version 0.26; module Library { export circuit api(): Field { return 1 as Field; } }' }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.equal(result.status, "incomplete");
    assert.equal(result.semanticProfile, "compact-0.30.0-zkir2");
    assert.equal(result.diagnostics[0].code, "unsupported-language-version");
  });
  withFiles({ "main.compact": 'pragma compiler_version 0.30; import "Library"; export circuit entry(): Field { return api(); }',
    "Library.compact": 'pragma compiler_version 0.31; module Library { export circuit api(): Field { return 1; } }' }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0].code, "unsupported-compiler-version");
  });
});

test("isolated reports and CLI/config selection retain historical profiles and explicit failures", async () => {
  const source = 'pragma language_version 0.23; export circuit entry(x: Uint<64>): Field { return x; }';
  withFiles({ "main.compact": source, "nightshade.json": '{"version":1,"compilerVersion":"0.31.1"}' }, directory => {
    const file = resolve(directory, "main.compact");
    assert.equal(readConfiguration(resolve(directory, "nightshade.json")).options.compilerVersion, "0.31.1");
    const result = JSON.parse(execFileSync(process.execPath, [resolve('dist/src/cli.js'), 'scan', file, '--json', '--compiler-version', '0.31.1'], { encoding: 'utf8' }));
    assert.equal(result.status, "complete"); assert.equal(result.semanticProfile, "compact-0.31.1-zkir2");
  });
  const result = await scanFileIsolated(resolve('tests/corpus/informational/dead-code-corrected.compact'), { compilerVersion: '0.30.0' });
  assert.equal(result.status, 'complete'); assert.equal(result.semanticProfile, 'compact-0.30.0-zkir2');
  for (const scanner of [scanFile, scanFileIsolated]) {
    const missing = await scanner("/nonexistent-profile-input.compact", { compilerVersion: "0.30.0" });
    assert.equal(missing.status, "incomplete"); assert.equal(missing.semanticProfile, "compact-0.30.0-zkir2");
    assert.equal(missing.diagnostics[0].code, "input-error");
  }
  const failure = await scanFileIsolated("/nonexistent-profile-input.compact", { compilerVersion: "0.31.1" }, { timeoutMs: 0 });
  assert.equal(failure.status, "incomplete"); assert.equal(failure.semanticProfile, "compact-0.31.1-zkir2");
  assert.match(failure.diagnostics[0].code, /^worker-/);
  const modern = scanFile(resolve('tests/corpus/informational/dead-code-corrected.compact'));
  assert.equal(mergeResults([result, modern]).semanticProfile, "mixed");
});

test("compiler executable is a toolchain pin and cannot disagree with configuration", () => {
  if (!compilers['0.30.0']) return;
  checked('export circuit entry(x: Uint<64>): Field { return x; }', '0.30.0', true, file => {
    const result = scanFile(file, { compiler: compilers['0.30.0'] });
    assert.equal(result.status, 'complete'); assert.equal(result.compilerValidated, true); assert.equal(result.semanticProfile, 'compact-0.30.0-zkir2');
    assert.equal(scanFile(file, { compiler: compilers['0.30.0'], compilerVersion: '0.34.0' }).diagnostics[0].code, 'compiler-profile-mismatch');
  });
});
