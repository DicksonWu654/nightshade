import assert from "node:assert/strict";
import test from "node:test";
import { chmodSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { compilerIdentity, validateWithCompiler } from "./compiler-fixtures.js";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { readConfiguration } from "../src/config.js";
import { selectCompilerVersion, type CompilerVersion } from "../src/semantic/profile.js";
import { withFiles } from "./helpers.js";

const version = "0.35.0-rc.1" as const;
const compiler = process.env.COMPACTC_035_RC1_TEST;
const location = { file: "main.compact", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
function checked(source: string, inspect: (file: string) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (compiler) {
      const result = validateWithCompiler(compiler, file, [], 30000, 2, version);
      assert.equal(result.valid, true, result.error);
      assert.equal(result.version, version);
      assert.equal(result.languageVersion, "0.27.0");
    }
    inspect(file);
  });
}

test("prerelease selection preserves stable defaults and rejects unqualified ZKIR3", () => {
  assert.equal(selectCompilerVersion([], location), "0.34.0");
  assert.equal(selectCompilerVersion(["pragma language_version >= 0.22;"], location), "0.34.0");
  assert.equal(selectCompilerVersion(["pragma language_version 0.27;"], location), "0.35.0");
  assert.equal(selectCompilerVersion(["pragma compiler_version 0.35;"], location), "0.35.0");
  assert.equal(selectCompilerVersion([], location, version), version);
  assert.throws(() => selectCompilerVersion([], location, version, 3), /ZKIR3/);
  assert.throws(() => selectCompilerVersion([], location, "0.35.0-rc.0" as CompilerVersion), /Unsupported compiler/);
  assert.throws(() => selectCompilerVersion(["pragma language_version 0.28;"], location), /No supported compiler/);
});

test("compiler identity accepts the pinned release stamp and refuses unknown builds or malformed suffixes", () => {
  withFiles({}, directory => {
    const file = resolve(directory, "compactc");
    const identity = (reported: string) => {
      writeFileSync(file, `#!/bin/sh\ncase "$1" in --version) printf '%s\\n' '${reported}' ;; --language-version) printf '%s\\n' '0.27.0' ;; *) exit 2 ;; esac\n`);
      chmodSync(file, 0o755);
      return compilerIdentity(file);
    };
    assert.equal(identity("0.35.0-rc.1 (debb05f94 2026-09-29)").valid, true);
    assert.equal(identity("0.35.0-rc.1").valid, false);
    assert.equal(identity("0.35.0-rc.1 (000000000 2026-09-29)").valid, false);
    assert.equal(identity("0.35.0-dev (debb05f94 2026-09-29)").valid, false);
    assert.equal(identity("0.35.0-rc.1 arbitrary suffix").valid, false);
    assert.equal(identity("0.35.0-rc.1 (debb05f94 wrong-date)").valid, false);
  });
  if (compiler) assert.equal(compilerIdentity(compiler).valid, true);
});

test("prerelease public-address alias and ordinary ledger transfers agree across both engines and cache modes", () => {
  checked(`pragma language_version 0.27; import CompactStandardLibrary;
  export ledger recipient: PublicAddress;
  export circuit entry(value: PublicAddress): PublicAddress { recipient = disclose(value); return recipient; }`, file => {
    const program = new Program(file, [], undefined, undefined, 2, version), results = [];
    assert.equal(program.compilerVersion, version);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const result = new Dataflow(program, 40000, 256, 50000, engine, cached).analyze();
      assert.deepEqual(result.diagnostics, []);
      assert.deepEqual(result.completedEntries, program.entries);
      assert.equal(result.paths.length, 1);
      results.push(result.paths);
    }
    for (const result of results) assert.deepEqual(result, results[0]);
    assert.equal(scanFile(file, { compilerVersion: version }).semanticProfile, "compact-0.35.0-rc.1-zkir2");
    assert.equal(scanFile(file, { compilerVersion: "0.34.0" }).status, "incomplete");
  });
});

test("prerelease Schnorr verifier retains the new identity-key assertion", () => {
  checked(`pragma language_version 0.27; import CompactStandardLibrary;
  export circuit entry(): Boolean {
    return jubjubSchnorrVerify<1>(default<Vector<1, Field>>, default<JubjubSchnorrSignature>, default<JubjubPoint>);
  }`, file => {
    const program = new Program(file, [], undefined, undefined, 2, version);
    for (const engine of ["instructions", "expressions"] as const) {
      const result = new Dataflow(program, 40000, 256, 50000, engine).analyze();
      assert.deepEqual(result.diagnostics, []);
      assert.equal(result.paths.length, 0);
      assert.ok(result.failedAssertions.some(item => item.location.file.endsWith("standard-library-0.35-rc.1.compact")));
    }
  });
});

test("new kernel caller semantics are modeled as an unknown read", () => {
  checked(`pragma language_version 0.27; import CompactStandardLibrary;
  export circuit entry(): Maybe<PublicAddress> { return kernel.caller(); }`, file => {
    const result = scanFile(file, { compilerVersion: version });
    assert.equal(result.status, "complete");
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.coverage.completedEntries.length, 1);
  });
});

test("configuration and isolated scans retain the prerelease profile and ZKIR restriction", async () => {
  withFiles({ "main.compact": "export circuit entry(): Field { return 1 as Field; }", "nightshade.json": '{"version":1,"compilerVersion":"0.35.0-rc.1"}' }, directory => {
    const selected = readConfiguration(resolve(directory, "nightshade.json"));
    assert.equal(selected.options.compilerVersion, version);
    const file = resolve(directory, "main.compact");
    assert.equal(scanFile(file, selected.options).status, "complete");
    assert.equal(scanFile(file, { compilerVersion: version, zkirVersion: 3 }).status, "incomplete");
  });
  // Keep the temporary directory alive until the supervised worker returns.
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-rc-worker-"));
  try {
    const file = resolve(directory, "main.compact");
    writeFileSync(file, "pragma language_version 0.27; export circuit entry(): Field { return 1 as Field; }");
    const result = await scanFileIsolated(file, { compilerVersion: version });
    assert.equal(result.status, "complete");
    assert.equal(result.semanticProfile, "compact-0.35.0-rc.1-zkir2");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
