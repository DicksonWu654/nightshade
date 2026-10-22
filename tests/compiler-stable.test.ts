import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { chmodSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { compilerIdentity, validateWithCompiler } from "./compiler-fixtures.js";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { readConfiguration } from "../src/config.js";
import { selectCompilerVersion } from "../src/semantic/profile.js";
import { withFiles } from "./helpers.js";

const version = "0.35.0" as const;
const compiler = process.env.COMPACTC_035_TEST;
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

test("stable 0.35 selection preserves 0.34 defaults and prefers the stable release to RC", () => {
  for (const pragma of ["", "pragma language_version >= 0.22;", "pragma compiler_version >= 0.30;"]) {
    assert.equal(selectCompilerVersion(pragma ? [pragma] : [], location), "0.34.0");
  }
  for (const pragma of ["pragma language_version 0.27;", "pragma compiler_version 0.35;", "pragma compiler_version 0.35.0;", "pragma language_version !0.26;"]) {
    assert.equal(selectCompilerVersion([pragma], location), version);
  }
  assert.equal(selectCompilerVersion([], location, version), version);
  assert.equal(selectCompilerVersion(["pragma compiler_version 0.35;"], location, "0.35.0-rc.1"), "0.35.0-rc.1");
  assert.throws(() => selectCompilerVersion([], location, version, 3), /ZKIR3/);
});

test("stable compiler identity requires the pinned stamp and matching language", () => {
  withFiles({}, directory => {
    const file = resolve(directory, "compactc");
    const identity = (reported: string, language = "0.27.0") => {
      writeFileSync(file, `#!/bin/sh\ncase "$1" in --version) printf '%s\\n' '${reported}' ;; --language-version) printf '%s\\n' '${language}' ;; *) exit 2 ;; esac\n`);
      chmodSync(file, 0o755);
      return compilerIdentity(file);
    };
    assert.equal(identity("0.35.0 (debb05f94 2026-09-29)").valid, true);
    for (const reported of ["0.35.0", "0.35.0 (000000000 2026-09-29)", "0.35.0-dev (debb05f94 2026-09-29)", "0.35.0 arbitrary suffix", "0.35.0 (debb05f94 wrong-date)"]) {
      assert.equal(identity(reported).valid, false, reported);
    }
    assert.equal(identity("0.35.0 (debb05f94 2026-09-29)", "0.26.0").valid, false);
  });
  if (compiler) assert.equal(compilerIdentity(compiler).valid, true);
});

test("stable PublicAddress and Schnorr rejection retain both engines and cache modes", () => {
  for (const [body, rejected] of [
    ["export ledger recipient: PublicAddress; export circuit entry(value: PublicAddress): PublicAddress { recipient = disclose(value); return recipient; }", false],
    ["export circuit entry(): Boolean { return jubjubSchnorrVerify<1>(default<Vector<1, Field>>, default<JubjubSchnorrSignature>, default<JubjubPoint>); }", true],
  ] as const) checked(`pragma language_version 0.27; import CompactStandardLibrary; ${body}`, file => {
    const program = new Program(file);
    assert.equal(program.compilerVersion, version);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const result = new Dataflow(program, 40000, 256, 50000, engine, cached).analyze();
      assert.deepEqual(result.diagnostics, []);
      assert.deepEqual(result.completedEntries, program.entries);
      assert.equal(result.paths.length, rejected ? 0 : 1);
      if (rejected) assert.ok(result.failedAssertions.some(item => item.location.file.endsWith("standard-library-0.35-rc.1.compact")));
      baseline ??= result.paths;
      assert.deepEqual(result.paths, baseline);
    }
    assert.equal(scanFile(file).semanticProfile, "compact-0.35.0-zkir2");
    assert.equal(scanFile(file, { compilerVersion: "0.34.0" }).status, "incomplete");
  });
});

test("stable caller is modeled and dynamic cross-contract calls retain an explicit re-entry boundary", () => {
  for (const [body, code] of [
    ["import CompactStandardLibrary; export circuit entry(): Maybe<PublicAddress> { return kernel.caller(); }", "caller"],
    ["contract Callee { circuit getSquare(x: Field): Field; } ledger callee: Callee; constructor (c: Callee) { callee = disclose(c); } export circuit entry(x: Field): Field { return callee.getSquare(disclose(x)); }", "unsupported-contract-call"],
  ] as const) checked(`pragma language_version 0.27; ${body}`, file => {
    const result = scanFile(file);
    assert.equal(result.status, code === "caller" ? "complete" : "incomplete");
    assert.equal(result.coverage.baselineStatus, code === "caller" ? "complete" : "incomplete");
    assert.equal(result.semanticProfile, "compact-0.35.0-zkir2");
    if (code === "caller") assert.deepEqual(result.diagnostics, []);
    if (code === "unsupported-contract-call") assert.ok(result.diagnostics.some(item => ["unsupported-contract-call", "dynamic-contract-call"].includes(item.code) && !item.scope));
    // Only the entry that reaches the unmodeled call is incomplete.
    assert.equal(result.coverage.completedEntries.some(entry => entry.endsWith("::entry")), code === "caller");
    assert.deepEqual(result.coverage.completedEntries.map(entry => entry.replace(/.*::/, "")), code === "unsupported-contract-call" ? ["constructor"] : ["entry"]);
  });
});

test("stable 0.35 invocation boundaries retain post-call writes and caller provenance", () => {
  checked(`pragma language_version 0.27; import CompactStandardLibrary;
  export circuit entry(): Maybe<PublicAddress> { return kernel.caller(); }`, file => {
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      const path = facts.paths.find(item => item.entry.endsWith("::entry"))!;
      const caller = path.operations?.find(operation => operation.kind === "kernel-read" && operation.name === "caller");
      assert.equal(caller?.result.kernelCaller, true, `${engine}/${cached}`);
    }
  });
  checked(`pragma language_version 0.27; import CompactStandardLibrary;
  contract Callee { circuit touch(x: Uint<64>): []; }
  export ledger callee: Callee;
  export ledger total: Uint<64>;
  constructor(c: Callee) { callee = disclose(c); total = 0; }
  export circuit entry(x: Uint<64>): Uint<64> {
    callee.touch(disclose(x));
    total = disclose(x);
    return total;
  }`, file => {
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.ok(facts.diagnostics.some(item => item.code === "dynamic-contract-call"), `${engine}/${cached}`);
      const path = facts.paths.find(item => item.entry.endsWith("::entry"))!;
      const invocation = path.operations?.find(operation => operation.kind === "circuit-invocation" && operation.name === "contract.touch");
      assert.equal(invocation?.result.predicateStructureLost, true, `${engine}/${cached}`);
      const write = path.writes.find(item => item.ledger.endsWith("::total"));
      assert.ok(write, `${engine}/${cached}`);
      const returned = path.sinks.find(item => item.kind === "exported-return")?.value;
      assert.ok(returned?.flows.some(flow => flow.source.name === "x"), `${engine}/${cached}`);
    }
  });
});

test("stable profile survives config, CLI, executable pins and supervised workers", async () => {
  let isolated: ReturnType<typeof scanFileIsolated> | undefined;
  withFiles({ "main.compact": "export circuit entry(): Field { return 1 as Field; }", "nightshade.json": '{"version":1,"compilerVersion":"0.35.0"}' }, directory => {
    const selected = readConfiguration(resolve(directory, "nightshade.json"));
    assert.equal(selected.options.compilerVersion, version);
    const file = resolve(directory, "main.compact");
    assert.equal(scanFile(file, selected.options).semanticProfile, "compact-0.35.0-zkir2");
    assert.equal(scanFile(file, { compilerVersion: version, zkirVersion: 3 }).status, "incomplete");
    const cli = JSON.parse(execFileSync(process.execPath, [resolve("dist/src/cli.js"), "scan", file, "--json", "--compiler-version", version], { encoding: "utf8" }));
    assert.equal(cli.status, "complete");
    assert.equal(cli.semanticProfile, "compact-0.35.0-zkir2");
    if (compiler) {
      const pinned = scanFile(file, { compiler });
      assert.equal(pinned.compilerValidated, true);
      assert.equal(pinned.semanticProfile, "compact-0.35.0-zkir2");
      assert.equal(scanFile(file, { compiler, compilerVersion: "0.35.0-rc.1" }).diagnostics[0].code, "compiler-profile-mismatch");
      assert.equal(validateWithCompiler(compiler, file, [], 30000, 3, version).valid, false);
    }
    // Missing input still carries the requested profile across the worker boundary.
    isolated = scanFileIsolated(resolve(directory, "missing.compact"), selected.options);
  });
  const result = await isolated!;
  assert.equal(result.status, "incomplete");
  assert.equal(result.semanticProfile, "compact-0.35.0-zkir2");
  assert.equal(result.diagnostics[0].code, "input-error");
  const complete = await scanFileIsolated(resolve("tests/corpus/informational/dead-code-corrected.compact"), { compilerVersion: version });
  assert.equal(complete.status, "complete");
  assert.equal(complete.semanticProfile, "compact-0.35.0-zkir2");
});
