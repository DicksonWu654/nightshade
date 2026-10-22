import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, realpathSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, relative, resolve } from "node:path";
import { Dataflow, Program, detectors, resolvePolicies } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { AnalysisError } from "../src/model.js";
import { withFiles } from "./helpers.js";

function withAliasedRoot(source: string, check: (physical: string, alias: string) => void): void {
  withFiles({}, directory => {
    const parentAlias = resolve(directory, "alias");
    symlinkSync(directory, parentAlias, "dir");
    let generated: string | undefined;
    withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, fixture => {
      generated = fixture;
      assert.equal(fixture, realpathSync(fixture));
      assert.equal(dirname(fixture), directory);
      const physical = resolve(fixture, "main.compact");
      const alias = resolve(parentAlias, basename(fixture), "main.compact");
      assert.notEqual(alias, physical);
      assert.equal(realpathSync(alias), physical);
      if (process.env.COMPACTC_TEST) {
        const compiled = validateWithCompiler(process.env.COMPACTC_TEST, alias);
        assert.equal(compiled.valid, true, compiled.error);
      }
      check(physical, alias);
    }, parentAlias);
    assert.ok(generated);
    assert.equal(existsSync(generated), false);
    assert.equal(existsSync(parentAlias), true);
  });
}

test("symlinked temporary parents retain physical fixture paths and usable aliased policy roots", () => {
  withAliasedRoot(`
    export ledger allowed: Boolean; export ledger stored: Field;
    circuit guard(): [] { assert(allowed, "authorized"); }
    export circuit entry(secret: Field): Field { guard(); stored = disclose(secret); return stored; }
  `, (physical, alias) => {
    const policies = { authorization: [{ state: "stored", guard: "guard" }] };
    const canonical = new Program(physical);
    const expected = resolvePolicies(canonical, policies);
    const expectedFacts = new Dataflow(canonical).analyze();
    for (const root of [alias, relative(process.cwd(), alias)]) {
      const program = new Program(root);
      assert.equal(program.root, root, "the caller's path spelling remains part of the public Program input");
      assert.equal(program.files.has(root), false);
      assert.ok(program.files.has(physical));
      assert.deepEqual(resolvePolicies(program), { secrets: [], authorization: [], transitions: [], workBudgets: [] });
      assert.deepEqual(resolvePolicies(program, policies), expected);
      const facts = new Dataflow(program).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.paths, expectedFacts.paths);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(detectors.filter(detector => detector.defaultEnabled !== false && detector.id !== "openzeppelin-preconditions").flatMap(detector => detector.run(facts, expected)), []);
      assert.throws(() => resolvePolicies(program, { authorization: [{ state: "stored", guard: "missing" }] }), error => {
        assert.ok(error instanceof AnalysisError);
        assert.equal(error.diagnostic.code, "invalid-policy");
        assert.equal(error.diagnostic.location.file, physical);
        return true;
      });
    }
  });
});

test("aliased API roots report value exhaustion at the physical source without crashing", () => {
  withAliasedRoot("export circuit entry(values: Vector<8, Field>): Vector<8, Field> { return values; }", (physical, alias) => {
    for (const engine of ["instructions", "expressions"] as const) {
      const expected = new Dataflow(new Program(physical), 20000, 256, 4, engine).analyze();
      assert.ok(expected.diagnostics.some(diagnostic => diagnostic.code === "value-budget"));
      for (const root of [alias, relative(process.cwd(), alias)]) {
        const program = new Program(root);
        const facts = new Dataflow(program, 20000, 256, 4, engine).analyze();
        assert.equal(program.root, root);
        assert.deepEqual(facts.diagnostics, expected.diagnostics);
        assert.ok(facts.diagnostics.every(diagnostic => diagnostic.location.file === physical));
        assert.deepEqual(facts.completedEntries, []);
      }
    }
  });
});

const cachedRootSource = "export circuit entry(values: Vector<8, Field>): Vector<8, Field> { return values; }";

function assertCachedRootDiagnostics(program: Program, physical: string): void {
  assert.equal(program.rootSource, program.files.get(physical));
  assert.deepEqual(resolvePolicies(program), { secrets: [], authorization: [], transitions: [], workBudgets: [] });
  const diagnostic = (code: string) => (error: unknown): boolean => {
    assert.ok(error instanceof AnalysisError);
    assert.equal(error.diagnostic.code, code);
    assert.deepEqual(error.diagnostic.location, program.rootSource.ast.span);
    assert.equal(error.diagnostic.location.file, physical);
    return true;
  };
  assert.throws(() => resolvePolicies(program, { workBudgets: [{ circuit: "missing", maxUnits: 1 }] }), diagnostic("invalid-policy"));
  const nested = (leaf: string) => `${"Vector<1,".repeat(34)}${leaf}${">".repeat(34)}`;
  assert.throws(() => program.sameType(nested("Uint<8>"), nested("Uint<16>")), diagnostic("type-depth"));
  for (const engine of ["instructions", "expressions"] as const) {
    const complete = new Dataflow(program, 20000, 256, 50000, engine).analyze();
    assert.deepEqual(complete.diagnostics, []);
    assert.deepEqual(complete.completedEntries, program.entries);
    const incomplete = new Dataflow(program, 20000, 256, 4, engine).analyze();
    assert.ok(incomplete.diagnostics.some(diagnostic => diagnostic.code === "value-budget"));
    assert.ok(incomplete.diagnostics.every(diagnostic => diagnostic.location.file === physical));
    assert.deepEqual(incomplete.completedEntries, []);
  }
}

test("cached root diagnostics remain available after the original file is removed", () => {
  withAliasedRoot(cachedRootSource, (physical, alias) => {
    const program = new Program(alias);
    unlinkSync(physical);
    assert.equal(existsSync(alias), false);
    assertCachedRootDiagnostics(program, physical);
    assert.equal(program.root, alias);
  });
});

test("relative Program roots retain cached diagnostics after the working directory changes", () => {
  withAliasedRoot(cachedRootSource, (physical, alias) => {
    const originalDirectory = process.cwd();
    try {
      process.chdir(dirname(alias));
      const program = new Program("main.compact");
      process.chdir(dirname(dirname(physical)));
      assert.equal(existsSync("main.compact"), false);
      assertCachedRootDiagnostics(program, physical);
      assert.equal(program.root, "main.compact");
    } finally {
      process.chdir(originalDirectory);
    }
  });
});

test("retargeting a root symlink cannot replace its cached diagnostic source", () => {
  withAliasedRoot(cachedRootSource, (physical, _alias) => {
    const link = resolve(dirname(physical), "entry-link.compact");
    const replacement = resolve(dirname(physical), "replacement.compact");
    writeFileSync(replacement, "pragma language_version >= 0.26.0; export circuit replacement(): Field { return default<Field>; }");
    symlinkSync(physical, link);
    const program = new Program(link);
    unlinkSync(link);
    symlinkSync(replacement, link);
    assert.equal(realpathSync(link), replacement);
    assertCachedRootDiagnostics(program, physical);
    assert.equal(program.files.has(replacement), false);
    assert.equal(program.root, link);
  });
});
