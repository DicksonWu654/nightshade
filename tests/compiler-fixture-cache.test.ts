import assert from "node:assert/strict";
import test from "node:test";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fixtureCacheStats, validateWithCompiler } from "./compiler-fixtures.js";
import { validateWithCompiler as fresh } from "../src/compiler/index.js";
import { COMPILER_PROFILES } from "../src/semantic/profile.js";

// Owned copies of the real pinned toolchain: cache behavior never changes the
// source compiler, and accepted entries must agree with fresh compilation.
test("compiler fixture acceptance invalidates source, dependency, environment, profile and launcher changes", () => {
  const pinned = process.env.COMPACTC_TEST;
  if (!pinned) return;
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-cache-regression-"));
  const environment = { ...process.env };
  const source = resolve(directory, "inputs/main.compact");
  const compiler = resolve(directory, "toolchain/compactc");
  const valid = "export circuit entry(): Field { return 1 as Field; }";
  const invalid = "export circuit entry(): Field { return missing(); }";
  const stats = () => fixtureCacheStats();
  const compile = () => validateWithCompiler(compiler, source, [], 30000, 2, "0.34.0");
  const uncached = () => fresh(compiler, source, [], 30000, 2, "0.34.0");
  try {
    cpSync(resolve(pinned, ".."), resolve(directory, "toolchain"), { recursive: true });
    mkdirSync(resolve(directory, "inputs"));
    process.env.COMPACTC_TEST = compiler;
    process.env.NIGHTSHADE_FIXTURE_CACHE = resolve(directory, "cache");
    delete process.env.NIGHTSHADE_DISABLE_FIXTURE_CACHE;
    for (const key of ["BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "COMPACT_PATH"]) delete process.env[key];
    writeFileSync(source, valid);
    { const result = compile(); assert.equal(result.valid, true, result.error); }
    let before = stats();
    assert.deepEqual(compile(), uncached());
    assert.equal(stats().hits, before.hits + 1, "unchanged acceptance reused");

    const workerIdentity = process.env.NODE_TEST_WORKER_ID;
    const shellLevel = process.env.SHLVL;
    process.env.NODE_TEST_WORKER_ID = "owned-alternate-worker";
    process.env.SHLVL = "7";
    before = stats();
    assert.deepEqual(compile(), uncached(), "Node worker ordinal is not a compiler input");
    assert.equal(stats().hits, before.hits + 1);
    if (workerIdentity === undefined) delete process.env.NODE_TEST_WORKER_ID;
    else process.env.NODE_TEST_WORKER_ID = workerIdentity;
    if (shellLevel === undefined) delete process.env.SHLVL; else process.env.SHLVL = shellLevel;

    writeFileSync(source, invalid);
    before = stats();
    assert.equal(compile().valid, false);
    assert.equal(compile().valid, false);
    assert.equal(stats().hits, before.hits, "rejections are never cached");
    writeFileSync(source, 'import "library"; export circuit entry(): Field { return value(); }');
    const library = resolve(directory, "inputs/library.compact");
    writeFileSync(library, "module library { export circuit value(): Field { return 2 as Field; } }");
    { const result = compile(); assert.equal(result.valid, true, result.error); }
    before = stats();
    assert.deepEqual(compile(), uncached());
    assert.equal(stats().hits, before.hits + 1);
    writeFileSync(library, "module library { export circuit value(): Field { return missing(); } }");
    assert.equal(compile().valid, false, "import content invalidates acceptance");
    rmSync(library);

    mkdirSync(resolve(directory, "inputs/node_modules"));
    const hidden = resolve(directory, "inputs/node_modules/library.compact");
    writeFileSync(hidden, "module library { export circuit value(): Field { return 2 as Field; } }");
    writeFileSync(source, 'import "node_modules/library"; export circuit entry(): Field { return value(); }');
    before = stats();
    { const result = compile(); assert.equal(result.valid, true, result.error); }
    { const result = compile(); assert.equal(result.valid, true, result.error); }
    assert.equal(stats().hits, before.hits, "unhashed dependencies bypass cache");
    writeFileSync(hidden, "module library { export circuit value(): Field { return missing(); } }");
    assert.equal(compile().valid, false);
    rmSync(hidden);
    const firstTarget = resolve(directory, "inputs/target-a.compact");
    const secondTarget = resolve(directory, "inputs/target-b.compact");
    writeFileSync(firstTarget, "module library { export circuit value(): Field { return 2 as Field; } }");
    writeFileSync(secondTarget, "module library { export circuit value(): Boolean { return true; } }");
    symlinkSync(firstTarget, hidden);
    before = stats();
    assert.equal(compile().valid, true);
    assert.equal(compile().valid, true);
    assert.equal(stats().hits, before.hits, "skipped-directory aliases cannot borrow another file's hash");
    unlinkSync(hidden); symlinkSync(secondTarget, hidden);
    assert.equal(compile().valid, false, "retargeting a dependency alias must get fresh validation");
    rmSync(firstTarget); rmSync(secondTarget);
    rmSync(resolve(directory, "inputs/node_modules"), { recursive: true });
    writeFileSync(source, valid);
    { const result = compile(); assert.equal(result.valid, true, result.error); }

    const first = resolve(directory, "path-a"), second = resolve(directory, "path-b");
    mkdirSync(first); mkdirSync(second);
    writeFileSync(resolve(second, "library.compact"), "module library { export circuit value(): Field { return 2 as Field; } }");
    writeFileSync(source, 'import "library"; export circuit entry(): Field { return value(); }');
    assert.equal(validateWithCompiler(compiler, source, [first, second]).valid, true);
    process.env.COMPACT_PATH = second;
    assert.equal(validateWithCompiler(compiler, source, [first]).valid, false, "explicit search paths override COMPACT_PATH");
    delete process.env.COMPACT_PATH;
    writeFileSync(source, valid);

    const path = process.env.PATH;
    mkdirSync(resolve(directory, "empty-path"));
    process.env.PATH = resolve(directory, "empty-path");
    assert.equal(compile().valid, false, "launcher PATH is part of acceptance");
    process.env.PATH = path;
    process.env.PATH = `${resolve(directory, "empty-path")}:${path}`;
    assert.equal(compile().valid, true);
    writeFileSync(resolve(directory, "empty-path/bash"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
    assert.equal(compile().valid, false, "same PATH with changed command resolution invalidates acceptance");
    process.env.PATH = path;
    rmSync(resolve(directory, "empty-path/bash"));
    writeFileSync(resolve(directory, "toolchain/dirname"), "#!/bin/sh\nprintf 'ignored'\n", { mode: 0o755 });
    process.env.PATH = `${resolve(directory, "empty-path")}:${path}`;
    assert.equal(compile().valid, true, "dirname runs before launcher prepends its toolchain directory");
    writeFileSync(resolve(directory, "empty-path/dirname"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
    assert.equal(compile().valid, false, "actual dirname resolution invalidates acceptance");
    process.env.PATH = path;
    rmSync(resolve(directory, "toolchain/dirname"));
    const marker = resolve(directory, "command-stop");
    writeFileSync(resolve(directory, "empty-path/bash"), `#!/bin/sh\nif [ -e '${marker}' ]; then exit 1; fi\nexec /bin/bash "$@"\n`, { mode: 0o755 });
    rmSync(resolve(directory, "empty-path/dirname"));
    process.env.PATH = `${resolve(directory, "empty-path")}:${path}`;
    before = stats();
    assert.equal(compile().valid, true);
    assert.equal(compile().valid, true);
    assert.equal(stats().hits, before.hits, "custom command closures are never cached");
    writeFileSync(marker, "owned marker");
    assert.equal(compile().valid, false, "custom interpreter external dependencies stay fresh");
    process.env.PATH = path;
    const bashEnv = resolve(directory, "bash-env");
    writeFileSync(bashEnv, "exit 1\n");
    process.env.BASH_ENV = bashEnv;
    before = stats();
    assert.equal(compile().valid, false);
    assert.equal(stats().hits, before.hits);
    delete process.env.BASH_ENV;

    const profile = COMPILER_PROFILES["0.34.0"] as { languageVersion: string };
    const language = profile.languageVersion;
    try {
      profile.languageVersion = "99.99.99";
      assert.equal(compile().valid, false, "changed profile cannot reuse acceptance");
    } finally { profile.languageVersion = language; }

    chmodSync(compiler, 0o644);
    assert.equal(compile().valid, false, "launcher execution mode invalidates acceptance");
    chmodSync(compiler, 0o755);
    { const result = compile(); assert.equal(result.valid, true, result.error); }
    mkdirSync(resolve(directory, "alias"));
    const alias = resolve(directory, "alias/compactc");
    symlinkSync(compiler, alias);
    process.env.COMPACTC_TEST = alias;
    before = stats();
    assert.equal(validateWithCompiler(alias, source).valid, false);
    assert.equal(stats().hits, before.hits, "symlink launcher with different $0 is not cached");
    process.env.COMPACTC_TEST = compiler;

    for (const name of readdirSync(resolve(directory, "cache"))) {
      const file = resolve(directory, "cache", name);
      const entry = JSON.parse(readFileSync(file, "utf8"));
      entry.result.languageVersion = "incorrect";
      writeFileSync(file, JSON.stringify(entry));
    }
    before = stats();
    assert.deepEqual(compile(), uncached());
    assert.equal(stats().hits, before.hits, "corrupt profile identity is rejected");
    process.env.NIGHTSHADE_FIXTURE_CACHE = resolve(directory, "not-a-directory");
    writeFileSync(process.env.NIGHTSHADE_FIXTURE_CACHE, "owned");
    assert.equal(compile().valid, true, "cache I/O cannot weaken acceptance assertions");
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in environment)) delete process.env[key];
    Object.assign(process.env, environment);
    rmSync(directory, { recursive: true, force: true });
  }
});
