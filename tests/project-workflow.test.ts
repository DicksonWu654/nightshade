import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Ajv } from "ajv";
import { discoverProject, discoverProjectIsolated } from "../src/semantic/project.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const cli = resolve("dist/src/cli.js");
const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 20000, env: { ...process.env, COMPACT_PATH: "" } });

test("project discovery finds common layouts, omits module roots and follows installed imports", () => {
  const source = 'import "@owned/library/helper"; export circuit entry(): Field { return number(); }';
  withFiles({
    "contract/src/main.compact": source,
    "node_modules/@owned/library/helper.compact": 'module helper { export circuit number(): Field { return 7 as Field; } }',
    "contract/src/library.compact": 'module library { export circuit unused(): Field { return 3 as Field; } }',
    "compact/contracts/second/src/main.compact": 'export circuit second(): Field { return 2 as Field; }',
    "contract/src/managed/output/bad.compact": 'bad syntax',
    "build/bad.compact": 'bad syntax',
  }, root => {
    if (process.env.COMPACTC_TEST) for (const file of ["contract/src/main.compact", "compact/contracts/second/src/main.compact"]) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, resolve(root, file), [resolve(root, "node_modules"), root]);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const result = run(root, "--json");
    assert.equal(result.status, 0, result.stdout);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "complete"); assert.equal(report.entrypoints.length, 2);
    assert.deepEqual(report.selection.discovery.omittedLibraries, [resolve(root, "contract/src/library.compact")]);
    assert.ok(report.coverage.parsed.includes(resolve(root, "node_modules/@owned/library/helper.compact")));
    assert.equal(report.coverage.attempted.length, 2);
    assert.deepEqual(report.selection.discovery.inferredSearchPaths[resolve(root, "contract/src/main.compact")], [resolve(root, "node_modules"), root]);
    const validate = new Ajv({ strict: false }).compile(JSON.parse(readFileSync("docs/schema/report.schema.json", "utf8")));
    assert.equal(validate(report), true, JSON.stringify(validate.errors));
    // Explicit paths control import resolution instead of silently adding inference.
    const explicit = run(root, "--json", "--compact-path", resolve(root, "unavailable"));
    assert.equal(explicit.status, 2); assert.ok(JSON.parse(explicit.stdout).diagnostics.some((item: { code: string }) => item.code === "unresolved-import"));
  });
});

test("discovery preserves first failures and exclusions; module-only scans stay incomplete", () => {
  withFiles({ "src/bad.compact": 'export circuit broken(): [] { unknown(); }', "src/parse.compact": 'module broken { %% }',
    "lib/helper.compact": 'module helper { export circuit helper(): [] {} }', "skip/invalid.compact": 'bad syntax' }, root => {
    const discovery = discoverProject(root, ["skip/**"]);
    assert.equal(discovery.status, "complete"); assert.equal(discovery.files.length, 2);
    assert.deepEqual(discovery.excluded, [resolve(root, "skip/invalid.compact")]);
    const report = JSON.parse(run(root, "--exclude", "skip/**", "--json").stdout);
    assert.equal(report.status, "incomplete"); assert.equal(report.coverage.attempted.length, 2);
    assert.ok(report.diagnostics.some((item: { code: string }) => item.code === "parse-error"));
    assert.equal(run(resolve(root, "lib"), "--json").status, 2);
    const explicit = JSON.parse(run(resolve(root, "lib/helper.compact"), "--json").stdout);
    assert.equal(explicit.status, "complete");
    assert.deepEqual(explicit.coverage.noEntrypointRoots, [resolve(root, "lib/helper.compact")]);
    assert.deepEqual(explicit.diagnostics.map((item: { code: string }) => item.code), ["no-entrypoints-analyzed"]);
  });
});

test("nearest installed dependency directories retain package-local resolution", () => {
  withFiles({ "packages/first/contracts/main.compact": 'import "@owned/library/helper"; export circuit entry(): Field { return number(); }',
    "packages/first/node_modules/@owned/library/helper.compact": 'module helper { export circuit number(): Field { return 1 as Field; } }',
    "node_modules/@owned/library/helper.compact": 'module helper { export circuit number(): Field { return 2 as Field; } }' }, root => {
    const report = JSON.parse(run(root, "--json").stdout);
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.ok(report.coverage.parsed.includes(resolve(root, "packages/first/node_modules/@owned/library/helper.compact")));
    assert.ok(!report.coverage.parsed.includes(resolve(root, "node_modules/@owned/library/helper.compact")));
  });
});

test("discovery output exhaustion remains incomplete", async () => {
  const root = mkdtempSync(resolve(tmpdir(), "nightshade-discovery-"));
  try {
    for (let index = 0; index < 30; index++) writeFileSync(resolve(root, `library${index}.compact`), `module library${index} {}`);
    const result = await discoverProjectIsolated(root, [], { maxOutputBytes: 1024 });
    assert.equal(result.status, "incomplete"); assert.equal(result.diagnostics[0].code, "worker-output-budget");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("Action scan driver records findings/incompleteness and treats paths as data", { skip: process.platform === "win32" }, () => {
  const positive = readFileSync("tests/corpus/vulnerable/direct.compact", "utf8");
  for (const [source, code] of [[positive, "1"], ['export circuit entry(): [] { unknown(); }', "2"], ['export circuit entry(): [] {}', "0"]])
    withFiles({ "contract $(touch injected).compact": source, "output.txt": "", "nested/placeholder": "", "nightshade.json": '{"version":1}' }, root => {
      const result = spawnSync("bash", [resolve("scripts/action-scan.sh")], { cwd: resolve(root, "nested"), encoding: "utf8", timeout: 20000, env: {
        ...process.env, PATH: dirname(process.execPath) + ":" + process.env.PATH, COMPACT_PATH: "", RUNNER_TEMP: root, GITHUB_WORKSPACE: root,
        GITHUB_OUTPUT: resolve(root, "output.txt"), NIGHTSHADE_ACTION_PATH: resolve("."), NIGHTSHADE_INPUT_PATH: "contract $(touch injected).compact",
        NIGHTSHADE_CONFIG: "nightshade.json", NIGHTSHADE_COMPILER_VERSION: "", NIGHTSHADE_FAIL_ON: "info",
      } });
      assert.equal(result.status, 0, result.stderr);
      const output = Object.fromEntries(readFileSync(resolve(root, "output.txt"), "utf8").trim().split("\n").map(line => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
      assert.equal(output["exit-code"], code); assert.equal(existsSync(resolve(root, "injected")), false);
      const sarif = JSON.parse(readFileSync(output.sarif, "utf8")); assert.equal(sarif.version, "2.1.0");
      assert.equal(sarif.runs[0].invocations[0].executionSuccessful, code !== "2");
    });
});
