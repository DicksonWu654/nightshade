import test, { TestContext } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { scanFile, scanFileIsolated } from "../src/index.js";
import { WorkerFailure, executionLimits, runNodeModule } from "../src/runtime/process.js";

function moduleFixture(context: TestContext, source: string): string {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-supervisor-test-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = resolve(directory, "worker.mjs");
  writeFileSync(path, source);
  return path;
}

test("isolated API preserves analysis findings and coverage", async () => {
  const path = resolve("tests/corpus/vulnerable/interprocedural.compact");
  const direct = scanFile(path);
  const isolated = await scanFileIsolated(path);
  assert.equal(isolated.status, direct.status);
  assert.deepEqual(isolated.findings, direct.findings);
  assert.deepEqual(isolated.coverage, direct.coverage);
  assert.ok(isolated.metrics.workerMs > 0);
  assert.ok(isolated.metrics.instructionNodes > isolated.metrics.cfgNodes);
});

test("[timing] worker timeout terminates rather than returning an empty success", async context => {
  const fixture = moduleFixture(context, "setInterval(() => {}, 1000);");
  await assert.rejects(runNodeModule(fixture, {}, { timeoutMs: 150 }), error => error instanceof WorkerFailure && error.code === "worker-timeout");
});

test("worker output is bounded independently of analysis budgets", async context => {
  const fixture = moduleFixture(context, 'console.log("x".repeat(2048));');
  await assert.rejects(runNodeModule(fixture, {}, { maxOutputBytes: 1024 }), error => error instanceof WorkerFailure && error.code === "worker-output-budget");
});

test("worker failures retain a bounded diagnostic instead of throwing through the scan API", async context => {
  const fixture = moduleFixture(context, 'console.error("synthetic worker failure"); process.exit(7);');
  await assert.rejects(runNodeModule(fixture, {}), error => error instanceof WorkerFailure && error.code === "worker-failed" && error.message.includes("synthetic worker failure"));
  const report = await scanFileIsolated(resolve("tests/fixtures/features/aggregates.compact"), {}, { maxOutputBytes: 1024 });
  assert.equal(report.status, "incomplete");
  assert.equal(report.diagnostics[0].code, "worker-output-budget");
  assert.deepEqual(report.coverage.completedEntries, []);
});

test("worker temporary output is removed by its supervisor", async context => {
  const fixture = moduleFixture(context, 'import {tmpdir} from "node:os"; import {writeFileSync} from "node:fs"; writeFileSync(tmpdir() + "/artifact", "temporary"); console.log(tmpdir());');
  const result = await runNodeModule(fixture, {});
  assert.equal(existsSync(result.stdout.trim()), false);
});

test("execution limits reject unknown, fractional, zero and unbounded settings", () => {
  for (const limits of [{ timeoutMs: 0 }, { timeoutMs: 600001 }, { heapMiB: 0 }, { heapMiB: 32.5 }, { maxOutputBytes: Number.MAX_SAFE_INTEGER }, { unknown: 1 }]) assert.throws(() => executionLimits(limits));
});

test("[timing] CLI timeout is machine-readable even with finding failure disabled", () => {
  const result = spawnSync(process.execPath, [resolve("dist/src/cli.js"), "tests/corpus/vulnerable/direct.compact", "--timeout-ms", "1", "--fail-on", "none", "--json"], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 2);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, "incomplete");
  assert.equal(report.diagnostics[0].code, "worker-timeout");
});

test("oversized worker metadata is rejected before launch", async context => {
  const fixture = moduleFixture(context, 'throw new Error("must not execute");');
  await assert.rejects(runNodeModule(fixture, { metadata: "x".repeat(1024 * 1024) }), error => error instanceof WorkerFailure && error.code === "worker-input-budget");
});
