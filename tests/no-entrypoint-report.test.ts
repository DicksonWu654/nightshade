import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { mergeResults, scanFile, scanFileIsolated } from "../src/index.js";
import { human, sarif } from "../src/reporting/index.js";
import { isNoEntrypointsNotice } from "../src/model.js";
import { withFiles } from "./helpers.js";

test("valid zero-entry roots are explicitly labeled through API, merge and reports", () => {
  withFiles({ "main.compact": "contract Peer { circuit read(value: Field): Field; }",
    "entry.compact": "constructor() {}", "bad.compact": "contract Peer { circuit read(): Missing; }" }, directory => {
    const file = resolve(directory, "main.compact");
    const zero = scanFile(file, { detectors: [] });
    assert.equal(zero.status, "complete");
    assert.deepEqual(zero.coverage.noEntrypointRoots, [file]);
    assert.equal(zero.diagnostics.length, 1);
    assert.equal(isNoEntrypointsNotice(zero.diagnostics[0], [file]), true);
    assert.equal(isNoEntrypointsNotice(zero.diagnostics[0], []), false);
    assert.equal(isNoEntrypointsNotice({ ...zero.diagnostics[0], message: "No entrypoints" }, [file]), false);
    assert.equal(isNoEntrypointsNotice({ ...zero.diagnostics[0], code: "analysis-error" }, [file]), false);
    assert.match(human(zero), /no entrypoints analyzed:/);
    assert.ok(JSON.stringify(sarif(zero)).includes('"noEntrypointRoots"'));
    const wire = sarif(zero) as { runs: { invocations: { toolExecutionNotifications: { level: string }[] }[] }[] };
    assert.equal(wire.runs[0].invocations[0].toolExecutionNotifications[0].level, "note");
    const entry = scanFile(resolve(directory, "entry.compact"), { detectors: [] });
    assert.equal(entry.status, "complete");
    assert.deepEqual(entry.coverage.noEntrypointRoots, []);
    const merged = mergeResults([zero, entry]);
    assert.deepEqual(merged.coverage.noEntrypointRoots, [file]);
    assert.equal(merged.status, "complete");
    assert.equal(merged.coverage.baselineStatus, "complete");
    const bad = scanFile(resolve(directory, "bad.compact"), { detectors: [] });
    assert.equal(bad.status, "incomplete");
    assert.deepEqual(bad.coverage.noEntrypointRoots, []);
  });
});

test("zero-entry worker transport preserves ordinary and Counter labels", async () => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-no-entry-"));
  try {
    const file = resolve(directory, "main.compact");
    writeFileSync(file, "contract Peer { circuit read(value: Field): Field; }");
    for (const experimentalCounterQueries of [false, true]) {
      const options = { detectors: ["spoofable-authorization"], experimentalCounterQueries };
      const direct = scanFile(file, options);
      const worker = await scanFileIsolated(file, options);
      assert.equal(worker.status, "complete", JSON.stringify(worker.diagnostics));
      assert.deepEqual(worker.coverage.noEntrypointRoots, [file]);
      assert.deepEqual(worker.coverage, JSON.parse(JSON.stringify(direct.coverage)));
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
