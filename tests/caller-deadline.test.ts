import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { scanFile } from "../src/index.js";
import { callerSuppliedDeadline } from "../src/detectors/caller-deadline.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const corpus = resolve("tests/corpus");
const cases = (JSON.parse(readFileSync(resolve(corpus, "manifest.json"), "utf8")).callerSuppliedDeadline as {
  cases: { file: string; sha256: string; lines: number[] }[];
}).cases;

test("caller time cannot satisfy a ledger notice without chain-time binding", () => {
  for (const entry of cases) {
    const file = resolve(corpus, entry.file);
    assert.equal(createHash("sha256").update(readFileSync(file)).digest("hex"), entry.sha256);
    if (process.env.COMPACTC_TEST) {
      const validated = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(validated.valid, true, validated.error);
    }
    const scan = scanFile(file, { detectors: [callerSuppliedDeadline.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(item => item.location.line), entry.lines, entry.file);
    const experimental = scanFile(file, { detectors: [callerSuppliedDeadline.id], experimentalCounterQueries: true });
    assert.equal(experimental.status, "complete", JSON.stringify(experimental.diagnostics));
    assert.deepEqual(experimental.findings.map(item => item.location.line), entry.lines, entry.file);
  }
});
