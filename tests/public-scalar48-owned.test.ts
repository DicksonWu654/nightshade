import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { scanFile, type CompilerVersion, type ZkirVersion } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

type Labels = {
  detector: string;
  compiler: CompilerVersion;
  zkirVersion: ZkirVersion;
  cases: { file: string; lines: number[] }[];
};
const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")) as Record<string, Labels>;

for (const group of ["publicScalarLegacy48", "publicScalarZkir348"]) {
  const labels = manifest[group];
  test(`exact owned scalar sources retain ${labels.compiler}/ZKIR${labels.zkirVersion} expectations`, () => {
    for (const item of labels.cases) {
      const file = resolve("tests/corpus", item.file);
      const compiler = labels.compiler === "0.31.1" ? process.env.COMPACTC_031_TEST : process.env.COMPACTC_TEST;
      if (compiler) {
        const result = validateWithCompiler(compiler, file, [], 30000, labels.zkirVersion, labels.compiler);
        assert.equal(result.valid, true, `${item.file}: ${result.error}`);
      }
      let ordinary: unknown;
      for (const experimentalCounterQueries of [false, true]) {
        const result = scanFile(file, { detectors: [labels.detector], compilerVersion: labels.compiler,
          zkirVersion: labels.zkirVersion, experimentalCounterQueries });
        assert.equal(result.status, "complete", `${item.file}: ${JSON.stringify(result.diagnostics)}`);
        assert.deepEqual(result.findings.map(finding => finding.location.line), item.lines, item.file);
        assert.ok(result.findings.every(finding => finding.severity === "info"));
        ordinary ??= result.findings;
        assert.deepEqual(result.findings, ordinary, item.file);
      }
    }
  });
}
