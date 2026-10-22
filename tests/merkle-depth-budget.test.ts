import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

test("legacy canonical 100-level Merkle proofs use the linear root summary", () => {
  withFiles({ "main.compact": `pragma language_version >= 0.20.0;
import CompactStandardLibrary;
witness path(): MerkleTreePath<100, Bytes<32>>;
export circuit entry(): MerkleTreeDigest { return disclose(merkleTreePathRoot<100, Bytes<32>>(path())); }
` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_030_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_030_TEST, file, [], 30000, 2, "0.30.0").valid, true);
    const report = scanFile(file, { compilerVersion: "0.30.0" });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.coverage.baselineStatus, "complete");
  });
});
