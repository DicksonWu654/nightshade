import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const compiler = process.env.COMPACTC_031_TEST;
function checked(name: string, body: string, inspect: (file: string) => void = file => {
  const report = scanFile(file, { compilerVersion: "0.31.1", detectors: [] });
  assert.equal(report.status, "complete", `${name}: ${JSON.stringify(report.diagnostics)}`);
}) {
  withFiles({ "main.compact": `pragma language_version 0.23; import CompactStandardLibrary; ${body}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (compiler) assert.equal(validateWithCompiler(compiler, file, [], 30000, 2, "0.31.1").valid, true, name);
    inspect(file);
  });
}

test("owned 0.31 protocol regressions remain compiler-valid and complete", () => {
  checked("verifiable credentials composed Opaque root", `struct Signature { key: JubjubPoint; scalar: Field; }
export circuit credentialRoot(value: Signature): Bytes<32> { return persistentHash<Signature>(value); }`);
  checked("credential entrypoint fanout", `export circuit issue(a: Bytes<32>): Bytes<32> { return persistentHash<Bytes<32>>(a); }
export circuit verify(a: Bytes<32>): Boolean { return a == a; }
export circuit revoke(a: Bytes<32>): Bytes<32> { return persistentHash<Bytes<32>>(a); }`);
  checked("Credential field field recomposition", `export circuit setVerificationMethod(q: Field, r: Field): Boolean { const joined = (8 as Field) * q + r; assert(joined == joined, "bound"); return true; }`, file => {
    const report = scanFile(file, { compilerVersion: "0.31.1", detectors: ["field-recomposition-range-review"] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
  });
  checked("Composed credential language-compatible root", `export circuit rwaCredential(subject: Bytes<32>): Bytes<32> { return persistentHash<Bytes<32>>(subject); }
export circuit identityCredential(subject: Bytes<32>): Boolean { return subject == subject; }`);
  checked("private-order corrected witness disclosure", `witness order(): Bytes<32>;
export circuit verifyOrder(): Bytes<32> { const value = order(); return disclose(value); }`);
  checked("Merkle proof selected-rule root", `witness path(): MerkleTreePath<10, Bytes<32>>;
export circuit proveStanding(): [] { const proof = path(); const root = merkleTreePathRoot<10, Bytes<32>>(proof); assert(root.field == root.field, "member"); }`, file => {
    const report = scanFile(file, { compilerVersion: "0.31.1", detectors: ["low-entropy-hash-disclosure"] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
  });
});
