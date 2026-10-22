import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Program, Dataflow, type AnalysisFacts } from "../src/index.js";
import { standardLibrary, zkir3Library } from "../src/semantic/stdlib.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles, semanticPaths } from "./helpers.js";

function compiler(file: string): void {
  if (!process.env.COMPACTC_TEST) return;
  const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
  assert.equal(result.valid, true, result.error);
}

test("stdlib sources match the exact 0.34.0 release and both parse through the owned parser", () => {
  for (const [source, hash] of [
    [standardLibrary, "166487c61232e4058f0a5cb1a2a154d5b926a574ba5bc24f5def905c2a938e52"],
    [zkir3Library, "e31907cb212ea1ddbae93148431fc51dc1f46d2182c88879e88fc3b12c47097b"],
  ] as const) {
    assert.equal(createHash("sha256").update(readFileSync(source.path)).digest("hex"), hash);
    assert.ok(source.ast.declarations.some(declaration => declaration.exported));
  }
  assert.equal(standardLibrary.ast.declarations.some(declaration => declaration.name === "PublicAddress"), false,
    "The later source checkout adds an alias absent from the pinned compiler release");
});

test("every declared ZKIR2 standard-library export resolves, including selected aliases", () => {
  const exports = standardLibrary.ast.declarations.filter(declaration => declaration.exported);
  const selection = exports.map(declaration => `${declaration.name} as imported_${declaration.name}`).join(",");
  withFiles({ "main.compact": `import {${selection}} from CompactStandardLibrary; export circuit entry(): [] {}` }, directory => {
    const file = resolve(directory, "main.compact");
    compiler(file);
    const program = new Program(file);
    for (const declaration of exports) assert.ok([...program.symbols.values()].some(symbol => symbol.name === declaration.name), declaration.name);
    assert.ok(program.files.has(standardLibrary.path));
    assert.deepEqual(program.activeSymbols().filter(symbol => symbol.kind === "circuit").map(symbol => symbol.name), ["entry"],
      "Dormant builtin helpers are not application declarations");
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
  });
});

test("parsed stdlib helpers and aggregate identities retain four-mode provenance across imports", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
module A {
  import {ShieldedCoinInfo, ShieldedSendResult as Packet, some} from CompactStandardLibrary;
  export circuit pack(value: ShieldedCoinInfo): Packet { return Packet {change: some<ShieldedCoinInfo>(value), sent: value}; }
}
module B {
  import {ShieldedSendResult, ShieldedCoinInfo} from CompactStandardLibrary;
  export circuit unpack(value: ShieldedSendResult): ShieldedCoinInfo { return value.change.value; }
}
import A; import B;
witness secret(): ShieldedCoinInfo;
export circuit entry(address: UserAddress): [ShieldedCoinInfo, UserAddress, Bytes<32>] {
  const value = secret();
  const result = unpack(pack(value));
  const zero = nativeToken();
  return disclose([result,address,zero]);
}` }, directory => {
    const file = resolve(directory, "main.compact");
    compiler(file);
    const program = new Program(file);
    let expected: AnalysisFacts | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const result = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
      assert.ok(result.items![0].fields!.nonce.flows.some(flow => flow.source.name === "secret"));
      assert.ok(result.items![1].fields!.bytes.flows.some(flow => flow.source.name === "address"));
      assert.equal(result.items![2].constant, "00".repeat(32));
      if (expected) assert.deepEqual(semanticPaths(facts), semanticPaths(expected));
      else expected = facts;
    }
  });
});

test("parsed token derivation preserves the existing cryptographic transfer override", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export circuit entry(domain: Bytes<32>, address: ContractAddress): Bytes<32> { return disclose(tokenType(domain,address)); }` }, directory => {
    const file = resolve(directory, "main.compact");
    compiler(file);
    const program = new Program(file);
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(facts.diagnostics, []);
    const value = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.equal(value.commitments?.[0].primitive, "persistentCommit");
    assert.deepEqual(new Set(value.flows.map(flow => flow.source.name)), new Set(["domain", "address"]));
    assert.ok(value.flows.every(flow => flow.form !== "raw"));
  });
});
