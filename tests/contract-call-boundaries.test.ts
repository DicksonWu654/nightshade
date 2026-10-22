import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { expressions } from "../src/model.js";
import { withFiles, semanticPaths } from "./helpers.js";

test("external signatures resolve imported aliases in their defining scope", () => {
  withFiles({
    "peer.compact": `module peer { type Payload = Field;
contract Peer { circuit consume(value: Payload): Payload; }
export { Peer }; }`,
    "main.compact": `import { Peer as Remote } from "peer";
type Payload = Boolean;
export circuit entry(peer: Remote): Field { return peer.consume(1 as Field); }`,
  }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const entry = program.functions.get(program.entries[0])!;
    const returned = entry.declaration.body!;
    assert.equal(returned.kind, "block");
    if (returned.kind !== "block") return;
    const statement = returned.body[0];
    assert.equal(statement.kind, "return");
    if (statement.kind !== "return") return;
    const call = expressions(statement.expr).find(expr => expr.contractCall);
    assert.ok(call);
    assert.equal(call.inferredType, "Field");
    assert.equal(program.symbols.get(call.contractCall!.contract)?.name, "Peer");
    assert.equal(program.mayAbortExpression(call), true);
    let baseline: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.completedEntries, []);
      assert.deepEqual(facts.paths, []);
      assert.deepEqual(facts.diagnostics.map(issue => issue.code), ["unsupported-contract-call"]);
      const current = semanticPaths(facts);
      baseline ??= current;
      assert.deepEqual(current, baseline);
    }
  });
});

for (const [signature, call, code] of [
  ["circuit run(x: Field): Field;", "peer.run()", "call-arity"],
  ["circuit run(x: Field): Field;", "peer.run(1 as Field, 2 as Field)", "call-arity"],
  ["circuit run(x: Field): Field;", "peer.absent(1 as Field)", "unsupported-contract-call"],
  ["circuit run(x: Field): Field; circuit run(x: Boolean): Field;", "peer.run(1 as Field)", "unsupported-contract-call"],
] as const) test(`external interface rejects ${code}: ${call}, ${signature}`, () => {
  withFiles({ "main.compact": `contract Peer { ${signature} }
export circuit entry(peer: Peer): Field { return ${call}; }` }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.equal(result.status, "incomplete");
    assert.deepEqual(result.coverage.completedEntries, []);
    assert.equal(result.diagnostics[0]?.code, code);
  });
});

for (const [signature, code] of [
  ["circuit unused(value: Missing): Field;", "unresolved-type"],
  ["circuit unused(value: Field): Missing;", "unresolved-type"],
  ["circuit unused(value: Counter): [];", "ledger-type-context"],
  ["circuit unused(): Counter;", "ledger-type-context"],
  ["circuit unused(value: Field, value: Field): [];", "duplicate-symbol"],
] as const) test(`dormant contract signature rejects ${code}: ${signature}`, () => {
  withFiles({ "main.compact": `import CompactStandardLibrary; contract Peer { ${signature} }` }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, code);
    assert.deepEqual(result.coverage.noEntrypointRoots, []);
  });
});
