import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { expressions, type Expr, type Statement } from "../src/model.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

// Calls through a declared external-contract interface are typed from the
// declaration but their callee effects stay unmodeled. Every entry that reaches
// one (directly or through a helper) is incomplete with an explicit diagnostic;
// entries that never reach one are analyzed exactly as before.
const source = `import CompactStandardLibrary;
contract Callee {
  circuit getSquare(x: Field): Field;
  circuit notify(x: Uint<64>): [];
  circuit read(): Boolean;
}
export ledger callee: Callee;
export ledger total: Uint<64>;
export ledger copy: Callee;
constructor(c: Callee) { callee = disclose(c); }
circuit forward(peer: Callee, x: Uint<64>): [] { peer.notify(x); }
export circuit direct(x: Field): Field {
  const result = callee.getSquare(disclose(x));
  total = 1;
  return result;
}
export circuit transitive(peer: Callee, x: Uint<64>): [] {
  forward(disclose(peer), disclose(x));
  total = disclose(x);
}
export circuit branch(flag: Boolean, x: Uint<64>): [] {
  if (disclose(flag)) { callee.notify(disclose(x)); }
  total = disclose(x);
}
export circuit cellRead(): [] { copy = callee.read(); }
export circuit unrelated(x: Uint<64>): [] {
  assert(x < 10, "small");
  total = disclose(x);
}
`;

const short = (entry: string) => entry.replace(/.*::/, "");

function checked(text: string, inspect: (file: string) => void, valid = true): void {
  withFiles({ "main.compact": text }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, valid, compiled.error);
    }
    inspect(file);
  });
}

function statementExpressions(statement: Statement | undefined): Expr[] {
  if (!statement) return [];
  if (statement.kind === "block" || statement.kind === "bindings") return statement.body.flatMap(statementExpressions);
  if (statement.kind === "if") return [...expressions(statement.condition), ...statementExpressions(statement.then), ...statementExpressions(statement.otherwise)];
  if (statement.kind === "for") return [...(statement.sequence ? expressions(statement.sequence) : []), ...statementExpressions(statement.body)];
  return expressions(statement.expr);
}

test("contract interface calls are typed and ledger operations keep compiler precedence", () => {
  checked(source, file => {
    const program = new Program(file);
    const calls = [...program.functions.values()].flatMap(fn => statementExpressions(fn.declaration.body))
      .filter(expr => expr.kind === "member" && expr.value === "call");
    const byName = (name: string) => calls.filter(expr => expr.name === name);
    assert.deepEqual(byName("getSquare").map(expr => [expr.contractCall?.circuit, expr.inferredType, expr.ledgerRoot]), [["getSquare", "Field", undefined]]);
    assert.deepEqual(byName("notify").map(expr => [expr.contractCall?.circuit, expr.inferredType]), [["notify", "[]"], ["notify", "[]"]]);
    // A Cell ADT operation of the same name wins, as in compactc's elt-call lookup.
    const read = byName("read");
    assert.equal(read.length, 1);
    assert.equal(read[0].contractCall, undefined);
    assert.ok(read[0].ledgerRoot);
    assert.ok(read[0].inferredType?.endsWith("::Callee"));
  });
});

test("only entries that reach an unmodeled contract call are incomplete in both engines and cache modes", () => {
  checked(source, file => {
    const program = new Program(file);
    const callers = ["direct", "transitive", "branch"];
    const expected = program.entries.filter(entry => !callers.includes(short(entry)));
    assert.deepEqual(expected.map(short).sort(), ["cellRead", "constructor", "unrelated"]);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.completedEntries, expected, `${engine}/${cached}`);
      assert.deepEqual(facts.diagnostics.map(item => [item.code, item.location.line]).sort(),
        [["unsupported-contract-call", 11], ["unsupported-contract-call", 13], ["unsupported-contract-call", 22]], `${engine}/${cached}`);
      // No history continues across the external callee.
      assert.ok(!facts.paths.some(path => ["direct", "transitive"].includes(short(path.entry))));
      // The branch history that skips the call is still explored, but the entry stays incomplete.
      assert.ok(facts.paths.some(path => short(path.entry) === "branch"));
      const comparable = facts.paths.map(path => ({ entry: path.entry, writes: path.writes.length, sinks: path.sinks.length }));
      baseline ??= comparable;
      assert.deepEqual(comparable, baseline);
    }
    const result = scanFile(file);
    assert.equal(result.status, "incomplete");
    assert.equal(result.coverage.baselineStatus, "incomplete");
    assert.deepEqual(result.coverage.completedEntries.map(short).sort(), ["cellRead", "constructor", "unrelated"]);
    assert.ok(result.diagnostics.filter(item => !item.scope).every(item => item.code === "unsupported-contract-call"));
    // Structural rule absence is program-wide; no caller rule is ever complete.
    for (const rule of result.coverage.rules ?? []) if (callers.includes(short(rule.entry))) assert.notEqual(rule.status, "complete", rule.detectorId);
    assert.ok((result.coverage.rules ?? []).some(rule => short(rule.entry) === "unrelated" && rule.status === "complete"));
  });
});

test("contract interface argument types follow the declaration", () => {
  checked(source.replace("callee.getSquare(disclose(x))", "callee.getSquare(true)"), file => {
    const result = scanFile(file);
    assert.equal(result.status, "incomplete");
    assert.deepEqual(result.coverage.completedEntries, []);
    assert.equal(result.diagnostics[0].code, "call-type-mismatch");
  }, false);
});
