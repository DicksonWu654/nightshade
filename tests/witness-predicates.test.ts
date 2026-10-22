import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { spoofableAuthorization } from "../src/detectors/authorization.js";
import { withFiles } from "./helpers.js";

function withProgram(source: string, check: (program: Program) => void): void {
  withFiles({ "main.compact": `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    check(new Program(file, [], directory));
  });
}

test("successful compound guards retain the evaluated right-hand predicate", () => {
  withProgram(`
export circuit conjunction(a: Boolean, b: Boolean): [] {
  assert(a && b, "both"); assert(!b, "contradiction");
}
export circuit disjunction(a: Boolean, b: Boolean): [] {
  assert(!a, "not first"); assert(a || b, "one"); assert(!b, "contradiction");
}
export circuit equality(a: Boolean, b: Field): [] {
  assert(a && b == (7 as Field), "both"); assert(b != (7 as Field), "contradiction");
}
export circuit negation(a: Boolean, b: Boolean): [] {
  assert(a && !b, "both"); assert(b, "contradiction");
}
circuit ordered(a: Boolean, b: Uint<8>): Boolean {
  return a && b < 7;
}
export circuit caller(a: Boolean, b: Uint<8>): [] {
  assert(ordered(a, b), "ordered"); assert(b == 8, "contradiction");
}`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.equal(facts.paths.length, 0, JSON.stringify({ engine, cached }));
    }
  });
});

const effectsProbe = `
export ledger owner: Bytes<32>;
export ledger authentication: Bytes<32>;
export ledger stored: Field;
witness identity(): Bytes<32>;
witness secret(): Bytes<32>;
circuit allowed(): Boolean { return identity() == owner; }
circuit mutate(next: Field): [] { stored = disclose(next); }
export circuit ignored(next: Field): [] { allowed(); mutate(next); }
export circuit late(next: Field): [] { mutate(next); assert(allowed(), "owner"); }
export circuit enforced(next: Field): [] { assert(allowed(), "owner"); mutate(next); }
export circuit alternate(next: Field): [] {
  assert(allowed(), "owner");
  assert(persistentHash<Bytes<32>>(secret()) == authentication, "secret");
  mutate(next);
}
export circuit selfEstablished(next: Field): [] {
  assert(allowed(), "owner");
  const supplied = secret();
  authentication = disclose(persistentHash<Bytes<32>>(supplied));
  assert(persistentHash<Bytes<32>>(supplied) == authentication, "self-established");
  mutate(next);
}
export circuit mixed(next: Field, secure: Boolean): [] {
  assert(allowed(), "owner");
  if (disclose(secure)) { assert(persistentHash<Bytes<32>>(secret()) == authentication, "secret"); }
  mutate(next);
}
export circuit sameSite(next: Field): [] {
  mutate(next);
  assert(allowed(), "owner");
  mutate(next);
}
export circuit optionalEarlier(flag: Boolean, next: Field): [] {
  if (disclose(flag)) { assert(allowed(), "owner"); mutate(next); }
  mutate(next);
}
export circuit forkedSource(flag: Boolean, next: Field): [] {
  if (disclose(flag)) { const unused = allowed(); }
  assert(allowed(), "required owner");
  mutate(next);
}`;

test("predicate/effect experiment preserves invocation sites, late checks and path-local alternate authentication", () => {
  withProgram(effectsProbe, program => {
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      const findings = spoofableAuthorization.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const entries = findings.map(finding => finding.metadata.entry).sort();
      assert.deepEqual(entries, ["enforced", "forkedSource", "late", "mixed", "optionalEarlier", "sameSite", "selfEstablished"]);
      assert.equal(findings.find(finding => finding.metadata.entry === "late")!.metadata.guardPosition, "after-effect");
      assert.deepEqual(findings.filter(finding => finding.metadata.entry === "sameSite").map(finding => finding.metadata.guardPosition).sort(), ["after-effect"]);
      assert.equal(findings.find(finding => finding.metadata.entry === "mixed")!.metadata.rawOnlyReaches, 1);
      const optional = findings.find(finding => finding.metadata.entry === "optionalEarlier")!;
      assert.equal((optional.metadata.effectCallSites as { line: number }[]).at(-1)!.line, 36, "only the optional call is guarded");
      const result = findings.map(({ fingerprint, metadata }) => ({ fingerprint, metadata })).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
      baseline ??= result;
      assert.deepEqual(result, baseline, JSON.stringify({ engine, cached }));
    }
  });
});

test("compound guards preserve feasible arms, including a skipped disjunction", () => {
  withProgram(`
export circuit conjunction(a: Boolean, b: Boolean): [] {
  assert(a && b, "both"); assert(b, "compatible");
}
export circuit disjunction(a: Boolean, b: Boolean): [] {
  assert(a || b, "either"); assert(!b, "first arm");
}
export circuit equality(a: Boolean, b: Field): [] {
  assert(a && b == (7 as Field), "both"); assert(b == (7 as Field), "compatible");
}
export circuit negation(a: Boolean, b: Boolean): [] {
  assert(a && !b, "both"); assert(!b, "compatible");
}
circuit ordered(a: Boolean, b: Uint<8>): Boolean {
  return a && b < 7;
}
export circuit caller(a: Boolean, b: Uint<8>): [] {
  assert(ordered(a, b), "ordered"); assert(b == 6, "compatible");
}`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(facts.paths.map(path => path.entry).sort(), [...program.entries].sort(), JSON.stringify({ engine, cached }));
    }
  });
});
