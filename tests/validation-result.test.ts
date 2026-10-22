import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { cachedSourceObservations, sourceObservations } from "../src/analysis/source-observations.js";
import { ignoredValidationResult as rule } from "../src/detectors/validation-result.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
export ledger count: Counter;
`;
const args = "msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint";
const call = "jubjubSchnorrVerify<1>(msg, sig, pk)";

function fixture(source: string, expected: string[], prefix = header, extras: Record<string,string> = {}): void {
  withFiles({ "main.compact": prefix + source, ...extras }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(findings.map(item => item.metadata.discardedBy).sort(), [...expected].sort());
      baseline ??= findings;
      assert.deepEqual(findings, baseline);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.deepEqual(result.findings, baseline);
    }
  });
}

test("discarded canonical verification reports the call, including unused resolved binding", () => {
  fixture(`export circuit discarded(${args}): [] { ${call}; count.increment(1); }
export circuit unused(${args}): [] { const valid = ${call}; count.increment(1); }`,
    ["expression-statement", "unused-binding"]);
});

test("assertions, aliases, rejecting branches, enforcing helpers and checker APIs preserve verification outcomes", () => {
  fixture(`circuit requireValid(valid: Boolean): [] { assert(valid, "signature"); }
circuit verify(${args}): Boolean { return ${call}; }
export circuit asserted(${args}): [] { assert(${call}, "signature"); count.increment(1); }
export circuit alias(${args}): [] { const valid = ${call}; const ok = valid; requireValid(ok); count.increment(1); }
export circuit rejectBefore(${args}): [] { const valid = ${call}; if (!disclose(valid)) { assert(false, "signature"); } count.increment(1); }
export circuit rejectAfter(${args}): [] { const valid = ${call}; count.increment(1); if (!disclose(valid)) { assert(false, "signature"); } }
export circuit split(${args}): [] { const valid = ${call}; if (disclose(valid)) { count.increment(1); } else { assert(false, "signature"); } }
export circuit throughHelper(${args}): [] { assert(verify(msg, sig, pk), "signature"); count.increment(1); }
export circuit checker(${args}): Boolean { return disclose(${call}); }`, []);
});

test("binding references follow resolved identity across sibling shadowing", () => {
  fixture(`export circuit entry(${args}): [] {
  const valid = ${call};
  { const valid = true; assert(valid, "unrelated"); }
  count.increment(1);
}`, ["unused-binding"]);
});

test("captured use of a verification result is conservatively retained", () => {
  fixture(`export circuit entry(${args}): [] {
  const valid = ${call};
  const results = map((ignored: Field): Boolean => valid, [0 as Field]);
  assert(results[0], "signature"); count.increment(1);
}`, []);
});

test("canonical imported aliases report, same-named application circuits are quiet", () => {
  fixture(`export circuit entry(${args}): [] { verify<1>(msg, sig, pk); count.increment(1); }`, ["expression-statement"],
    `import { jubjubSchnorrVerify as verify, JubjubSchnorrSignature, JubjubPoint, Counter } from CompactStandardLibrary;
export ledger count: Counter;
`);
  fixture(`circuit jubjubSchnorrVerify(value: Boolean): Boolean { return value; }
export circuit entry(value: Boolean): [] { jubjubSchnorrVerify(value); count.increment(1); }`, []);
});

test("statically dead verification and unreachable private helpers are quiet", () => {
  fixture(`circuit unused(${args}): [] { ${call}; }
export circuit entry(${args}): [] {
  if (false) { ${call}; }
  for (const i of 0..0) { ${call}; }
  count.increment(1);
}`, []);
});

test("skipped or optional logical rejection cannot hide later discarded verification", () => {
  fixture(`export circuit skipped(${args}): [] {
    false && (assert(false,"skipped"),true);
    true || (assert(false,"skipped"),false);
    ${call}; count.increment(1);
  }
  export circuit optional(flag: Boolean, ${args}): [] {
    flag && (assert(false,"optional"),true);
    ${call}; count.increment(1);
  }`, ["expression-statement", "expression-statement"]);
});

test("physical generic call sites deduplicate without losing source-equivalent specializations", () => {
  fixture(`circuit drop<#N>(msg: Vector<N, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  jubjubSchnorrVerify<N>(msg, sig, pk);
}
export circuit first(${args}): [] { drop<1>(msg, sig, pk); count.increment(1); }
export circuit second(msg: Vector<2, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] { drop<2>(msg, sig, pk); count.increment(1); }`,
    ["expression-statement"]);
});

test("source work exhaustion cannot certify absence of discarded validation", () => {
  withFiles({ "main.compact": header + `export circuit entry(${args}): [] { ${call}; count.increment(1); }` }, directory => {
    const observations = sourceObservations(new Program(resolve(directory, "main.compact")), 1, true);
    assert.equal(observations.complete, false);
    assert.deepEqual(observations.observations, []);
  });
});

test("independent validation work and cache cannot exhaust the ordinary informational source allowance", () => {
  withFiles({ "main.compact": header + `export circuit entry(${args}): [] { ${call}; count.increment(1); }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const ordinary = sourceObservations(program);
    assert.equal(ordinary.complete, true);
    assert.ok(ordinary.observations.every(item => item.kind !== rule.id));
    // At its measured required allowance the ordinary pass must stay complete,
    // even though separately selected validation work consumes more traversal.
    assert.equal(sourceObservations(program, ordinary.work).complete, true);
    assert.equal(sourceObservations(program, ordinary.work, true).complete, false);
    const cachedOrdinary = cachedSourceObservations(program);
    assert.deepEqual(cachedOrdinary, ordinary);
    const facts = new Dataflow(program).analyze();
    assert.equal(rule.run(facts).length, 1);
    assert.deepEqual(facts.diagnostics, []);
    assert.equal(cachedSourceObservations(program), cachedOrdinary);
    assert.deepEqual(sourceObservations(program), ordinary);
  });
});


test("transparent verifier helpers report caller discards across generics, disclosure and imported aliases",()=>{
  fixture(`circuit verify<#N>(msg: Vector<N, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): Boolean { return jubjubSchnorrVerify<N>(msg,sig,pk); }
circuit forward(${args}): Boolean { return disclose(verify<1>(msg,sig,pk)); }
import "Checker" prefix C_;
export circuit loose(${args}): [] { forward(msg,sig,pk); count.increment(1); }
export circuit unused(${args}): [] { const ok=C_verify(msg,sig,pk); count.increment(1); }
export circuit checked(${args}): [] { assert(forward(msg,sig,pk),"signature"); count.increment(1); }
export circuit checker(${args}): Boolean { return forward(msg,sig,pk); }
`,["expression-statement","unused-binding"],header,{"Checker.compact":`module Checker { import CompactStandardLibrary; export circuit verify(${args}): Boolean { return ${call}; } }`});
});

test("enforcing wrappers and custom same-named checkers are quiet when their results are discarded",()=>fixture(`
circuit enforcing(${args}): Boolean { assert(${call},"signature"); return true; }
module Fake { export circuit jubjubSchnorrVerify(): Boolean { return true; } }
import Fake prefix F_;
circuit custom(): Boolean { return F_jubjubSchnorrVerify(); }
export circuit safe(${args}): [] { enforcing(msg,sig,pk); custom(); count.increment(1); }
`,[]));

test("discarded local identity alias chains report the original verifier result", () => {
  fixture(`circuit checker(${args}): Boolean { return ${call}; }
export circuit direct(${args}): [] {
  const valid = ${call}; const alias = valid; const unused = alias;
  count.increment(1);
}
export circuit forwarded(${args}): [] {
  const valid = checker(msg,sig,pk); const alias = disclose(valid as Boolean);
  { const unused = alias; }
  count.increment(1);
}`, ["unused-alias-chain", "unused-alias-chain"]);
});

test("one terminal use preserves fan-out aliases, captures, returns and sibling identities", () => {
  fixture(`circuit consume(valid: Boolean): [] { assert(valid,"signature"); }
export circuit fanOut(${args}): [] {
  const valid = ${call}; const unused = valid; const live = valid;
  consume(live); count.increment(1);
}
export circuit captured(${args}): [] {
  const valid = ${call}; const alias = valid;
  const results = map((ignored: Field): Boolean => alias, [0 as Field]);
  assert(results[0],"signature"); count.increment(1);
}
export circuit returned(${args}): Boolean {
  const valid = ${call}; const alias = valid; return disclose(alias);
}
export circuit sibling(${args}): [] {
  const valid = ${call}; const alias = valid;
  { const alias = true; assert(alias,"unrelated"); }
  count.increment(1);
}`, ["unused-alias-chain"]);
});

test("non-alias computations and assignments conservatively retain a result", () => {
  fixture(`export ledger observed: Boolean;
export circuit computed(${args}): [] {
  const valid = ${call}; const alias = valid; const unused = !alias;
  count.increment(1);
}
export circuit published(${args}): [] {
  const valid = ${call}; const alias = valid; observed = disclose(alias);
  count.increment(1);
}`, []);
});

test("alias-only captures preserve outer results without suppressing local lambda discards", () => {
  fixture(`export circuit captured(${args}): [] {
  const valid = ${call}; const alias = valid;
  const result = map((x: Field): Boolean => {
    const unused = alias; return true;
  }, [0 as Field]);
  count.increment(1);
}
export circuit local(${args}): [] {
  const result = map((x: Field): Boolean => {
    const valid = jubjubSchnorrVerify<1>([x],sig,pk); const unused = valid;
    return true;
  }, [0 as Field]);
  count.increment(1);
}`, ["unused-alias-chain"]);
});

test("alias closure stays inside its source allowance and exhaustion cannot certify absence", () => {
  withFiles({ "main.compact": header + `export circuit entry(${args}): [] {
    const valid = ${call}; const alias = valid; const unused = alias; count.increment(1);
  }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const full = sourceObservations(program, 200000, true);
    assert.equal(full.complete, true);
    assert.equal(full.observations.filter(item => item.kind === rule.id).length, 1);
    assert.deepEqual(sourceObservations(program, full.work, true), full);
    const exhausted = sourceObservations(program, full.work - 1, true);
    assert.equal(exhausted.complete, false);
    assert.deepEqual(exhausted.observations, []);
  });
});
