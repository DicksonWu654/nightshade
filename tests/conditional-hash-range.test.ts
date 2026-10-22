import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { conditionalHashRanges } from "../src/semantic/conditional-hash-range.js";
import { Program } from "../src/semantic/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function qualified(file: string): void {
  if (process.env.COMPACTC_TEST) {
    const result = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
    assert.equal(result.valid, true, result.error);
  }
}

function withProgram(source: string, check: (program: Program) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"); qualified(file);
    check(new Program(file));
  });
}

const header = "import CompactStandardLibrary; export ledger digest: Bytes<32>;";
const write = "digest = disclose(persistentHash<Uint<128>>((a - b) as Uint<128>));";
const entry = (body: string) => `${header}
export circuit probe(enabled: Boolean, other: Boolean, a: Uint<128>, b: Uint<128>): [] { ${body} }`;
const expect = (source: string, count: number) => withProgram(source, program => {
  const result = conditionalHashRanges(program);
  assert.equal(result.complete, true, result.complete ? undefined : result.reason);
  assert.equal(result.observations.length, count);
});

test("owned compiler-valid Counter seeds qualify only the conditional subtraction relationship", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-conditional-hash-${variant}.compact`);
    qualified(file);
    const program = new Program(file), result = conditionalHashRanges(program);
    assert.equal(result.complete, true);
    assert.equal(result.applicable, variant !== "lookalike");
    assert.equal(result.observations.length, variant === "positive" ? 1 : 0);
    if (variant !== "positive") continue;
    const site = result.observations[0];
    assert.equal(program.symbols.get(site.entry)!.name, "hashDifference");
    assert.equal(site.caller, site.entry);
    assert.equal(site.hash.line, 32); assert.equal(site.subtraction.line, 31);
    assert.equal(site.inputType, "Uint<128>"); assert.equal(site.slotBytes, 16);
    assert.equal(site.uintBits, 128); assert.equal(site.branches[0].truth, true);
    assert.equal(site.sourceUse.kind, "ledger-write");
    assert.deepEqual(result.candidateEntries, [site.entry]);
  }
});

test("local aliases, negation, Boolean comparisons and else preserve actual inactive polarity", () => {
  for (const [condition, safe] of [
    ["active", "active"], ["!active", "!active"], ["active == false", "!active"],
    ["false != active", "active"], ["!!active", "active"],
  ]) expect(entry(`
    const active = disclose(enabled); const alias = active;
    const first = ${safe} ? a : 0 as Uint<128>;
    const second = ${safe} ? b : 0 as Uint<128>;
    const savedFirst = first; const savedSecond = second;
    if (${condition.replace(/active/g, "alias")}) {
      const difference = (savedFirst - savedSecond) as Uint<128>;
      const copied = difference;
      const value = persistentHash<Uint<128>>(copied); const output = value;
      digest = disclose(output);
    }`), 0);
  expect(entry(`
    const safeA = enabled ? 0 as Uint<128> : a;
    const safeB = enabled ? 0 as Uint<128> : b;
    if (disclose(enabled)) { } else {
      digest = disclose(persistentHash<Uint<128>>((safeA - safeB) as Uint<128>));
    }`), 0);
  withProgram(entry(`if (!disclose(enabled)) { } else { ${write} }`), program => {
    const result = conditionalHashRanges(program);
    assert.equal(result.complete, true); assert.equal(result.observations.length, 1);
    assert.equal(result.observations[0].branches[0].truth, false);
  });
});

test("unrelated/opposite selections and partially sanitized nested branches retain review", () => {
  for (const choice of ["other", "!enabled"]) expect(entry(`
    const safeA = ${choice} ? a : 0 as Uint<128>;
    const safeB = ${choice} ? b : 0 as Uint<128>;
    if (disclose(enabled)) {
      digest = disclose(persistentHash<Uint<128>>((safeA - safeB) as Uint<128>));
    }`), 1);
  expect(entry(`const safeA = enabled ? a : 0 as Uint<128>;
    if (disclose(enabled)) { digest = disclose(persistentHash<Uint<128>>((safeA - b) as Uint<128>)); }`), 1);
  // Only selecting the subtrahend to zero is sufficient for these typed operands.
  expect(entry(`const safeB = enabled ? b : 0 as Uint<128>;
    if (disclose(enabled)) { digest = disclose(persistentHash<Uint<128>>((a - safeB) as Uint<128>)); }`), 0);
  withProgram(entry(`const safeA = other ? a : 0 as Uint<128>; const safeB = other ? b : 0 as Uint<128>;
    if (disclose(enabled)) { if (disclose(other)) {
      digest = disclose(persistentHash<Uint<128>>((safeA - safeB) as Uint<128>));
    } }`), program => {
    const result = conditionalHashRanges(program);
    assert.equal(result.complete, true); assert.equal(result.observations.length, 1);
    assert.equal(result.observations[0].branches.length, 1);
  });
});

test("only earlier unconditional assertions on the same immutable operands suppress", () => {
  for (const predicate of ["a >= b", "b <= a", "a > b", "!(a < b)", "a == b", "!(b != a)"])
    expect(entry(`const saved = a; assert(${predicate}, "global order"); if (disclose(enabled)) {
      digest = disclose(persistentHash<Uint<128>>((saved - b) as Uint<128>)); }`), 0);
  for (const body of [
    `if (disclose(enabled)) { assert(a >= b, "active only"); ${write} }`,
    `if (disclose(other)) { assert(a >= b, "unrelated"); } if (disclose(enabled)) { ${write} }`,
    `if (disclose(enabled)) { ${write} } assert(a >= b, "later");`,
    `assert(!(a >= b), "opposite order"); if (disclose(enabled)) { ${write} }`,
    `assert(b >= a, "opposite order"); if (disclose(enabled)) { ${write} }`,
  ]) expect(entry(body), 1);
  expect(entry(`assert(enabled, "always active"); if (disclose(enabled)) { ${write} }`), 0);
  expect(entry(`{ { assert(a >= b, "plain unconditional block"); } } if (disclose(enabled)) { ${write} }`), 0);
});

test("fresh ledger reads and changed controls do not inherit saved-snapshot invariants", () => {
  for (const saved of [true, false]) expect(`${header}
    export ledger leftValue: Uint<128>; export ledger rightValue: Uint<128>;
    export circuit probe(enabled: Boolean, nextLeft: Uint<128>, nextRight: Uint<128>): [] {
      const left = leftValue; const right = rightValue; const alias = left;
      assert(alias >= right, "saved order");
      leftValue = disclose(nextLeft); rightValue = disclose(nextRight);
      if (disclose(enabled)) { const a = ${saved ? "left" : "leftValue"}; const b = ${saved ? "right" : "rightValue"}; ${write} }
    }`, saved ? 0 : 1);
  for (const snapshot of [true, false]) expect(`${header} export ledger active: Boolean;
    export circuit probe(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] {
      const saved = active;
      const safeA = saved ? a : 0 as Uint<128>; const safeB = saved ? b : 0 as Uint<128>;
      active = disclose(enabled);
      if (${snapshot ? "saved" : "active"}) {
        digest = disclose(persistentHash<Uint<128>>((safeA - safeB) as Uint<128>));
      }
    }`, snapshot ? 0 : 1);
});

test("fresh witness invocations remain distinct while retained aliases preserve snapshots", () => {
  for (const saved of [true, false]) expect(`${header} witness amount(): Uint<128>;
    export circuit probe(enabled: Boolean): [] {
      const first = amount(); const second = amount(); const alias = first;
      assert(alias >= second, "saved order");
      if (disclose(enabled)) {
        const a = ${saved ? "first" : "amount()"}; const b = ${saved ? "second" : "amount()"}; ${write}
      }
    }`, saved ? 0 : 1);
});

test("canonical imported native hash and nominal Uint aliases retain identity; namesakes stay quiet", () => {
  expect(`import { persistentHash as hash } from CompactStandardLibrary;
    new type Quantity = Uint<128>; export ledger digest: Bytes<32>;
    export circuit probe(enabled: Boolean, a: Quantity, b: Quantity): [] {
      if (disclose(enabled)) { digest = disclose(hash<Quantity>((a - b) as Quantity)); }
    }`, 1);
  expect(`module Library { export circuit persistentHash<T>(input: T): Bytes<32> { return default<Bytes<32>>; } }
    import { persistentHash as pretend } from Library; export ledger digest: Bytes<32>;
    export circuit probe(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] {
      if (disclose(enabled)) { digest = disclose(pretend<Uint<128>>((a - b) as Uint<128>)); }
    }`, 0);
});

test("unconditional/direct inputs, safe zero differences and unrelated unused subtractions stay quiet", () => {
  for (const body of [
    write,
    `const change = (a - b) as Uint<128>; if (disclose(enabled)) { digest = disclose(persistentHash<Uint<128>>(change)); }`,
    `if (disclose(enabled)) { digest = disclose(persistentHash<Uint<128>>((a - a) as Uint<128>)); }`,
    `if (disclose(enabled)) { digest = disclose(persistentHash<Uint<128>>((a - 0) as Uint<128>)); }`,
    `if (disclose(enabled)) { const unused = (a - b) as Uint<128>; digest = disclose(persistentHash<Uint<128>>(a)); }`,
  ]) expect(entry(body), 0);
  expect(`${header} circuit unused(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] { if (disclose(enabled)) { ${write} } }
    export circuit probe(): [] { digest = default<Bytes<32>>; }`, 0);
});

test("unused hashes in a stateful entry remain candidates; pure backend retention is unavailable", () => {
  expect(`import CompactStandardLibrary; export ledger round: Counter;
    export circuit probe(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] {
      if (disclose(enabled)) { persistentHash<Uint<128>>((a - b) as Uint<128>); }
      round.increment(1);
    }`, 1);
  withProgram(`import CompactStandardLibrary;
    export circuit probe(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] {
      if (disclose(enabled)) { persistentHash<Uint<128>>((a - b) as Uint<128>); }
    }`, program => {
    const result = conditionalHashRanges(program);
    assert.equal(result.complete, false); assert.deepEqual(result.observations, []);
    if (!result.complete) assert.match(result.reason, /pure source entry/);
  });
});

test("root-wide enumeration follows helpers and withholds every observation on unsupported profiles", () => {
  withProgram(`${header}
    circuit helper(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] { if (disclose(enabled)) { ${write} } }
    export circuit first(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] { helper(enabled, a, b); }
    export circuit second(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] { helper(enabled, a, b); }`, program => {
    const result = conditionalHashRanges(program);
    assert.equal(result.complete, true); assert.equal(result.observations.length, 2);
    for (const site of result.observations) assert.equal(program.symbols.get(site.caller)!.name, "helper");
    assert.deepEqual(result.candidateEntries, program.entries);
    for (const [version, zkir] of [["0.31.1", 2], ["0.35.0", 2], ["0.34.0", 3]] as const) {
      const changed = new Program(program.root, [], program.sourceRoot, undefined, zkir, version);
      const unavailable = conditionalHashRanges(changed);
      assert.equal(unavailable.complete, false); assert.deepEqual(unavailable.observations, []);
      if (!unavailable.complete) assert.match(unavailable.reason, /qualified only/);
    }
  });
  withProgram(entry("digest = default<Bytes<32>>;"), program => {
    const changed = new Program(program.root, [], program.sourceRoot, undefined, 3, "0.34.0");
    assert.equal(conditionalHashRanges(changed).complete, true);
  });
  for (const forwarded of [false, true]) withProgram(`${header}
    circuit differenceHash(a: Uint<128>, b: Uint<128>): Bytes<32> {
      return persistentHash<Uint<128>>((a - b) as Uint<128>);
    }
    circuit forward(a: Uint<128>, b: Uint<128>): Bytes<32> { return differenceHash(a, b); }
    export circuit probe(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] {
      if (disclose(enabled)) { digest = disclose(${forwarded ? "forward" : "differenceHash"}(a, b)); }
    }`, program => {
    const result = conditionalHashRanges(program);
    assert.equal(result.complete, false); assert.deepEqual(result.observations, []);
    if (!result.complete) assert.match(result.reason, /caller\/callback control transport/);
  });
  for (const conditionalFirst of [false, true]) {
    const helper = `circuit differenceHash(a: Uint<128>, b: Uint<128>): Bytes<32> {
      return persistentHash<Uint<128>>((a - b) as Uint<128>);
    }`;
    const conditional = `circuit conditional(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] {
      if (disclose(enabled)) { digest = disclose(differenceHash(a, b)); }
    }`;
    const unconditional = `circuit unconditional(a: Uint<128>, b: Uint<128>): [] { digest = disclose(differenceHash(a, b)); }`;
    const calls = ["conditional(enabled, a, b);", "unconditional(a, b);"];
    if (!conditionalFirst) calls.reverse();
    withProgram(`${header} ${helper} ${conditional} ${unconditional}
      export circuit probe(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] { ${calls.join(" ")} }`, program => {
      const result = conditionalHashRanges(program);
      assert.equal(result.complete, false); assert.deepEqual(result.observations, []);
    });
    const entries = [
      "export circuit first(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] { conditional(enabled, a, b); }",
      "export circuit second(a: Uint<128>, b: Uint<128>): [] { unconditional(a, b); }",
    ];
    if (!conditionalFirst) entries.reverse();
    withProgram(`${header} ${helper} ${conditional} ${unconditional} ${entries.join("\n")}`, program => {
      const result = conditionalHashRanges(program);
      assert.equal(result.complete, false); assert.deepEqual(result.observations, []);
    });
  }
});

test("unqualified schemas/control and exhausted or corrupted enumeration withhold partial observations", () => {
  for (const extra of [
    "export circuit unsupported(enabled: Boolean, a: Uint<64>, b: Uint<64>): [] { if (disclose(enabled)) { digest = disclose(persistentHash<Uint<64>>((a - b) as Uint<64>)); } }",
    "struct Input { value: Uint<128> } export circuit unsupported(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] { if (disclose(enabled)) { digest = disclose(persistentHash<Input>(Input { value: (a - b) as Uint<128> })); } }",
    "export circuit unsupported(a: Uint<128>, b: Uint<128>): [] { if (false) { digest = disclose(persistentHash<Uint<128>>((a - b) as Uint<128>)); } }",
    "export circuit unsupported(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] { for (const i of 0..0) { if (disclose(enabled)) { digest = disclose(persistentHash<Uint<128>>((a - b) as Uint<128>)); } } }",
    "export circuit unsupported(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] { digest = disclose(enabled ? persistentHash<Uint<128>>((a - b) as Uint<128>) : default<Bytes<32>>); }",
    "export circuit unsupported(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] { const change = enabled ? (a - b) as Uint<128> : 0 as Uint<128>; digest = disclose(persistentHash<Uint<128>>(change)); }",
    "circuit callback(value: Uint<128>): Bytes<32> { if (disclose(value > 0)) { return persistentHash<Uint<128>>((value - 1) as Uint<128>); } return default<Bytes<32>>; } export circuit unsupported(a: Uint<128>): [] { map(callback, [a]); digest = default<Bytes<32>>; }",
  ]) withProgram(`${entry(`if (disclose(enabled)) { ${write} }`)}\n${extra}`, program => {
    const result = conditionalHashRanges(program);
    assert.equal(result.complete, false); assert.deepEqual(result.observations, []);
    assert.ok(result.candidateEntries.includes(program.entries[0]));
  });
  withProgram(entry(`if (disclose(enabled)) { ${write} }`), program => {
    const complete = conditionalHashRanges(program);
    assert.equal(complete.complete, true); assert.equal(complete.observations.length, 1);
    for (const allowance of [0, 1, 10, complete.work - 1, -1, NaN, Infinity]) {
      const result = conditionalHashRanges(program, allowance);
      assert.equal(result.complete, false); assert.deepEqual(result.observations, []);
    }
    assert.equal(conditionalHashRanges(program, complete.work).complete, true);
    program.symbols.delete("intrinsic::persistentHash");
    assert.equal(conditionalHashRanges(program).complete, false);
  });
});
