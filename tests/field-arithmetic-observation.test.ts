import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, type AbstractValue } from "../src/index.js";
import { integerEnvelope } from "../src/dataflow/integer-envelope.js";
import { assumeScalar, binaryValue, type ScalarConstraints } from "../src/dataflow/transfers.js";
import { FIELD_MODULUS } from "../src/semantic/types.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";
const observe = (program: Program, engine: "instructions" | "expressions", cached: boolean, steps = 40000) =>
  new Dataflow(program, steps, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all", false, false, false, true, false, false, false, true);
const source = `import CompactStandardLibrary;
export ledger balance: Field;
circuit subtract(left: Uint<64>, right: Uint<64>): Field { return (left as Field) - (right as Field); }
export circuit unchecked(amount: Field): [] { balance = disclose(balance - amount); }
export circuit guarded(amount: Uint<64>): [] { const previous = balance as Uint<64>; assert(previous >= amount, "balance"); balance = disclose(subtract(previous,amount)); }
export circuit lateGuard(amount: Uint<64>): [] { const previous = balance as Uint<64>; balance = disclose(subtract(previous,amount)); assert(previous >= amount, "balance"); }
export pure circuit literalWrap(): Field { return (0 as Field) - (1 as Field); }
export pure circuit intentionalResidue(): Field { return ${FIELD_MODULUS - 1n} as Field; }
circuit modular(left: Field, right: Field): Field { return left - right; }
export circuit reused(): [Field,Field] { const first = modular(0 as Field,1 as Field); return [first,modular(0 as Field,1 as Field)]; }
export circuit controlOnly(left: Uint<64>, right: Uint<64>): Boolean { return disclose(subtract(left,right) == (0 as Field)); }
export circuit hashOnly(left: Uint<64>, right: Uint<64>): Bytes<32> { return disclose(persistentHash<Field>(subtract(left,right))); }
export circuit reset(amount: Field): [] { balance = disclose(balance - amount); balance = 0 as Field; }
export circuit widened(value: Uint<8>): Field { return disclose(value as Field); }
export circuit derived(value: Uint<8>): Field { return disclose((value as Field) * (value as Field)); }
export circuit narrowed(value: Field): Field { const small = value as Uint<8>; return disclose(small as Field); }
export circuit snapshot(amount: Uint<8>): Field { const saved = balance as Uint<8>; balance = 9 as Field; return disclose((saved as Field) - (amount as Field)); }

`;

function fixture(check: (program: Program) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    check(new Program(file));
  });
}

test("exact Field observations distinguish modular reduction and preserve numeric-cast bounds", () => fixture(program => {
  let baseline: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false,true]) {
    const facts = observe(program, engine, cached).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
    assert.equal(facts.arithmeticEvidence, true);
    const entries = new Map(facts.paths.map(path => [program.symbols.get(path.entry)!.name, path]));
    const result = (entry: string) => entries.get(entry)!.sinks.at(-1)!.value;
    assert.equal(result("literalWrap").constant, result("intentionalResidue").constant);
    assert.ok(result("literalWrap").fieldArithmetic);
    assert.equal(result("intentionalResidue").fieldArithmetic, undefined);
    assert.deepEqual(result("literalWrap").fieldArithmetic!.operands.map(value => value.constant), ["0", "1"]);
    for (const entry of ["guarded", "lateGuard"]) {
      const value = result(entry).items?.[0] ?? result(entry);
      assert.deepEqual(value.fieldArithmetic!.operands.map(operand => operand.integerRange), Array(2).fill({ minimum: "0", maximum: String((1n << 64n) - 1n) }));
    }
    assert.deepEqual(result("reused").items!.map(value => value.fieldArithmetic!.operands.map(operand => operand.constant)), [["0","1"],["0","1"]]);
    assert.deepEqual(result("widened").integerRange, { minimum: "0", maximum: "255" });
    assert.deepEqual(result("narrowed").integerRange, { minimum: "0", maximum: "255" });
    assert.deepEqual(result("derived").integerRange, { minimum: "0", maximum: String(FIELD_MODULUS - 1n) }, "value-changing arithmetic must not retain its input envelope");
    assert.equal(result("snapshot").fieldArithmetic!.operands[0].constant, undefined, "later writes cannot rebind the saved operand");
    assert.deepEqual(result("snapshot").fieldArithmetic!.operands[0].integerRange, { minimum: "0", maximum: "255" });
    assert.equal(result("controlOnly").fieldArithmetic, undefined);
    assert.equal(result("hashOnly").fieldArithmetic, undefined);
    assert.equal(result("reset").fieldArithmetic, undefined);
    assert.ok(entries.get("reset")!.writes[0].after.fieldArithmetic, "real historical effects survive subsequent reset");
    if (cached && engine === "instructions") assert.ok(facts.metrics.summaryHits > 0, "exercise actual pure helper reuse");
    const observations = [...entries].map(([name,path]) => ({ name, sinks: path.sinks.map(sink => ({ kind: sink.kind, value: sink.value.fieldArithmetic, items: sink.value.items?.map(value => value.fieldArithmetic), constant: sink.value.constant })), predicates: path.predicates }));
    baseline ??= observations;
    assert.deepEqual(observations, baseline);
  }
}));

test("arithmetic evidence remains explicit and correlated requests use exact facts", () => fixture(program => {
  const ordinary = new Dataflow(program).analyze();
  assert.equal(ordinary.arithmeticEvidence, undefined);
  assert.ok(ordinary.paths.every(path => path.sinks.every(sink => !sink.value.fieldArithmetic && !sink.value.integerRange)));
  const facts = observe(program,"instructions",true).analyzeWithCorrelatedQueries([]);
  assert.deepEqual(facts.correlated, []);
  assert.deepEqual(facts.sources, []);
  assert.deepEqual(facts.exact.diagnostics, []);
  assert.equal(facts.exact.arithmeticEvidence, true);
  const entry = program.entries.find(entry => program.symbols.get(entry)!.name === "unchecked")!;
  const selected = observe(program,"instructions",true).selectSourceWitness(entry, false);
  assert.equal(selected.status, "selected");
  if (selected.status === "selected") assert.ok(selected.path.sinks[0].value.fieldArithmetic);
  const exhausted = observe(program,"instructions",true,1).analyze();
  assert.ok(exhausted.diagnostics.some(diagnostic => diagnostic.code.endsWith("budget")));
  assert.equal(exhausted.completedEntries.length, 0);
}));

test("integer envelopes follow successful cast domains and retained comparisons", () => fixture(program => {
  const state: ScalarConstraints = { known: new Map(), truths: new Map(), excluded: new Map(), aggregateExclusions: new Map(), aggregateExclusionLeaves: 0, aggregateExclusionsExhausted: false };
  const value: AbstractValue = { identity: "value", type: "Field", flows: [], ledger: new Set(), integerRange: { minimum: "0", maximum: "255" } };
  const constant: AbstractValue = { constant: "10", constantKind: "integer", type: "Uint<8>", flows: [], ledger: new Set() };
  const location = program.rootSource.ast.span;
  assert.equal(assumeScalar(binaryValue([value,constant],"<",location,"Uint<8>")!,true,state),true);
  assert.deepEqual(integerEnvelope("Field",value,state), { minimum: 0n, maximum: 9n });
  assert.deepEqual(integerEnvelope("Uint<3>",value,state), { minimum: 0n, maximum: 7n });
  assert.equal(integerEnvelope("Boolean",value,state), undefined);
}));


test("empty checked-narrowing intersections abort instead of retaining incompatible ranges", () => {
  withFiles({ "main.compact": `export circuit entry(value: Uint<16>): Field {
    assert(value >= (256 as Uint<16>), "large");
    const small = value as Uint<8>;
    return disclose((small as Field) - (1 as Field));
  }
  export circuit allowed(value: Uint<16>): Field {
    assert(value < (128 as Uint<16>), "small");
    const small = value as Uint<8>;
    return disclose((small as Field) - (1 as Field));
  }` }, directory => {
    const file = resolve(directory,"main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST,file);
      assert.equal(compiled.valid,true,compiled.error);
    }
    const program = new Program(file), entry = program.entries.find(id => program.symbols.get(id)!.name === "entry")!;
    for (const engine of ["instructions","expressions"] as const) for (const cached of [false,true]) for (const observed of [false,true]) {
      const flow = observed ? observe(program,engine,cached) : new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,true,"all");
      const facts = flow.analyze();
      assert.deepEqual(facts.diagnostics,[]);
      assert.deepEqual(facts.completedEntries,program.entries);
      assert.equal(facts.paths.some(path => path.entry === entry),false);
      assert.equal(facts.paths.length,1);
      if (observed) assert.deepEqual(facts.paths[0].sinks[0].value.fieldArithmetic!.operands[0].integerRange,{ minimum: "0", maximum: "127" });
    }
  });
});


test("repeated arithmetic aliases retain bounded numeric snapshots without recursively expanding origins", () => {
  withFiles({ "main.compact": `circuit square(value: Field, unused: Field): Field { return value * value; }
  export circuit entry(value: Field): Field {
    return disclose(fold(square,value,default<Vector<24,Field>>));
  }` }, directory => {
    const file = resolve(directory,"main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST,file);
      assert.equal(compiled.valid,true,compiled.error);
    }
    const program = new Program(file);
    for (const engine of ["instructions","expressions"] as const) for (const cached of [false,true]) {
      const facts = observe(program,engine,cached).analyze();
      assert.deepEqual(facts.diagnostics,[]);
      assert.deepEqual(facts.completedEntries,program.entries);
      assert.equal(facts.paths.length,1);
      const value = facts.paths[0].sinks[0].value;
      assert.equal(value.fieldArithmetic!.operator,"*");
      assert.ok(value.fieldArithmetic!.operands.every(operand => !operand.fieldArithmetic));
      assert.ok(Buffer.byteLength(JSON.stringify(value,(_,value) => value instanceof Set ? [...value] : value)) < 250000, "shared recurrence must not expand an exponential operand-origin tree");
      assert.ok(facts.metrics.abstractValues < 50000);
    }
  });
});
