import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { detectFieldArithmetic, fieldArithmeticWraparound as rule } from "../src/detectors/field-arithmetic.js";
import { arithmeticTargets } from "../src/semantic/arithmetic-targets.js";
import { FIELD_MODULUS } from "../src/semantic/types.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const observe = (program: Program, engine: "instructions" | "expressions", cached: boolean) =>
  new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,true,"all",false,false,false,true,false,false,false,true);
const source = `import CompactStandardLibrary;
export ledger balance: Field;
export ledger balances: Map<Uint<8>,Field>;
circuit subtract(left: Uint<64>, right: Uint<64>): Field { return (left as Field)-(right as Field); }
export circuit implicit(left: Field,right: Uint<8>): Field { return disclose(left-right); }
export circuit implicitGuarded(left: Field,right: Uint<8>): Field { const previous = left as Uint<8>; assert(previous >= right,"bounds"); return disclose(left-right); }
export circuit unchecked(left: Uint<64>, right: Uint<64>): Field { return disclose(subtract(left,right)); }
export circuit before(left: Uint<64>, right: Uint<64>): Field { assert(left >= right,"bounds"); return disclose(subtract(left,right)); }
export circuit after(left: Uint<64>, right: Uint<64>): [] { balance = disclose(subtract(left,right)); assert(left >= right,"bounds"); }
export circuit reversed(left: Uint<64>, right: Uint<64>): Field { assert(right <= left,"bounds"); return disclose(subtract(left,right)); }
export circuit unrelated(left: Uint<64>, right: Uint<64>, other: Uint<64>): Field { assert(other >= right,"unrelated"); return disclose(subtract(left,right)); }
export circuit checked(left: Uint<64>, right: Uint<64>): Field { return disclose((left-right) as Field); }
export circuit alias(left: Uint<64>, right: Uint<64>, other: Uint<64>): Field { const result = subtract(left,right); assert(left == other,"alias"); assert(other >= right,"bounds"); return disclose(result); }
export circuit same(left: Uint<64>): Field { return disclose(subtract(left,left)); }
export circuit branch(left: Uint<64>, right: Uint<64>): Field { if (disclose(left >= right)) { return disclose(subtract(left,right)); } else { return 0 as Field; } }
export circuit saved(amount: Uint<8>): Field { const previous = balance as Uint<8>; balance = 9 as Field; assert(previous >= amount,"saved"); return disclose((previous as Field)-(amount as Field)); }
export circuit replaced(amount: Uint<8>): Field { const previous = balance as Uint<8>; balance = 9 as Field; assert((balance as Uint<8>) >= amount,"new"); return disclose((previous as Field)-(amount as Field)); }
export circuit lookup(first: Uint<8>, second: Uint<8>, amount: Uint<8>): Field { const a = balances.lookup(disclose(first)) as Uint<8>; const b = balances.lookup(disclose(second)) as Uint<8>; assert(a >= amount,"first"); return disclose((b as Field)-(amount as Field)); }
export circuit endpoint(value: Field, bit: Uint<1>): Field { assert(value != (${FIELD_MODULUS-1n} as Field),"endpoint"); return disclose(value + (bit as Field)); }
export circuit endpointMissing(value: Field, bit: Uint<1>): Field { return disclose(value + (bit as Field)); }
export circuit endpointAlias(value: Field, other: Field, bit: Uint<1>): Field { assert(value == other,"alias"); assert(other != (${FIELD_MODULUS-1n} as Field),"endpoint"); return disclose(value + (bit as Field)); }
export circuit castSub(left: Uint<8>, right: Uint<8>): Uint<8> { return disclose(((left as Field)-(right as Field)) as Uint<8>); }
export circuit castAdd(value: Field, bit: Uint<1>): Uint<8> { return disclose((value + (bit as Field)) as Uint<8>); }
export circuit safeMultiply(left: Uint<8>, right: Uint<8>): Field { return disclose((left as Field)*(right as Field)); }
export circuit multiply(left: Uint<128>, right: Uint<128>): Field { return disclose((left as Field)*(right as Field)); }
export circuit mustWrap(left: Uint<8>, right: Uint<8>): Field { assert(left == (0 as Uint<8>),"zero"); assert(right > (0 as Uint<8>),"positive"); return disclose((left as Field)-(right as Field)); }
export pure circuit literals(): Field { return ((0 as Uint<8>) as Field)-((1 as Uint<8>) as Field); }
export circuit modular(left: Field, right: Field): Field { return disclose(left-right); }
export circuit control(left: Uint<64>, right: Uint<64>): Boolean { return disclose(subtract(left,right) == (0 as Field)); }
export circuit hashed(left: Uint<64>, right: Uint<64>): Bytes<32> { return disclose(persistentHash<Field>(subtract(left,right))); }
export circuit reset(left: Uint<64>, right: Uint<64>): [] { balance = disclose(subtract(left,right)); balance = 0 as Field; }
export circuit rejected(left: Uint<64>, right: Uint<64>): [] { balance = disclose(subtract(left,right)); assert(false,"revert"); }
`;

function fixture(text: string, check: (program: Program) => void): void {
  withFiles({"main.compact":text}, directory => {
    const file = resolve(directory,"main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST,file);
      assert.equal(compiled.valid,true,compiled.error);
    }
    check(new Program(file));
  });
}

test("Field quantity warnings preserve same-operand guards, endpoints, atomic writes and cast rejection across engines/caches", () => fixture(source,program => {
  let baseline: unknown;
  const expected = ["castAdd","endpointMissing","implicit","lookup","multiply","mustWrap","replaced","reset","unchecked","unrelated"];
  for (const engine of ["instructions","expressions"] as const) for (const cached of [false,true]) {
    const facts = observe(program,engine,cached).analyze();
    assert.deepEqual(facts.diagnostics,[]);
    assert.deepEqual(facts.completedEntries,program.entries);
    const findings = rule.run(facts);
    assert.deepEqual(facts.diagnostics,[]);
    assert.deepEqual(findings.map(finding => finding.metadata.entry).sort(),expected);
    assert.equal(findings.find(finding => finding.metadata.entry === "mustWrap")!.confidence,"high");
    assert.equal(findings.find(finding => finding.metadata.entry === "mustWrap")!.metadata.wrap,"always-wrap");
    assert.ok(findings.every(finding => finding.metadata.pathFeasibility === "not-proven"));
    const normalized = findings.map(finding => ({ entry: finding.metadata.entry, fingerprint: finding.fingerprint, wrap: finding.metadata.wrap, operands: finding.metadata.operandBounds, effects: finding.metadata.effects })).sort((a,b) => String(a.entry).localeCompare(String(b.entry)));
    if (baseline) assert.deepEqual(normalized,baseline); else baseline = normalized;
  }
  const scan = scanFile(program.root,{detectors:[rule.id]});
  assert.equal(scan.status,"complete",JSON.stringify(scan.diagnostics));
  assert.deepEqual(scan.findings.filter(finding => finding.detectorId === rule.id).map(finding => finding.metadata.entry).sort(),expected);
  assert.equal(rule.defaultEnabled,false,"natural Ecdh masking is a retained intent-dependent false-positive shape");
  assert.ok(scanFile(program.root).findings.every(finding => finding.detectorId !== rule.id));
}));

test("shared arithmetic sites group effects without borrowing a guard from another invocation or history", () => fixture(`import CompactStandardLibrary;
export ledger a: Field;
export ledger b: Field;
circuit sub(left: Uint<8>,right: Uint<8>): Field { return (left as Field)-(right as Field); }
export circuit entry(left: Uint<8>,right: Uint<8>,other: Uint<8>): [] { assert(left >= right,"first"); a = disclose(sub(left,right)); b = disclose(sub(other,right)); a = disclose(sub(other,right)); }
export circuit paths(left: Uint<8>,right: Uint<8>,choice: Boolean): Field { if (disclose(choice)) { assert(left >= right,"some"); } return disclose(sub(left,right)); }
`,program => {
  for (const engine of ["instructions","expressions"] as const) for (const cached of [false,true]) {
    const facts = observe(program,engine,cached).analyze();
    const findings = rule.run(facts);
    assert.deepEqual(facts.diagnostics,[]);
    assert.equal(findings.length,2);
    const entry = findings.find(finding => finding.metadata.entry === "entry")!;
    assert.equal((entry.metadata.effects as unknown[]).length,2);
  }
}));

test("quantity observation cannot silently use compressed, missing or exhausted evidence", () => fixture(`export circuit entry(left: Uint<8>,right: Uint<8>): Field { return disclose((left as Field)-(right as Field)); }`,program => {
  assert.equal(arithmeticTargets(program).applicable,true);
  assert.equal(arithmeticTargets(program,1).complete,false);
  const ordinary = new Dataflow(program).analyze();
  assert.deepEqual(rule.run(ordinary),[]);
  assert.ok(ordinary.diagnostics.some(diagnostic => diagnostic.code === "arithmetic-evidence-unavailable"));
  const exact = observe(program,"instructions",true).analyze();
  const exhausted: AnalysisFacts = {...exact,diagnostics:[]};
  assert.deepEqual(detectFieldArithmetic(exhausted,1),[]);
  assert.ok(exhausted.diagnostics.some(diagnostic => diagnostic.code === "arithmetic-review-budget"));
  const joined: AnalysisFacts = {...exact,diagnostics:[],pathSemantics:"guard-cover"};
  assert.deepEqual(rule.run(joined),[]);
  assert.ok(joined.diagnostics.some(diagnostic => diagnostic.code === "arithmetic-evidence-unavailable"));
  const limited = scanFile(program.root,{detectors:[rule.id],maxSteps:1});
  assert.equal(limited.status,"incomplete");
  assert.equal(limited.coverage.completedEntries.length,0);
}));

test("generic Field modular math needs no quantity observer and changed values cannot inherit Uint origins", () => fixture(`import CompactStandardLibrary;
export circuit fieldOnly(left: Field,right: Field): Field { return disclose(left-right); }
export circuit scalar(value: Uint<8>): Field { return disclose(((value as Bytes<32>) as Field) - (1 as Field)); }
`,program => {
  assert.equal(arithmeticTargets(program).applicable,false);
  const scan = scanFile(program.root,{detectors:[rule.id]});
  assert.equal(scan.status,"complete",JSON.stringify(scan.diagnostics));
  assert.deepEqual(scan.findings,[]);
}));


test("intentional additive Field masking remains an explicit known review false positive, so quantity intent is opt-in", () => fixture(`import CompactStandardLibrary;
export circuit encrypt(value: Uint<128>, secret: Field): Field {
  const mask = degradeToTransient(persistentHash<Field>(secret));
  return disclose((value as Field)+mask);
}`,program => {
  const selected = scanFile(program.root,{detectors:[rule.id]});
  assert.equal(selected.status,"complete",JSON.stringify(selected.diagnostics));
  assert.equal(selected.findings.length,1);
  assert.equal(selected.findings[0].metadata.modularIntentInferred,false);
  const defaults = scanFile(program.root);
  assert.equal(defaults.status,"complete",JSON.stringify(defaults.diagnostics));
  assert.ok(defaults.findings.every(finding => finding.detectorId !== rule.id));
}));

test("checked aliases constrain the same immutable arithmetic result and earlier atomic effects", () => fixture(`import CompactStandardLibrary;
export ledger balance: Field;
circuit sub(left: Field,right: Field): Field { return left-right; }
export circuit typedAlias(left: Uint<8>,right: Uint<8>,expected: Uint<8>): Field { const result = (left as Field)-(right as Field); assert(result == (expected as Field),"typed alias"); return disclose(result); }
export circuit typedAliasReversed(left: Uint<8>,right: Uint<8>,expected: Uint<8>): Field { const result = (left as Field)-(right as Field); assert((expected as Field) == result,"typed alias"); return disclose(result); }
export circuit repeated(left: Uint<8>,right: Uint<8>): Uint<8> { const first = sub(left as Field,right as Field); balance = disclose(first); const second = sub(left as Field,right as Field); return disclose(second as Uint<8>); }
export circuit cachedReplay(left: Uint<8>,right: Uint<8>): Uint<8> { for (const i of 0..2) { balance = disclose(sub(left as Field,right as Field)); } return disclose(balance as Uint<8>); }
export circuit returnedPair(left: Uint<8>,right: Uint<8>): [Field,Uint<8>] { const result = (left as Field)-(right as Field); const checked = result as Uint<8>; return disclose([result,checked]); }
export circuit earlierWrite(left: Uint<8>,right: Uint<8>): Uint<8> { const result = (left as Field)-(right as Field); balance = disclose(result); return disclose(result as Uint<8>); }
export circuit different(left: Uint<8>,right: Uint<8>,other: Uint<8>): [Field,Field] { const safe = sub(left as Field,right as Field); const checked = safe as Uint<8>; const unsafe = sub(other as Field,right as Field); return disclose([safe,unsafe]); }
export circuit addition(value: Field,bit: Uint<1>): [Field,Uint<8>] { const result = value+(bit as Field); const checked = result as Uint<8>; return disclose([result,checked]); }
export circuit alternatives(left: Uint<8>,right: Uint<8>,choice: Boolean): [Field,Uint<8>] { const result = (left as Field)-(right as Field); if (disclose(choice)) { return disclose([result,result as Uint<8>]); } else { return disclose([result,0 as Uint<8>]); } }
`,program => {
  for (const engine of ["instructions","expressions"] as const) for (const cached of [false,true]) {
    const facts = observe(program,engine,cached).analyze();
    const findings = rule.run(facts);
    assert.deepEqual(facts.diagnostics,[]);
    assert.deepEqual(facts.completedEntries,program.entries);
    assert.deepEqual(findings.map(finding => finding.metadata.entry).sort(),["addition","alternatives","different"]);
    if (cached) assert.ok(facts.metrics.summaryHits > 0,"exercise real pure-summary reuse of deterministic arithmetic");
    const path = facts.paths.find(path => program.symbols.get(path.entry)!.name === "earlierWrite")!;
    const id = path.sinks.find(sink => sink.kind === "ledger-write")!.value.identity;
    assert.ok(id);
    assert.deepEqual(path.integerDomains!.get(id!),{ minimum:"0",maximum:"255" });
  }
  const scan = scanFile(program.root,{detectors:[rule.id]});
  assert.equal(scan.status,"complete",JSON.stringify(scan.diagnostics));
  assert.deepEqual(scan.findings.map(finding=>finding.metadata.entry).sort(),["addition","alternatives","different"]);
}));

test("checked-domain capacity is incomplete and cannot be silently dropped", () => {
  const casts = Array.from({length:257},(_,i) => `const result${i} = (value as Field)-(${i} as Field); const checked${i} = result${i} as Uint<16>;`).join("\n");
  fixture(`export circuit entry(value: Uint<16>): Field { ${casts} return disclose(result256); }`,program => {
    for (const engine of ["instructions","expressions"] as const) {
      const facts = observe(program,engine,true).analyze();
      assert.equal(facts.completedEntries.length,0);
      assert.ok(facts.diagnostics.some(diagnostic=>diagnostic.code==="arithmetic-domain-budget"));
    }
    assert.equal(scanFile(program.root,{detectors:[rule.id]}).status,"incomplete");
  });
});

test("mixed Field/Uint implicit arithmetic alone cannot be certified inapplicable", () => fixture(`export circuit entry(left: Field,right: Uint<8>): Field { return disclose(left-right); }`,program => {
  assert.equal(arithmeticTargets(program).applicable,true);
  const selected = scanFile(program.root,{detectors:[rule.id]});
  assert.equal(selected.status,"complete",JSON.stringify(selected.diagnostics));
  assert.equal(selected.findings.length,1);
  const ordinary = new Dataflow(program).analyze();
  assert.deepEqual(rule.run(ordinary),[]);
  assert.ok(ordinary.diagnostics.some(diagnostic=>diagnostic.code==="arithmetic-evidence-unavailable"));
}));
