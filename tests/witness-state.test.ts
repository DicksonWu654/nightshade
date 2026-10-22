import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow } from "../src/dataflow/index.js";
import { uncheckedWitnessState } from "../src/dataflow/witness-state.js";
import { unconstrainedWitnessToState as rule } from "../src/detectors/witness-state.js";
import { Program } from "../src/semantic/index.js";
import { scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function check(body: string, expected: string[]) {
  withFiles({"main.compact":"import CompactStandardLibrary;\n"+body},directory=>{
    const file=resolve(directory,"main.compact");
    if(process.env.COMPACTC_TEST) { const c=validateWithCompiler(process.env.COMPACTC_TEST,file);assert.equal(c.valid,true,c.error); }
    const program=new Program(file);let baseline:unknown;
    for(const engine of ["instructions","expressions"] as const) for(const cached of [false,true]) {
      const facts=new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,false,"all").analyze();
      assert.deepEqual(facts.diagnostics,[]);assert.deepEqual(facts.completedEntries,program.entries);
      const findings=rule.run(facts).sort((a,b)=>a.fingerprint.localeCompare(b.fingerprint));
      assert.deepEqual(facts.diagnostics,[]);assert.deepEqual(findings.map(f=>f.metadata.entry).sort(),expected.slice().sort());
      baseline??=findings;assert.deepEqual(findings,baseline);
    }
    const result=scanFile(file,{detectors:[rule.id]});assert.equal(result.status,"complete",JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings.sort((a,b)=>a.fingerprint.localeCompare(b.fingerprint)),baseline);
    assert.ok(scanFile(file).findings.every(f=>f.detectorId!==rule.id));
  });
}

test("raw witness writes require a value-specific assertion; parameters and unrelated caller checks are distinct",()=>check(`
export ledger stored: Uint<64>;
export ledger cap: Uint<64>;
witness amount(): Uint<64>;
witness callerAllowed(): Boolean;
export circuit unchecked(): [] { stored=disclose(amount()); }
export circuit unrelated(): [] { assert(callerAllowed(),"caller");stored=disclose(amount()); }
export circuit boundedWrapper(): [] { const value=amount();assert((value<=cap)&&true,"amount");stored=disclose(value); }
export circuit boundedAlias(): [] { const value=amount();const bounded=(value<=cap)&&true;assert(bounded,"amount");stored=disclose(value); }
export circuit bounded(): [] { const value=amount();assert(value<=cap,"amount");stored=disclose(value); }
export circuit lateBound(): [] { const value=amount();stored=disclose(value);assert(value<=100,"late atomic check"); }
export circuit parameter(value: Uint<64>): [] { stored=disclose(value); }
`,["unchecked","unrelated"]));

test("distinct calls, aggregate leaves, self-comparisons and witness attestations do not validate the written leaf",()=>check(`
struct Reward { value: Uint<64>; checked: Uint<64>; }
export ledger stored: Uint<64>;
witness reward(): Reward;
witness amount(): Uint<64>;
witness signature_valid(value: Uint<64>): Boolean;
export circuit leaf(): [] { const r=reward();assert(r.checked<100,"other leaf");stored=disclose(r.value); }
export circuit otherCall(): [] { assert(amount()<100,"first");stored=disclose(amount()); }
export circuit self(): [] { const value=amount();assert(value==value,"self");stored=disclose(value); }
export circuit wrappedSelf(): [] { const value=amount();assert((value==value)&&true,"self");stored=disclose(value); }
export circuit attestation(): [] { const value=amount();assert(signature_valid(value),"attestation");stored=disclose(value); }
export circuit echo(): [] { const value=amount();stored=disclose(value);assert(value==stored,"echo"); }
`,["leaf","otherCall","self","wrappedSelf","attestation","echo"]));

test("branch choices alone are not assertions; immutable checked snapshots do not constrain a new witness",()=>check(`
export ledger stored: Uint<64>;
witness amount(): Uint<64>;
witness yes(): Boolean;
export circuit negatedOptional(): [] {const value=amount();assert(!(value<100 && yes()),"optional");stored=disclose(value);}
export circuit branch(): [] { const value=amount();if(disclose(value<100)){stored=disclose(value);}else{stored=disclose(value);} }
export circuit changed(): [] { const checked=amount();assert(checked<100,"old");const fresh=amount();stored=disclose(fresh); }
export circuit compound(): [] { const value=amount();assert(value<100 && value>0,"range");stored=disclose(value); }
export circuit tautologicalAlternative(): [] {const value=amount();assert(value<100 || true,"optional");stored=disclose(value);}
export circuit alternative(flag: Boolean): [] { const value=amount();assert(flag || value<100,"optional");stored=disclose(value); }
`,["branch","changed","alternative","tautologicalAlternative","negatedOptional"]));

test("overwrites, transformed/cast data, constructor setup and rejected histories stay outside this narrow review",()=>check(`
export ledger stored: Uint<64>;
export ledger digest: Bytes<32>;
witness amount(): Uint<64>;
constructor(){stored=disclose(amount());}
export circuit overwritten(): [] {stored=disclose(amount());stored=0;}
export circuit hashed(): [] {digest=disclose(persistentHash<Uint<64>>(amount()));}
export circuit casted(): [] {stored=disclose((amount() as Uint<8>) as Uint<64>);}
export circuit derived(): [] {stored=disclose((amount()+1) as Uint<64>);}
export circuit rejected(): [] {stored=disclose(amount());assert(false,"reject");}
`,[]));

test("helper guards, source invocations and callbacks preserve exact value evidence across cache modes",()=>check(`
export ledger stored: Uint<64>;
witness amount(): Uint<64>;
circuit save(value: Uint<64>): [] {stored=disclose(value);}
circuit capped(value: Uint<64>): [] {assert(value<100,"amount");save(value);}
circuit identity(value: Uint<64>): Uint<64> {return value;}
export circuit helper(): [] {save(amount());}
export circuit guarded(): [] {capped(amount());}
export circuit cached(): [] {const v=amount();const a=identity(v);const b=identity(v);stored=disclose(b);}
export circuit callback(): [] {map(save,[amount()]);}
`,["helper","cached","callback"]));

test("missing or exhausted evidence stays explicitly incomplete and review is opt-in",()=>{
  assert.equal(rule.defaultEnabled,false);
  const path={entry:"entry",bindings:[],sinks:[],path:[],writes:[],predicates:[]};
  assert.throws(()=>uncheckedWitnessState(path,()=>{throw Error("budget");}),/budget/);
  assert.throws(()=>uncheckedWitnessState({...path,predicates:undefined},()=>{}),/unavailable/);
  withFiles({"main.compact":"import CompactStandardLibrary;export ledger stored:Uint<64>;witness value():Uint<64>;export circuit save():[]{stored=disclose(value());}"},directory=>{
    const facts=new Dataflow(new Program(resolve(directory,"main.compact"))).analyze();
    assert.deepEqual(rule.run(facts),[]);assert.equal(facts.diagnostics[0].code,"witness-state-evidence-incomplete");
  });
});


test("checkpoint prefixes retain later pure witness checks and omit fallible ledger-dependent validation",()=>check(`
export ledger stored: Uint<64>; export ledger cap: Uint<64>;
witness quantity(): Uint<64>;
circuit readCap(): Uint<64> { return cap; }
export circuit pureCheck(): [] { const value=quantity(); stored=disclose(value); kernel.checkpoint(); assert(value<=100,"proof validation"); }
export circuit savedCheck(): [] { const saved=readCap(); const value=quantity(); stored=disclose(value); kernel.checkpoint(); assert(value<=saved,"guaranteed snapshot"); }
export circuit lateLedgerCheck(): [] { const value=quantity(); stored=disclose(value); kernel.checkpoint(); assert(value<=readCap(),"fallible validation"); }
`,["lateLedgerCheck"]));
