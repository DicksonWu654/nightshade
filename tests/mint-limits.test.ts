import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow } from "../src/dataflow/index.js";
import { mintQuantityEvidence } from "../src/dataflow/mint-quantities.js";
import { unboundedMint as rule } from "../src/detectors/mint-limits.js";
import { Program } from "../src/semantic/index.js";
import { scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function check(body: string, expected: string[], maximums: Record<string,string> = {}) {
  withFiles({"main.compact":"import CompactStandardLibrary;\n"+body},directory=>{
    const file=resolve(directory,"main.compact");
    if(process.env.COMPACTC_TEST) { const c=validateWithCompiler(process.env.COMPACTC_TEST,file);assert.equal(c.valid,true,c.error); }
    const program=new Program(file);let baseline:unknown;
    for(const engine of ["instructions","expressions"] as const)for(const cached of [false,true]) {
      const facts=new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,true,"all",false,false,false,true,false,false,false,false,true,true).analyze();
      assert.deepEqual(facts.diagnostics,[]);assert.deepEqual(facts.completedEntries,program.entries);
      for (const [entry, maximum] of Object.entries(maximums)) {
        const paths=facts.paths.filter(path=>program.symbols.get(path.entry)?.name===entry);
        assert.ok(paths.length,entry);
        for (const path of paths) {
          const mints=path.operations?.filter(operation=>operation.kind==="kernel-write" && ["mintShielded","mintUnshielded"].includes(operation.name));
          assert.ok(mints?.length,entry);
          for (const mint of mints) assert.equal(String(mintQuantityEvidence(path,()=>{}).bounds(mint.args[1],"Uint<64>").range.maximum),maximum,entry);
        }
      }
      const findings=rule.run(facts).sort((a,b)=>a.fingerprint.localeCompare(b.fingerprint));
      assert.deepEqual(facts.diagnostics,[]);assert.deepEqual(findings.map(f=>f.metadata.entry).sort(),expected.slice().sort());
      baseline??=findings;assert.deepEqual(findings,baseline);
    }
    const result=scanFile(file,{detectors:[rule.id]});assert.equal(result.status,"complete",JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings.sort((a,b)=>a.fingerprint.localeCompare(b.fingerprint)),baseline);
    assert.ok(scanFile(file).findings.every(f=>f.detectorId!==rule.id));
  });
}

test("native range and lower-only checks are not application upper caps; fixed and narrower quantities are",()=>check(`
export circuit loose(amount: Uint<64>, nonce: Bytes<32>): [] { mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit lowerOnly(amount: Uint<64>, nonce: Bytes<32>): [] { assert(amount > 0,"positive"); mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit capped(amount: Uint<64>, nonce: Bytes<32>): [] { assert(amount <=100,"cap"); mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit cappedLate(amount: Uint<64>, nonce: Bytes<32>): [] { mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); assert(amount<=100,"cap"); }
circuit wideHelper(amount: Uint<64>, nonce: Bytes<32>): [] { mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit narrowThroughHelper(amount: Uint<8>, nonce: Bytes<32>): [] { wideHelper(amount,nonce); }
export circuit typed(amount: Uint<8>, nonce: Bytes<32>): [] { mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit fixed(nonce: Bytes<32>): [] { mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),shieldedBurnAddress()); }
`,["loose","lowerOnly"]));

test("quantity guards use exact scalar snapshots and exclude irrelevant input checks",()=>check(`
export circuit computedCapped(amount: Uint<64>, nonce: Bytes<32>): [] { const quantity=(amount+1) as Uint<64>; assert(quantity<=100,"cap"); mintShieldedToken(default<Bytes<32>>,disclose(quantity),disclose(nonce),shieldedBurnAddress()); }
export circuit unrelated(amount: Uint<64>, other: Uint<64>, nonce: Bytes<32>): [] { assert(other<=100,"other"); mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit alias(amount: Uint<64>, nonce: Bytes<32>): [] { const saved=amount; assert(saved<=100,"cap"); mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
`,["unrelated"]));

test("numeric widening preserves computed and aggregate leaf domains before mint observation",()=>check(`
circuit wideVector(values: Vector<1, Uint<64>>): [] { kernel.mintUnshielded(default<Bytes<32>>,disclose(values[0])); }
circuit wideScalar(amount: Uint<64>): [] { kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); }
export circuit computed(amount: Uint<8>): [] { const quantity=(amount+1) as Uint<64>; kernel.mintUnshielded(default<Bytes<32>>,disclose(quantity)); }
export circuit vector(values: Vector<1, Uint<8>>): [] { wideVector(values); }
export circuit computedHelper(amount: Uint<8>): [] { wideScalar((amount+1) as Uint<64>); }
export circuit genuinelyWide(amount: Uint<64>): [] { const quantity=(amount+1) as Uint<64>; kernel.mintUnshielded(default<Bytes<32>>,disclose(quantity)); }
`,["genuinelyWide"],{computed:"256",vector:"255",computedHelper:"256"}));

test("public immutable ledger upper bound and equality count; a private echo and older revisions do not",()=>check(`
export ledger limit: Uint<64>;
export circuit ledgerQuantity(): [] { mintShieldedToken(default<Bytes<32>>,limit,default<Bytes<32>>,shieldedBurnAddress()); }
export circuit ledgerSelection(flag: Boolean): [] { if(disclose(flag)) { mintShieldedToken(default<Bytes<32>>,limit,default<Bytes<32>>,shieldedBurnAddress()); } }
export circuit transitive(amount: Uint<64>, upper: Uint<64>): [] { assert(upper == limit,"alias"); assert(amount <=upper,"cap"); kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); }
export ledger limits: Map<Uint<8>,Uint<64>>;
export circuit mapCap(amount: Uint<64>, key: Uint<8>): [] { assert(limits.member(disclose(key)),"exists"); assert(amount<=limits.lookup(disclose(key)),"public cap"); kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); }
export circuit publicSelf(): [] { const amount=limit; assert(amount<=limit,"tautology"); kernel.mintUnshielded(default<Bytes<32>>,amount); }
export circuit publicCap(amount: Uint<64>, nonce: Bytes<32>): [] { assert(amount<=limit,"cap"); mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit publicEquality(amount: Uint<64>, nonce: Bytes<32>): [] { assert(amount==limit,"cap"); mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit privateEcho(amount: Uint<64>, nonce: Bytes<32>): [] { limit=disclose(amount); assert(amount<=limit,"echo"); mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit changed(): [] { const before=limit; assert(before<=100,"old cap"); limit=18446744073709551615; mintShieldedToken(default<Bytes<32>>,limit,default<Bytes<32>>,shieldedBurnAddress()); }
`,["ledgerQuantity","ledgerSelection","privateEcho","publicSelf"]));

test("both mint kinds, direct kernel mints and helper invocations retain quantity evidence",()=>check(`
circuit helper(amount: Uint<64>): [] { mintUnshieldedToken(default<Bytes<32>>,disclose(amount),right<ContractAddress,UserAddress>(UserAddress { bytes: pad(32,"recipient") })); }
export circuit unshielded(amount: Uint<64>): [] { helper(amount); }
export circuit guarded(amount: Uint<64>): [] { assert(amount<101,"cap"); helper(amount); }
export circuit direct(amount: Uint<64>): [] { kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); }
module Fake { export circuit mintShieldedToken(): [] {} }
import Fake prefix F_;
export circuit lookalike(): [] { F_mintShieldedToken(); }
`,["direct","unshielded"]));

test("branches remain separate, later rejection and initial allocation are outside review",()=>check(`
constructor(amount: Uint<64>, nonce: Bytes<32>) { mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit optionalCap(flag: Boolean, amount: Uint<64>, nonce: Bytes<32>): [] { if(disclose(flag)) { assert(amount<=100,"cap"); } mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }
export circuit rejected(amount: Uint<64>, nonce: Bytes<32>): [] { mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); assert(false,"reject"); }
`,["optionalCap"]));

test("absent or exhausted quantity evidence is incomplete; review remains opt-in",()=>{
  assert.equal(rule.defaultEnabled,false);
  const path={entry:"entry",bindings:[],sinks:[],path:[],writes:[],predicates:[]};
  const value={flows:[],ledger:new Set<string>(),type:"Uint<64>",mintSnapshot:"saved"};
  assert.throws(()=>mintQuantityEvidence(path,()=>{throw Error("budget");}).bounds(value,"Uint<64>"),/budget/);
  assert.throws(()=>mintQuantityEvidence({...path,predicates:undefined},()=>{}),/requires successful predicates/);
  withFiles({"main.compact":"import CompactStandardLibrary; export circuit mint(amount: Uint<64>): [] { kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); }"},directory=>{
    const program=new Program(resolve(directory,"main.compact"));
    const facts=new Dataflow(program).analyze();
    assert.deepEqual(rule.run(facts),[]);assert.equal(facts.diagnostics[0].code,"mint-quantity-evidence-incomplete");
    const snapshotsOnly=new Dataflow(program,40000,256,50000,"instructions",true,true,"equivalent-states",false,true,"all",false,false,false,true,false,false,false,false,true).analyze();
    assert.equal(snapshotsOnly.diagnostics.length,0);assert.equal(snapshotsOnly.mintEvidence,true);
    assert.deepEqual(rule.run(snapshotsOnly),[]);assert.equal(snapshotsOnly.diagnostics[0].code,"mint-quantity-evidence-incomplete");
  });
});


test("checkpoint prefixes retain pure proof caps and saved guaranteed reads; later ledger reads stay fallible",()=>check(`
export ledger cap: Uint<64>;
circuit readCap(): Uint<64> { return cap; }
export circuit pureCap(amount: Uint<64>): [] { kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); kernel.checkpoint(); assert(amount<=100,"proof cap"); }
export circuit savedCap(amount: Uint<64>): [] { const saved=readCap(); kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); kernel.checkpoint(); assert(amount<=saved,"saved cap"); }
export circuit lateLedgerCap(amount: Uint<64>): [] { kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); kernel.checkpoint(); assert(amount<=readCap(),"fallible cap"); }
`,["lateLedgerCap"]));


test("computed public caps retain exact numeric origins without accepting private or self-derived bounds",()=>check(`
export ledger cap: Uint<64>;
export circuit savedComputed(amount: Uint<64>): [] { const saved=(cap+1) as Uint<64>; kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); kernel.checkpoint(); assert(amount<=saved,"public cap"); }
export circuit computed(amount: Uint<64>): [] { const saved=(cap*2+1) as Uint<64>; assert(amount<=saved,"public cap"); kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); }
export circuit fallibleComputed(amount: Uint<64>): [] { kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); kernel.checkpoint(); const saved=(cap+1) as Uint<64>; assert(amount<=saved,"fallible cap"); }
export circuit privateBound(amount: Uint<64>, extra: Uint<64>): [] { const saved=(cap+extra) as Uint<64>; assert(amount<=saved,"private cap"); kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); }
export circuit echo(amount: Uint<64>): [] { cap=disclose(amount); const saved=(cap+1) as Uint<64>; assert(amount<=saved,"echo"); kernel.mintUnshielded(default<Bytes<32>>,disclose(amount)); }
export circuit selfDerived(): [] { const amount=cap; const saved=(amount+1) as Uint<64>; assert(amount<=saved,"self"); kernel.mintUnshielded(default<Bytes<32>>,amount); }
`,["fallibleComputed","privateBound","echo","selfDerived"]));
