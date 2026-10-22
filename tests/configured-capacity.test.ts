import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, scanFileIsolated, detectors } from "../src/index.js";
import { CollectionFacts } from "../src/dataflow/collections.js";
import { configuredMembershipCapacityReview as rule } from "../src/detectors/configured-capacity.js";
import { withFiles } from "./helpers.js";
const header=`import CompactStandardLibrary; export ledger members: Set<Bytes<32>>; export ledger actions: Counter;`;
const setup=`constructor(seed: Bytes<32>) { members.insert(disclose(seed)); }`;
const gate=`export circuit act(a: Bytes<32>, b: Bytes<32>): [] {
 assert(a != b, "different members"); assert(members.member(disclose(a)), "A"); assert(members.member(disclose(b)), "B"); actions.increment(1);
}`;
function fixture(source:string,expected:number,gap=false) {
  withFiles({"main.compact":source},directory=>{
    const program=new Program(resolve(directory,"main.compact")),entry=program.entries.find(id=>program.symbols.get(id)!.kind!=="constructor")!;
    let oracle:unknown;
    for(const engine of ["instructions","expressions"] as const) for(const cached of [false,true]) {
      const flow=new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,false,"all",false,true,false,false);
      const facts=flow.analyzeConfiguredCapacityEntry(entry); const findings=rule.run(facts);
      assert.equal(findings.length,expected,`${engine}/${cached}: ${JSON.stringify(facts.diagnostics)}`);
      assert.equal(facts.diagnostics.length>0,gap,JSON.stringify(facts.diagnostics));
      assert.deepEqual(facts.failedAssertions,[]); assert.deepEqual(facts.assertionReaches,[]);
      oracle??=findings; assert.deepEqual(findings,oracle);
    }
  });
}
test("one symbolic constructor member conflicts with two distinct requirements only",()=>{
  fixture(header+setup+gate,1);
  fixture(header+`constructor(first:Bytes<32>,second:Bytes<32>) { assert(first != second,"two"); members.insert(disclose(first)); members.insert(disclose(second)); }`+gate,0);
  fixture(header+setup+gate.replace('assert(a != b, "different members");','').replace('assert(members.member(disclose(b)), "B");',''),0);
});
test("same key, alternatives and negated checks do not invent distinct members",()=>{
  fixture(header+setup+gate.replace('assert(a != b, "different members");','').replace('member(disclose(b))','member(disclose(a))'),0);
  fixture(header+setup+`export circuit act(a:Bytes<32>,b:Bytes<32>): [] { assert(a != b,"different"); assert(members.member(disclose(a)) || members.member(disclose(b)),"either"); }`,0);
  fixture(header+setup+`export circuit act(a:Bytes<32>,b:Bytes<32>): [] { assert(a != b,"different"); assert(!members.member(disclose(a)),"absent"); assert(members.member(disclose(b)),"present"); }`,0);
});
test("shared upper bounds are optional and transfer conservatively",()=>{
  const region={root:"members",path:[],type:"Set<Field>"};
  const ordinary=new CollectionFacts(); ordinary.reset(region); ordinary.insert(region,"identity:first");
  assert.deepEqual(ordinary.snapshot(),{exhausted:false,collections:[{region:{root:"members",path:[]},defaultMember:false,members:[{key:"identity:first",present:true}],size:1}]});
  assert.equal(ordinary.upperBound(region),undefined);
  const tracked=new CollectionFacts(256,true); assert.equal(tracked.upperBound(region),undefined); tracked.reset(region); tracked.insert(region,undefined); assert.equal(tracked.upperBound(region),1);
  tracked.insert(region,"identity:next"); assert.equal(tracked.upperBound(region),2); tracked.remove(region,undefined); assert.equal(tracked.upperBound(region),2);
  assert.equal(tracked.clone().upperBound(region),2); const empty=new CollectionFacts(256,true); empty.reset(region); assert.equal(tracked.common(empty).upperBound(region),2);
  tracked.invalidateWrite(region); assert.equal(tracked.upperBound(region),undefined);
});
test("selected direct and supervised reports expose isolated state boundary",async()=>{
  const source=header+setup+gate;
  // Direct inline control; persistent owned seed is qualified separately.
  withFiles({"main.compact":source},directory=>{
    const file=resolve(directory,"main.compact"), report=scanFile(file,{detectors:[rule.id]});
    assert.equal(report.status,"complete",JSON.stringify(report.diagnostics)); assert.equal(report.findings.length,1); assert.equal(report.findings[0].severity,"info");
    assert.equal(report.findings[0].metadata.stateBoundary,"immediate-post-constructor"); assert.ok(!scanFile(file).coverage.detectors.includes(rule.id));
    const exhausted=scanFile(file,{detectors:[rule.id],maxSteps:1}); assert.equal(exhausted.status,"incomplete"); assert.ok(exhausted.diagnostics.length);
  });
  const directory=mkdtempSync(resolve(tmpdir(),"compact-capacity-supervised-"));
  try { const file=resolve(directory,"main.compact"); writeFileSync(file,source);
    const options={detectors:[rule.id]}, direct=scanFile(file,options), supervised=await scanFileIsolated(file,options);
    assert.equal(supervised.status,"complete",JSON.stringify(supervised.diagnostics)); assert.deepEqual(supervised.findings,direct.findings); assert.deepEqual(supervised.coverage.rules,direct.coverage.rules);
  } finally { rmSync(directory,{recursive:true,force:true}); }
  assert.equal(detectors.at(-1),rule);
});
test("fresh transfer enlarges capacity; stale membership revision diagnoses",()=>{
  fixture(header+setup+gate.replace(' assert(a != b,',' members.insert(disclose(b)); assert(a != b,'),0);
  fixture(header+setup+`export circuit act(a:Bytes<32>,b:Bytes<32>): [] { assert(a != b,"different"); const saved=members.member(disclose(a)); members.insert(disclose(b)); assert(saved,"stale"); assert(members.member(disclose(b)),"B"); }`,0,true);
  fixture(header+gate,0,true);
  fixture(header+setup+gate.replace('actions.increment(1);','members.remove(disclose(a));'),0,true);
});
test("ordinary unknown state never becomes initialized empty or leaks sequence failures",()=>{
  withFiles({"main.compact":header+setup+gate},directory=>{
    const program=new Program(resolve(directory,"main.compact")); const ordinary=new Dataflow(program).analyze();
    assert.equal(ordinary.configuredCapacity,undefined); assert.deepEqual(ordinary.diagnostics,[]);
    assert.ok(ordinary.paths.some(path=>path.entry.endsWith("::act")));
    assert.ok(ordinary.paths.flatMap(path=>path.predicates??[]).every(predicate=>predicate.value.collectionPredicate?.upperBound===undefined));
    const entry=program.entries.find(id=>id.endsWith("::act"))!;
    const unavailable=new Dataflow(program,1,1,1,"instructions",true,true,"equivalent-states",false,false,"all",false,true,false,false).analyzeConfiguredCapacityEntry(entry);
    assert.ok(unavailable.diagnostics.length); assert.deepEqual(unavailable.failedAssertions,[]); assert.equal(unavailable.configuredCapacity!.prefixes.length,0);
  });
});
test("direct registry dispatch leaves ordinary facts unchanged",()=>{
  withFiles({"main.compact":header+setup+gate},directory=>{
    const program=new Program(resolve(directory,"main.compact"));
    const facts=new Dataflow(program).analyze();
    const before=structuredClone({diagnostics:facts.diagnostics,metrics:facts.metrics,paths:facts.paths});
    assert.deepEqual(rule.run(facts),[]);
    assert.deepEqual({diagnostics:facts.diagnostics,metrics:facts.metrics,paths:facts.paths},before);
  });
});
test("same-site helper summaries preserve all final gate predicates",()=>{
  const helper=`circuit requireMember(id:Bytes<32>): [] { assert(members.member(disclose(id)),"member"); }
 export circuit act(a:Bytes<32>,b:Bytes<32>): [] { assert(a != b,"different"); requireMember(a); requireMember(b); }`;
  fixture(header+setup+helper,1);
});
test("required scalar equality relays and partial distinctness use exact identities",()=>{
  fixture(header+setup+`export circuit act(a:Bytes<32>,b:Bytes<32>,alias:Bytes<32>): [] { assert(b == alias,"relay"); assert(a != alias,"distinct"); assert(members.member(disclose(a)),"A"); assert(members.member(disclose(b)),"B"); }`,1);
  fixture(header+setup+`export circuit act(a:Bytes<32>,b:Bytes<32>,ok:Boolean): [] { assert(members.member(disclose(a)) == ok,"unknown relation"); assert(a != b,"different"); assert(members.member(disclose(b)),"B"); }`,0,true);
});
test("zero capacity and bounded three-member clique report exact demands",()=>{
  fixture(header+`constructor() {}`+`export circuit act(a:Bytes<32>): [] { assert(members.member(disclose(a)),"required"); }`,1);
  fixture(header+`constructor(a:Bytes<32>,b:Bytes<32>) { members.insert(disclose(a)); members.insert(disclose(b)); }`+`export circuit act(a:Bytes<32>,b:Bytes<32>,c:Bytes<32>): [] { assert(a != b,"ab"); assert(b != c,"bc"); assert(a != c,"ac"); assert(members.member(disclose(a)),"A"); assert(members.member(disclose(b)),"B"); assert(members.member(disclose(c)),"C"); }`,1);
});

test("callback requirements reuse ordinary transfers and zero iterations require nothing",()=>{
  fixture(header+setup+`circuit check(id:Bytes<32>): Boolean { assert(members.member(disclose(id)),"member"); return true; }
 export circuit act(a:Bytes<32>,b:Bytes<32>): [] { assert(a != b,"different"); map(check,[a,b]); }`,1);
  fixture(header+setup+`circuit check(id:Bytes<32>): Boolean { assert(members.member(disclose(id)),"member"); return true; }
 export circuit act(a:Bytes<32>,b:Bytes<32>): [] { assert(a != b,"different"); map(check,[] as Vector<0,Bytes<32>>); }`,0);
});
test("unrelated represented sorting helper is absent while baseline exhaustion stays explicit",()=>{
  withFiles({"main.compact":header+setup+gate+`
circuit exchange(a:Uint<16>,b:Uint<16>): Vector<2,Uint<16>> { return a >= b ? [a,b] : [b,a]; }
export circuit neighbor(a:Uint<16>,b:Uint<16>,c:Uint<16>): Vector<3,Uint<16>> { const x=exchange(a,b); const y=exchange(x[1],c); const z=exchange(x[0],y[0]); return [z[0],z[1],y[1]]; }`},directory=>{
    const file=resolve(directory,"main.compact"),report=scanFile(file,{detectors:[rule.id]});
    assert.equal(report.findings.length,1); const row=report.coverage.rules!.find(row=>row.entry.endsWith("::neighbor"))!;
    assert.equal(row.status,"not-applicable"); assert.equal(row.evidence,"structural-absence");
    const baseline=scanFile(file,{detectors:[],maxValues:1}); assert.equal(baseline.status,"incomplete"); assert.ok(baseline.diagnostics.length);
  });
});
test("unknown nested wildcard capacities and replacement are not finite capacity proof",()=>{
  fixture(`import CompactStandardLibrary; export ledger groups: Map<Bytes<32>,Set<Bytes<32>>>;
 constructor(group:Bytes<32>,seed:Bytes<32>) { groups.insertDefault(disclose(group)); groups.lookup(disclose(group)).insert(disclose(seed)); }
 export circuit act(group:Bytes<32>,a:Bytes<32>,b:Bytes<32>): [] { assert(a!=b,"different"); assert(groups.lookup(disclose(group)).member(disclose(a)),"A"); assert(groups.lookup(disclose(group)).member(disclose(b)),"B"); }`,0,true);
});

test("compiler-qualified generic and shared Counter capacity triplets retain source-first sites",()=>{
  for (const [family,line] of [["toy",9],["counter",33]] as const) {
    for (const variant of ["positive","corrected","lookalike"] as const) {
      const file=resolve("tests/corpus/known-bugs",`${family}-configured-membership-capacity-${variant}.compact`);
      const report=scanFile(file,{detectors:[rule.id]});
      assert.equal(report.status,"complete",JSON.stringify(report.diagnostics));
      assert.equal(report.findings.length,variant==="positive"?1:0,`${family}/${variant}`);
      if (variant==="positive") assert.equal(report.findings[0].location.line,line);
    }
  }
});

test("native signer capacity evidence preserves compiler profile and frozen membership site",()=>{
  for (const variant of ["positive","corrected","lookalike"] as const) {
    const file=resolve("tests/corpus/synthetic-regressions/state16",`configured-membership-capacity-review-case-43-native-${variant}.compact`);
    const report=scanFile(file,{detectors:[rule.id],compilerVersion:"0.34.0",zkirVersion:3});
    assert.equal(report.status,"complete",JSON.stringify(report.diagnostics));
    assert.equal(report.findings.length,variant==="positive"?1:0,variant);
    if (variant==="positive") {
      assert.equal(report.findings[0].location.line,82);
      assert.equal(report.findings[0].metadata.stateBoundary,"immediate-post-constructor");
    }
  }
});
