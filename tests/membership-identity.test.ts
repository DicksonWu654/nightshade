import assert from "node:assert/strict";
import test from "node:test";
import {resolve} from "node:path";
import {Program,scanFile} from "../src/index.js";
import {observeMembershipIdentity as observe} from "../src/analysis/membership-identity-observation.js";
import {independentMembershipIdentityReview as rule} from "../src/detectors/membership-identity.js";
import {withFiles} from "./helpers.js";
import {membershipIdentityList,membershipIdentitySet} from "../src/semantic/membership-identity.js";

function matrix(file:string, expected:number) {
  const program=new Program(file,[],undefined,undefined,3,"0.34.0");
  let reference:unknown;
  for(const engine of ["instructions","expressions"] as const)for(const cached of [false,true]) {
    const result=observe(program,rule,{},undefined,{engine,cached});
    assert.deepEqual(result.diagnostics,[]);
    assert.equal(result.findings.length,expected);
    assert.deepEqual(result.work.limits,{maxSteps:40000,maxPaths:256,maxValues:50000});
    assert.ok(result.findings.every(f=>f.severity==="info" && f.metadata.soleAuthorization===false && f.metadata.applicationImpact==="not-inferred"));
    reference??=result.findings;assert.deepEqual(result.findings,reference);
  }
  return program;
}

test("owned memo relationship preserves engine/cache parity and distinct ledger questions",()=>{
  for(const variant of ["positive","corrected","lookalike"]) {
    const file=resolve(`tests/corpus/drafts/memo-identity44/${variant}.compact`);
    const p=matrix(file,variant==="positive"?2:0);
    const result=observe(p,rule,{});
    assert.deepEqual(result.findings.map(f=>f.location.line),variant==="positive"?[58,58]:[]);
    if(variant==="positive")assert.deepEqual(result.findings.map(f=>f.metadata.effectLines),[[35,51],[37,43,52]]);
    const selected=scanFile(file,{detectors:[rule.id],zkirVersion:3});
    assert.equal(selected.status,"complete",JSON.stringify(selected.diagnostics));
    assert.equal(selected.findings.length,variant==="positive"?2:0);
    assert.ok(scanFile(file,{zkirVersion:3}).findings.every(f=>f.detectorId!==rule.id));
  }
});

test("source-first boundaries distinguish intentional administration, repeated calls, binding, keys and alternatives",()=>{
  for(const [name,count] of [["intentional-admin",1],["repeated-witness",1],["equality-bound",0],["distinct-key",0],["optional-membership",0]] as const)
    matrix(resolve(`tests/corpus/drafts/memo-identity44-boundaries/${name}.compact`),count);
});

test("small preparation, history and shared value budgets refuse instead of reporting quiet complete coverage",()=>{
  const p=new Program(resolve("tests/corpus/drafts/memo-identity44/positive.compact"),[],undefined,undefined,3,"0.34.0");
  for(const limits of [{maxSteps:1},{maxPaths:1},{maxValues:100}]) {
    const r=observe(p,rule,limits);assert.deepEqual(r.findings,[]);assert.ok(r.diagnostics.length);
    assert.ok(r.coverage.some(row=>row.status==="incomplete"));
  }
});

test("many-entry refusal has bounded entry-local diagnostic codes",()=>{
  const source='import CompactStandardLibrary; witness secret(): Bytes<32>;'+Array.from({length:64},(_,i)=>`export circuit entry${i}(key:Bytes<32>):[]{assert(persistentHash<Bytes<32>>(secret())==disclose(key),"key");}`).join('\n');
  withFiles({"main.compact":source},directory=>{
    const p=new Program(resolve(directory,"main.compact"),[],undefined,undefined,3,"0.34.0");
    const r=observe(p,rule,{maxSteps:1,maxValues:50});
    assert.equal(r.coverage.length,64);assert.deepEqual(r.findings,[]);assert.equal(r.diagnostics.length,64);
    assert.ok(r.coverage.every(row=>row.status==="incomplete" && row.diagnosticCodes.length===1));
    assert.ok(r.diagnostics.every(issue=>issue.scope?.kind==="rule" && issue.scope.detectorId===rule.id));
  });
});

test("canonical imported and nominal collection aliases preserve the exact native shape",()=>{
  const folder=resolve("tests/corpus/drafts/memo-identity54-alias");
  const program=matrix(resolve(folder,"imported-positive.compact"),1);
  const positive=observe(program,rule,{});
  assert.equal(positive.findings[0].location.line,13);
  assert.equal(positive.findings[0].metadata.effectLedger,"memoState");
  assert.deepEqual(positive.findings[0].metadata.effectLines,[15]);
  assert.ok(positive.findings[0].callPath.includes("checkAndPop"));
  matrix(resolve(folder,"imported-corrected.compact"),0);
  const charge=()=>true;
  assert.equal(membershipIdentityList(program,"standard-type::List<Bytes<16>>",charge),false);
  assert.equal(membershipIdentitySet(program,"standard-type::Set<Bytes<16>>",charge),false);
  assert.equal(membershipIdentityList(program,"List<Bytes<32>>",charge),false);
  assert.equal(membershipIdentitySet(program,"Set<Bytes<32>>",charge),false);
  assert.equal(membershipIdentityList(program,"standard-type::List<Bytes<32>>",()=>false),false);
});

test("direct, transitive and late scalar equality bind saved membership snapshots",()=>{
  matrix(resolve("tests/corpus/drafts/memo-identity44-boundaries/equality-bound.compact"),0);
  for(const name of ["transitive","late"])
    matrix(resolve(`tests/corpus/drafts/memo-identity54-alias/${name}.compact`),0);
});
