import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { resolvePolicies, validatePolicies, type Policies } from "../src/policies.js";
import { prepareSourceMapGetters } from "../src/semantic/source-map-getters.js";
import { observeSourceMapGetters } from "../src/analysis/source-map-getters-observation.js";
import { sourceClaimMapGetterReview as rule } from "../src/detectors/source-map-getters.js";
import { readConfiguration } from "../src/config.js";
import { withFiles } from "./helpers.js";
const quote = "// Documentation claims DEFAULT_ADMIN_ROLE is customizable by roleAdmin entry.";
const contract = { setter:"setAdmin",getter:"getRoleAdmin",map:"roleAdmin",setterKey:"role",setterValue:"admin",getterKey:"role",quote };
const policies:Policies = {sourceMapGetters:[contract]};
const frozen=(variant:string)=>resolve("tests/corpus/synthetic-regressions/state16",`source-claim-map-getter-review-case-5-${variant}.compact`);
const positive=readFileSync(frozen("positive"),"utf8");
function check(source:string,expected:number,status="complete",policy=policies) {
  withFiles({"main.compact":source}, directory=>{
    const file=resolve(directory,"main.compact"), report=scanFile(file,{detectors:[rule.id],policies:policy});
    assert.equal(report.status,status,JSON.stringify(report.diagnostics));assert.equal(report.findings.length,expected,JSON.stringify(report.diagnostics));
  });
}
test("frozen exact adjacent contract distinguishes same-code intentional control and removed configuration",()=>{
  for(const variant of ["positive","corrected","lookalike"]){
    const report=scanFile(frozen(variant),{detectors:[rule.id],policies});
    assert.equal(report.status,"complete",JSON.stringify(report.diagnostics));assert.equal(report.findings.length,variant==="positive"?1:0);
    if(variant==="positive"){assert.equal(report.findings[0].location.line,6);assert.equal(report.findings[0].source!.line,4);}
  }
  assert.ok(!scanFile(frozen("positive")).coverage.detectors.includes(rule.id));
});
test("original-history capture and matcher preserve both engines and caches",()=>{
  const program=new Program(frozen("positive")),resolved=resolvePolicies(program,policies);let oracle:unknown;
  for(const engine of ["instructions","expressions"] as const)for(const cached of [false,true]){
    const observed=observeSourceMapGetters(program,rule,resolved,{},undefined,{engine,cached});
    assert.equal(observed.diagnostics.length,0,JSON.stringify(observed.diagnostics));assert.equal(observed.findings.length,1);
    oracle??=observed.findings;assert.deepEqual(observed.findings,oracle);
  }
});
test("prose is never inferred; exact parser comment adjacency activates the selected contract",()=>{
  check(positive.replace(quote,"// arbitrary explicitly selected marker"),1,"complete",{sourceMapGetters:[{...contract,quote:"// arbitrary explicitly selected marker"}]});
  check(positive.replace(quote,quote+"\n// unrelated intervening comment"),0);
  check(positive.replace(quote,quote+"\ncircuit unrelated():[]{}"),0);
  check(positive.replace(quote,"// no supplied contract"),0);
  check(positive.replace("export circuit setAdmin","export circuit otherSetter"),0,"incomplete");
  check(positive.replace("roleAdmin.insert(disclose(role), disclose(admin));","roleAdmin.insert(disclose(role), default<Bytes<32>>);"),0);
});
test("getters reading the Map through helper or zero-iteration callback are quiet",()=>{
  check(positive.replace("return default<Bytes<32>>;","return roleAdmin.lookup(disclose(role));"),0);
  check(positive.replace("export circuit getRoleAdmin",`circuit read(role:Bytes<32>):Boolean {return roleAdmin.member(disclose(role));}\nexport circuit getRoleAdmin`).replace("return default<Bytes<32>>;","map(read,[] as Vector<0,Bytes<32>>); return default<Bytes<32>>;"),0);
  check(positive.replace("return default<Bytes<32>>;","kernel.checkpoint(); return default<Bytes<32>>;"),0,"incomplete");
});
test("setter writes must survive and use exact original selected operands",()=>{
  check(positive.replace("roleAdmin.insert(disclose(role), disclose(admin));","roleAdmin.insert(disclose(role), disclose(admin)); roleAdmin.remove(disclose(role));"),0);
  check(positive.replace("roleAdmin.insert(disclose(role), disclose(admin));","roleAdmin.insert(disclose(admin), disclose(role));"),0);
  check(positive.replace("roleAdmin.insert(disclose(role), disclose(admin));", "roleAdmin.insert(disclose(role), disclose(admin)); assert(admin == default<Bytes<32>>,\"late default only\");"),0);
  check(positive.replace("return default<Bytes<32>>;","return disclose(role);"),0);
  check(positive.replace("return default<Bytes<32>>;","return pad(32,\"x\");"),0);
  check(positive.replace("roleAdmin.insert(disclose(role), disclose(admin));", "assert(admin == default<Bytes<32>>,\"fixed default only\"); roleAdmin.insert(disclose(role), disclose(admin));"),0);
});
test("direct and JSON policy validators reject malformed dense records without invoking accessors",()=>{
  const program=new Program(frozen("positive")),location=program.rootSource.ast.span;
  const bad = [Array(1),[{...contract,extra:"x"}],[{...contract,getterKey:1}],[{...contract,quote:"💡".repeat(600)}],[contract,contract]];
  const access=Object.defineProperty({},"sourceMapGetters",{enumerable:true,get(){throw new Error("invoked");}});
  for(const input of [{sourceMapGetters:undefined},access,Object.create(policies),...bad.map(value=>({sourceMapGetters:value}))]){
    assert.throws(()=>validatePolicies(input,location),/sourceMapGetters/);
    assert.throws(()=>resolvePolicies(program,input as Policies),/sourceMapGetters/);
  }
  assert.deepEqual(validatePolicies(policies,location),policies);
  check(positive,0,"incomplete",{sourceMapGetters:[{...contract,setterValue:"missing"}]});
});
test("low preparation, values and capture budgets produce rule-scoped incomplete diagnostics",()=>{
  for(const budget of [{maxSteps:1},{maxValues:1},{maxSteps:350}]){
    const report=scanFile(frozen("positive"),{detectors:[rule.id],policies,...budget});
    assert.equal(report.status,"incomplete");assert.equal(report.findings.length,0);assert.ok(report.diagnostics.some(d=>d.scope?.kind==="rule"&&d.scope.detectorId===rule.id));
  }
});
test("supervised selected policy report agrees with direct report",async()=>{
  const directory=mkdtempSync(resolve(tmpdir(),"source-map-getter-"));
  try{
    const file=resolve(directory,"main.compact");writeFileSync(file,positive);
    const direct=scanFile(file,{detectors:[rule.id],policies});const supervised=await scanFileIsolated(file,{detectors:[rule.id],policies});
    assert.equal(supervised.status,"complete",JSON.stringify(supervised.diagnostics));assert.deepEqual(supervised.findings,direct.findings);assert.deepEqual(supervised.coverage.rules,direct.coverage.rules);
  }finally{rmSync(directory,{recursive:true,force:true});}
});

test("experimental Counter mode cannot certify configured Map getter histories", async()=>{
  const options = { detectors: [rule.id], policies, experimentalCounterQueries: true };
  for (const report of [scanFile(frozen("positive"), options), await scanFileIsolated(frozen("positive"), options)]) {
    assert.equal(report.status, "incomplete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings, []);
    assert.equal(report.schemaVersion, "1.7.0");
    if (report.schemaVersion === "1.7.0") assert.ok(report.analysis.coverage.every(row => row.status === "incomplete"));
    assert.ok(report.diagnostics.some(issue => issue.code === "source-map-getter-counter-unavailable"
      && issue.scope?.kind === "rule" && issue.scope.detectorId === rule.id));
  }
});

test("canonical nominal Map and value aliases retain their identities",()=>{
  check(positive.replace("import CompactStandardLibrary;", "import CompactStandardLibrary; new type Admin = Bytes<32>; new type ConfigMap = Map<Bytes<32>,Admin>;").replace("roleAdmin: Map<Bytes<32>, Bytes<32>>", "roleAdmin: ConfigMap").replace("admin: Bytes<32>", "admin: Admin").replace("getRoleAdmin(role: Bytes<32>): Bytes<32>", "getRoleAdmin(role: Bytes<32>): Admin").replace("default<Bytes<32>>", "default<Admin>"),1);
});

test("JSON configuration uses the same selected policy and typed scan path",()=>{
  withFiles({"main.compact":positive,"nightshade.json":JSON.stringify({version:1,detectors:[rule.id],policies})},directory=>{
    const config=readConfiguration(resolve(directory,"nightshade.json"));
    const report=scanFile(resolve(directory,"main.compact"),config.options);
    assert.equal(report.status,"complete",JSON.stringify(report.diagnostics));assert.equal(report.findings.length,1);
  });
});

test("active nonexported setter failures remain root-scoped in no-entrypoint scans",async()=>{
  const directory=mkdtempSync(resolve(tmpdir(),"source-map-no-entry-"));
  try{
    const file=resolve(directory,"main.compact");writeFileSync(file,positive.replaceAll("export circuit", "circuit"));
    const clean=scanFile(file,{detectors:[rule.id]});assert.equal(clean.status,"complete");assert.equal(clean.coverage.noEntrypointRoots.length,1);
    const direct=scanFile(file,{detectors:[rule.id],policies});const worker=await scanFileIsolated(file,{detectors:[rule.id],policies});
    for(const report of [direct,worker]){assert.equal(report.status,"incomplete",JSON.stringify(report.diagnostics));assert.ok(report.diagnostics.some(d=>d.scope?.kind==="rule" && d.scope.detectorId===rule.id && d.scope.entry==="" && d.location.file===file));assert.equal(report.coverage.noEntrypointRoots.length,0);}
  }finally{rmSync(directory,{recursive:true,force:true});}
});

test("matching refuses wrong entry identities and lost original history inventories",()=>{
  const program=new Program(frozen("positive")),claim=prepareSourceMapGetters(program,[contract],()=>true)[0];
  for(const corrupt of ["setter-entry","getter-entry","setter-inventory","history-row"]){
    const setter=new Dataflow(program).analyzeMapGetterEntry(claim.setter),facts=new Dataflow(program).analyzeMapGetterEntry(claim.getter);
    facts.sourceMapGetterEvidence={claim,setterPaths:setter.paths,setterHistories:setter.paths.length,getterClosure:"complete-without-selected-root-read",maxSteps:40000,maxValues:50000};
    if(corrupt==="setter-entry")setter.paths[0].entry=claim.getter;
    if(corrupt==="getter-entry")facts.paths[0].entry=claim.setter;
    if(corrupt==="setter-inventory")facts.sourceMapGetterEvidence.setterHistories++;
    if(corrupt==="history-row")delete facts.paths[0].sourceClaimHistory;
    assert.equal(rule.run(facts).length,0);assert.ok(facts.diagnostics.some(d=>d.code==="source-map-getter-evidence-unavailable"));
  }
});
