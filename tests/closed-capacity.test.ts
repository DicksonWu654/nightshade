import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { closedMembershipCapacityReview as rule } from "../src/detectors/closed-capacity.js";
import { closedCapacityScope } from "../src/semantic/closed-capacity.js";
import { withFiles } from "./helpers.js";
const header = `import CompactStandardLibrary; export ledger members:Set<Bytes<32>>; export ledger actions:Counter;
constructor(seed:Bytes<32>){ members.insert(disclose(seed)); }
export circuit act(a:Bytes<32>,b:Bytes<32>):[]{ assert(a != b,"distinct"); assert(members.member(disclose(a)),"a"); assert(members.member(disclose(b)),"b"); actions.increment(1); }`;
test("closed Set conflict preserves both engines and cache modes", () => {
  withFiles({"main.compact":header}, directory => {
    const program = new Program(resolve(directory,"main.compact"));
    const closure = closedCapacityScope(program,()=>{}), entry = [...closure.entries][0];
    let oracle:unknown;
    for (const engine of ["instructions","expressions"] as const) for (const cached of [false,true]) {
      const facts = new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,false,"all",false,true,false,false).analyzeConfiguredCapacityEntry(entry);
      facts.closedCapacity = {writers:closure.writers}; const findings = rule.run(facts);
      assert.equal(facts.diagnostics.length,0,JSON.stringify(facts.diagnostics)); assert.equal(findings.length,1);
      oracle ??= findings; assert.deepEqual(findings,oracle);
    }
    const report = scanFile(resolve(directory,"main.compact"),{detectors:[rule.id]});
    assert.equal(report.status,"complete",JSON.stringify(report.diagnostics)); assert.equal(report.findings.length,1);
    assert.equal(report.findings[0].severity,"info"); assert.ok(!scanFile(resolve(directory,"main.compact")).coverage.detectors.includes(rule.id));
  });
});
test("every subsequent writer blocks the certificate, including unused and empty callback writers", () => {
  for (const extra of [
    `export circuit configure(x:Bytes<32>):[]{members.insert(disclose(x));}`,
    `export circuit configure(x:Bytes<32>):[]{members.remove(disclose(x));}`,
    `circuit write(x:Bytes<32>):Boolean {members.insert(disclose(x));return true;} export circuit configure():[]{map(write,[] as Vector<0,Bytes<32>>);}`,
    `circuit write(x:Bytes<32>):[]{members.insert(disclose(x));} export circuit configure(x:Bytes<32>):[]{write(x);}`,
  ]) withFiles({"main.compact":header+extra},directory=>{
    const report=scanFile(resolve(directory,"main.compact"),{detectors:[rule.id]});
    assert.equal(report.status,"complete",JSON.stringify(report.diagnostics));assert.equal(report.findings.length,0);
  });
});
test("frozen native constructor histories keep exact positive and quiet controls", () => {
  for(const variant of ["positive","corrected","lookalike"] as const) {
    const report=scanFile(resolve("tests/corpus/synthetic-regressions/state16",`configured-membership-capacity-review-case-43-native-${variant}.compact`),{detectors:[rule.id],compilerVersion:"0.34.0",zkirVersion:3});
    assert.equal(report.status,"complete",JSON.stringify(report.diagnostics));assert.equal(report.findings.length,variant==="positive"?1:0);
    if(variant==="positive")assert.equal(report.findings[0].location.line,82);
  }
});
test("closure and cumulative values refuse without emitting findings", () => {
  withFiles({"main.compact":header},directory=>{
    for(const budget of [{maxSteps:1},{maxValues:1}]) {
      const report=scanFile(resolve(directory,"main.compact"),{detectors:[rule.id],...budget});
      assert.equal(report.status,"incomplete");assert.equal(report.findings.length,0);assert.ok(report.diagnostics.some(d=>d.scope?.kind==="rule" && d.scope.detectorId===rule.id));
    }
  });
});

test("constructor path exhaustion stays rule-scoped",()=>{
  withFiles({"main.compact":header.replace("constructor(seed:Bytes<32>){ members.insert(disclose(seed)); }","constructor(seed:Bytes<32>,choose:Boolean){ if(disclose(choose)){members.insert(disclose(seed));} }")},directory=>{
    const report=scanFile(resolve(directory,"main.compact"),{detectors:[rule.id],maxPaths:1});
    assert.equal(report.status,"incomplete");assert.equal(report.findings.length,0);assert.ok(report.diagnostics.some(d=>d.scope?.kind==="rule" && d.scope.detectorId===rule.id));
  });
});

test("an unused checkpoint entry refuses the whole source certificate",()=>{
  withFiles({"main.compact":header+`export circuit other():[]{kernel.checkpoint();}`},directory=>{
    const report=scanFile(resolve(directory,"main.compact"),{detectors:[rule.id]});
    assert.equal(report.status,"incomplete");assert.equal(report.findings.length,0);assert.ok(report.diagnostics.some(d=>d.code==="closed-capacity-closure-unavailable"));
  });
});
test("closure failure is discovered once then propagated to all exported entries",()=>{
  const many=Array.from({length:30},(_,i)=>`export circuit other${i}():[]{}`).join("\n");
  withFiles({"main.compact":header+many},directory=>{
    const program=new Program(resolve(directory,"main.compact"));let calls=0;
    assert.throws(()=>closedCapacityScope(program,()=>{if(++calls>5)throw new Error("bounded");}),/bounded/);assert.equal(calls,6);
    const report=scanFile(resolve(directory,"main.compact"),{detectors:[rule.id],maxSteps:5});
    const failures=report.diagnostics.filter(d=>d.code==="closed-capacity-closure-unavailable");
    assert.equal(failures.length,31);assert.equal(report.findings.length,0);
    assert.ok(report.ruleObservationWork!.find(w=>w.detectorId===rule.id)!.metrics.steps<=5);
  });
});

test("explicitly disabled continuation retains the source cardinality contradiction",()=>{
  withFiles({"main.compact":header.replace("actions.increment(1);","assert(false,\"disabled\"); actions.increment(1);")},directory=>{
    const report=scanFile(resolve(directory,"main.compact"),{detectors:[rule.id]});
    assert.equal(report.status,"complete",JSON.stringify(report.diagnostics));assert.equal(report.findings.length,1);
  });
});
