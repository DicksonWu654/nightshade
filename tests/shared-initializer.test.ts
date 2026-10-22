import { onceGateShape } from "../src/dataflow/once-gate-shape.js";
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, symlinkSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, detectors, scanFile, scanFileIsolated } from "../src/index.js";
import { sharedModuleOnceGate as rule } from "../src/detectors/shared-initializer.js";
import { sharedInitializerTargets } from "../src/semantic/shared-initializer.js";
import { withFiles } from "./helpers.js";
const gate = `module Gate { export ledger ready: Boolean; export circuit run(): [] { assert(!ready, "once"); ready = true; } }`;
const source = `import CompactStandardLibrary;
module A { import "Gate" prefix G_; export circuit go(): [] { G_run(); } }
module B { import "Gate" prefix G_; export circuit go(): [] { G_run(); } }
import A prefix A_; import B prefix B_;
export circuit first(): [] { A_go(); } export circuit second(): [] { B_go(); }`;
function fixture(files: Record<string,string>, expected: number, gap = false, setup?: (directory:string)=>void) {
  withFiles(files,directory=>{
    setup?.(directory); const program=new Program(resolve(directory,"main.compact")); let oracle: unknown;
    for(const engine of ["instructions","expressions"] as const) for(const cached of [false,true]) {
      const facts=new Dataflow(program,40000,256,50000,engine,cached,cached).analyze();
      assert.equal(facts.diagnostics.length,0);
      const findings=rule.run(facts); assert.equal(findings.length,expected);
      assert.equal(facts.diagnostics.some(issue=>issue.code==="shared-gate-source-unavailable"),gap);
      oracle??=findings; assert.deepEqual(findings,oracle);
      for(const finding of findings) { assert.equal(finding.severity,"info"); assert.equal(finding.metadata.initializationIntent,"unknown"); }
    }
  });
}
test("owned shared-initializer triplet preserves shared identity and distinct local flags",()=>{
  for(const [variant,expected] of [["positive",1],["corrected",0],["lookalike",0]] as const) {
    const directory="tests/corpus/synthetic-regressions/state16/";
    const files:Record<string,string>={"main.compact":readFileSync(directory+`shared-module-once-gate-case-77-${variant}.compact`,"utf8")};
    if(variant==="positive") files["shared-module-once-gate-case-77-positive/security/Initializable.compact"]=readFileSync(directory+"shared-module-once-gate-case-77-positive/security/Initializable.compact","utf8");
    fixture(files,expected);
  }
});
test("names do not establish identity or intent; one wrapper alias is quiet",()=>{
  fixture({"main.compact":source,"Gate.compact":gate},1);
  fixture({"main.compact":source.replace('module B { import "Gate" prefix G_; export circuit go(): [] { G_run(); } }','').replace('import B prefix B_;','import A prefix B_;'),"Gate.compact":gate},0);
  fixture({"main.compact":source.replace('module B { import "Gate" prefix G_; export circuit go(): [] { G_run(); } }','module B { ledger ready: Boolean; export circuit go(): [] { assert(!ready,"own"); ready = true; } }'),"Gate.compact":gate},0);
});
test("separate compiler path identities do not merge symlinked physical bytes",()=>{
  fixture({"main.compact":source.replace('module B { import "Gate"','module B { import "alias/Gate"'),"Gate.compact":gate},0,false,directory=>symlinkSync(directory,resolve(directory,"alias"),"dir"));
});
test("aborted, conditional and shadow-local gate shapes diagnose",()=>{
  fixture({"main.compact":source,"Gate.compact":gate.replace('ready = true;','ready = true; assert(false,"abort");')},0,true);
  fixture({"main.compact":source.replace('G_run();','if (true) { G_run(); }'),"Gate.compact":gate},0,true);
  fixture({"main.compact":source,"Gate.compact":gate.replace('assert(!ready, "once");','{ const ready = false; assert(!ready, "local"); }')},0,true);
});
test("bounded traversal reports gaps and registered opt-in API matches",async()=>{
  assert.ok(detectors.includes(rule)); assert.equal(rule.defaultEnabled,false);
  const file=resolve("tests/corpus/synthetic-regressions/state16/shared-module-once-gate-case-77-positive.compact");
  const program=new Program(file); const bounded=sharedInitializerTargets(program,1);
  assert.equal(bounded.groups.length,0); assert.ok(bounded.gaps.length);
  const direct=scanFile(file,{detectors:[rule.id]}); assert.equal(direct.status,"complete"); assert.equal(direct.findings.length,1);
  const supervised=await scanFileIsolated(file,{detectors:[rule.id]}); assert.equal(supervised.status,"complete"); assert.deepEqual(supervised.findings,direct.findings);
  assert.ok(!scanFile(file).coverage.detectors.includes(rule.id));
});

test("registered source sites and single-wrapper alias control are complete", async () => {
  const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).sharedModuleOnceGate as {
    detector: string; optIn: boolean; cases: { file: string; lines: number[] }[];
  };
  assert.equal(manifest.detector, rule.id);
  assert.equal(manifest.optIn, true);
  for (const item of manifest.cases) {
    const report = await scanFileIsolated(resolve("tests/corpus", item.file), { detectors: [rule.id] });
    assert.equal(report.status, "complete", item.file);
    assert.deepEqual(report.findings.map(finding => finding.location.line), item.lines, item.file);
    assert.equal(report.diagnostics.length, 0, item.file);
  }
});

test("literal message and complete operand shape exclude hidden message transfers",()=>{
  withFiles({"main.compact":source,"Gate.compact":gate},directory=>{
    const program=new Program(resolve(directory,"main.compact"));
    const target=sharedInitializerTargets(program).groups[0]; assert.ok(target);
    const body=program.functions.get(target.gate)!.declaration.body!;
    assert.ok(onceGateShape(body,target.ledger));
    assert.equal(body.kind,"block"); if(body.kind!=="block")return;
    const assertion=body.body[0]; assert.equal(assertion.kind,"expr"); if(assertion.kind!=="expr")return;
    const original=assertion.expr;
    assertion.expr={...original,args:[...original.args,{kind:"call",args:[],name:"messageHelper",symbol:"owned-effectful-message-helper",span:original.span}]};
    assert.equal(onceGateShape(body,target.ledger),undefined);
    const result=sharedInitializerTargets(program); assert.equal(result.groups.length,0); assert.ok(result.gaps.length);
    assertion.expr={...original,assertionMessageLiteral:undefined}; assert.equal(onceGateShape(body,target.ledger),undefined);
  });
  withFiles({"main.compact":source,"Gate.compact":gate.replace('export circuit run()', 'circuit messageHelper(): Opaque<"string"> { ready = true; return "hidden"; } export circuit run()').replace('"once"','messageHelper()')},directory=>{
    const report=scanFile(resolve(directory,"main.compact"),{detectors:[rule.id]});
    assert.equal(report.status,"incomplete"); assert.equal(report.findings.length,0); assert.ok(report.diagnostics.length);
  });
});
