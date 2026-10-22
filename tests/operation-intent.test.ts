import assert from "node:assert/strict";
import test from "node:test";
import { Ajv } from "ajv";
import { readConfiguration } from "../src/config.js";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { Program, Dataflow, scanFile } from "../src/index.js";
import { resolvePolicies, validatePolicies, type Policies } from "../src/policies.js";
import { intentBooleanRequirements } from "../src/dataflow/operation-intent-booleans.js";
import { merkleDigestKey } from "../src/dataflow/merkle-enforcement.js";
import { operationIntentPolicy as rule } from "../src/detectors/operation-intent.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const directory=resolve("tests/corpus/drafts/operation-intent44");
const policies:Policies={operationIntent:[
  {circuit:"updateDocument",ledgers:["document"],controllerCommitment:"controllerCommitment",nonce:"authorizationNonce",operation:"1",version:"1",
    statement:{self:"selfAddress",operation:"operation",version:"version",nonce:"nonce"},inputs:[{field:"input",parameter:"next",writeValue:"document"}]},
  {circuit:"revokeDocument",ledgers:["document"],controllerCommitment:"controllerCommitment",nonce:"authorizationNonce",operation:"2",version:"1",
    statement:{self:"selfAddress",operation:"operation",version:"version",nonce:"nonce"},inputs:[{field:"input",ledger:"document"}]},
]};
function analyze(file:string) {
  const program=new Program(file,[],undefined,undefined,3,"0.34.0");
  const selected=resolvePolicies(program,policies);
  let previous:unknown;
  for(const engine of ["instructions","expressions"] as const) for(const cached of [false,true]) {
    const observed=[];
    for(const policy of selected.operationIntent!) {
      const facts=new Dataflow(program,40000,256,50000,engine,cached,cached).analyzeOperationIntentEntry(policy.circuit);
      assert.equal(facts.diagnostics.length,0);
      const findings=rule.run(facts,selected);
      assert.equal(facts.diagnostics.length,0);
      observed.push(findings.map(f=>f.metadata!.missing));
    }
    if(previous) assert.deepEqual(observed,previous); previous=observed;
  }
  return previous as string[][][];
}
function fixture(source:string,check:(file:string)=>void) {
  withFiles({"main.compact":source},root=>{
    const file=resolve(root,"main.compact");
    if(process.env.COMPACTC_TEST) {const compiled=validateWithCompiler(process.env.COMPACTC_TEST,file,[],30000,3,"0.34.0");assert.equal(compiled.valid,true,compiled.error);}
    check(file);
  });
}
const corrected=()=>readFileSync(resolve(directory,"corrected.compact"),"utf8");
test("operation intent complete owned triplet and both engines/cache modes",()=>{
  assert.deepEqual(analyze(resolve(directory,"corrected.compact")),[[],[]]);
  assert.deepEqual(analyze(resolve(directory,"lookalike.compact")),[[],[]]);
  assert.ok(analyze(resolve(directory,"positive.compact")).every(entry=>entry.length>0));
});
const sourceExpectations: {
  detector: string; compiler: "0.34.0"; zkirVersion: 3; policies: Policies;
  cases: { file: string; lines: number[] }[];
} = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).operationIntentPolicy44;
for (const expectation of sourceExpectations.cases) test(`operation intent source-defined sites: ${expectation.file}`, () => {
  const file = resolve("tests/corpus", expectation.file);
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, sourceExpectations.zkirVersion, sourceExpectations.compiler);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const report = scanFile(file, { detectors: [sourceExpectations.detector], policies: sourceExpectations.policies,
    compilerVersion: sourceExpectations.compiler, zkirVersion: sourceExpectations.zkirVersion });
  assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
  assert.deepEqual(report.diagnostics, []);
  assert.deepEqual(report.findings.map(finding => finding.location.line), expectation.lines);
  assert.ok(report.findings.every(finding => finding.severity === "info"));
});
for(const [name,expected] of [
  ["missing-canonical-self","canonical-self"],["missing-version","version"],["wrong-operation-tag","operation"],
  ["missing-nonce-binding","current-nonce"],["stale-constant-nonce","current-nonce"],
  ["missing-actual-input","input:input"],["wrong-revoke-input","input:input"],
  ["absent-nonce-consumption-update","nonce-consumption"],["absent-nonce-consumption-revoke","nonce-consumption"],
  ["unenforced-verifier","enforced-operation-signature"],
] as const) test(`operation intent ${name}`,()=>{
  const rows=analyze(resolve(directory,"boundaries",`${name}.compact`));assert.ok(rows.flat(2).includes(expected));
});
test("operation intent signed input must equal actual protected write",()=>fixture(corrected().replace("document = disclose(next);","document = 7 as Field;"),file=>{
  assert.ok(analyze(file).flat(2).includes("write-value:input"));
}));
test("operation intent different supplied verifier key is not registered key",()=>fixture(corrected().replace("controllerSignature(), pk)","controllerSignature(), controllerKey())"),file=>{
  assert.ok(analyze(file).flat(2).includes("registered-key"));
}));
test("operation intent late checks cannot authorize earlier writes",()=>fixture(corrected().replace("authorize(1 as Uint<8>, next);\n  document = disclose(next);","document = disclose(next);\n  authorize(1 as Uint<8>, next);"),file=>{
  assert.ok(analyze(file).flat(2).includes("enforced-operation-signature"));
}));
test("operation intent source-wide reset writers are incomplete",()=>{
  const result=scanFile(resolve(directory,"boundaries/reset-writer.compact"),{detectors:[rule.id],policies,compilerVersion:"0.34.0",zkirVersion:3});
  assert.equal(result.status,"incomplete");assert.ok(result.diagnostics.some(issue=>issue.code==="operation-intent-undeclared-writer"));
});
test("operation intent malformed and unresolved policy selectors reject",()=>{
  const program=new Program(resolve(directory,"corrected.compact"),[],undefined,undefined,3,"0.34.0");
  const location=program.rootSource.ast.span;
  const first=policies.operationIntent![0];
  for(const invalid of [Array(1),[{...first,extra:"unknown"}],[{...first,inputs:[{field:"input",parameter:"next"}]}],[{...first,inputs:[{field:"nonce",parameter:"next",writeValue:"document"}]}],[{...first,operation:"-1"}]])
    assert.throws(()=>validatePolicies({operationIntent:invalid},location));
  assert.throws(()=>resolvePolicies(program,{operationIntent:[{...first,circuit:"absent"}]}));
  assert.throws(()=>resolvePolicies(program,{operationIntent:[{...first,nonce:"document"}]}));
  assert.throws(()=>resolvePolicies(program,{operationIntent:[{...first,inputs:[{field:"input",parameter:"absent",writeValue:"document"}]}]}));
  assert.throws(()=>resolvePolicies(program,{operationIntent:[first,{...policies.operationIntent![1],operation:"1"}]}));
});
test("operation intent work and cumulative values never quietly drop proof",()=>{
  const file=resolve(directory,"corrected.compact");
  for(const budget of [{maxSteps:1},{maxValues:1},{maxSteps:500},{maxValues:30}]) {
    const result=scanFile(file,{detectors:[rule.id],policies,compilerVersion:"0.34.0",zkirVersion:3,...budget});
    assert.equal(result.status,"incomplete");assert.ok(result.diagnostics.length);
  }
});
test("operation intent public policy scan complete and ordinary metadata remains absent",()=>{
  const file=resolve(directory,"corrected.compact");
  const result=scanFile(file,{detectors:[rule.id],policies,compilerVersion:"0.34.0",zkirVersion:3});
  assert.deepEqual(result.diagnostics,[]);assert.deepEqual(result.findings,[]);
  const ordinary=new Dataflow(new Program(file,[],undefined,undefined,3,"0.34.0")).analyze();
  assert.equal(ordinary.operationIntentEvidence,undefined);
  assert.ok(!JSON.stringify(ordinary.paths).includes('"numericExpression"'));
  assert.ok(!JSON.stringify(ordinary.paths).includes('"kernelSelf"'));
});
test("operation intent opposite branches cannot donate signature fields",()=>fixture(corrected().replace("updateDocument(next: Field)","updateDocument(next: Field, flag: Boolean)").replace(
  "authorize(1 as Uint<8>, next);", "const selectedTag = disclose(flag) ? 1 as Uint<8> : 2 as Uint<8>; const selectedInput = disclose(flag) ? 0 as Field : next; authorize(selectedTag, selectedInput);"),file=>{
  const rows=analyze(file);assert.ok(rows.flat(2).includes("operation"));
}));
test("operation intent stale saved nonce revision and multiple consumption are mismatches",()=>fixture(corrected().replace(
  "authorize(1 as Uint<8>, next);", "authorizationNonce = (authorizationNonce + 1) as Uint<64>;\n  authorize(1 as Uint<8>, next);"),file=>{
  assert.ok(analyze(file).flat(2).includes("nonce-consumption"));
}));
test("operation intent opaque verifier message is scoped incomplete",()=>fixture(corrected().replace(
  "keccak256<OperationAuthorization>(statement)", "keccak256<Bytes<32>>(keccak256<OperationAuthorization>(statement))"),file=>{
  const report=scanFile(file,{detectors:[rule.id],policies,compilerVersion:"0.34.0",zkirVersion:3});
  assert.equal(report.status,"incomplete");assert.ok(report.diagnostics.some(issue=>issue.code==="operation-intent-proof-unavailable" && issue.scope?.detectorId===rule.id));
}));
test("operation intent exact signed scalar equality permits a distinct input alias",()=>fixture(corrected()
  .replace("updateDocument(next: Field)","updateDocument(next: Field, signedValue: Field)")
  .replace("authorize(1 as Uint<8>, next);","assert(signedValue == next, \"same input\");\n  authorize(1 as Uint<8>, signedValue);"),file=>{
  assert.deepEqual(analyze(file),[[],[]]);
}));
test("operation intent private reset within a selected entry is not consumption",()=>fixture(corrected().replace(
  "authorizationNonce = (authorizationNonce + 1) as Uint<64>;", "authorizationNonce = 0 as Uint<64>;"),file=>{
  assert.ok(analyze(file).flat(2).includes("nonce-consumption"));
}));
test("operation intent namesake verifier cannot satisfy canonical signature requirement",()=>fixture(corrected().replace(
  "secp256k1EcdsaVerify(keccak256<OperationAuthorization>(statement), controllerSignature(), pk)", "pretendVerify(keccak256<OperationAuthorization>(statement), controllerSignature(), pk)")+
  "\ncircuit pretendVerify(message: Bytes<32>, signature: Secp256k1EcdsaSignature, pk: Secp256k1Point): Boolean { return true; }\n",file=>{
  assert.ok(analyze(file).flat(2).includes("enforced-operation-signature"));
}));
test("operation intent controller digest requires exact canonical vector serialization",()=>fixture(corrected().replace(
  "persistentHash<Vector<2, Secp256k1Base>>([secp256k1PointX(pk), secp256k1PointY(pk)])", "persistentHash<[Secp256k1Base, Secp256k1Base]>([secp256k1PointX(pk), secp256k1PointY(pk)])"),file=>{
  assert.ok(analyze(file).flat(2).includes("registered-key"));
}));
test("operation intent controller enrollment within a protected entry is a mismatch",()=>fixture(corrected().replace(
  "document = disclose(next);", "document = disclose(next);\n  controllerCommitment = controllerId(disclose(controllerKey()));"),file=>{
  assert.ok(analyze(file).flat(2).includes("controller-enrollment-write"));
}));
test("operation intent cached mutation replay retains exact write operands and order",()=>fixture(corrected().replace(
  "document = disclose(next);", "writeDocument(next);\n  writeDocument(next);")+"\ncircuit writeDocument(value: Field): [] { document = disclose(value); }\n",file=>{
  assert.deepEqual(analyze(file),[[],[]]);
  const program=new Program(file,[],undefined,undefined,3,"0.34.0"),selected=resolvePolicies(program,policies);
  const cached=new Dataflow(program,40000,256,50000,"instructions",true,true).analyzeOperationIntentEntry(selected.operationIntent![0].circuit);
  assert.ok(cached.metrics.statefulSummaryHits>0);
}));

test("operation intent configuration and report retain current version contracts",()=>{
  withFiles({"config.json":JSON.stringify({version:1,detectors:[rule.id],policies})},root=>{
    const config=readConfiguration(resolve(root,"config.json"));
    assert.deepEqual(config.options.policies,policies);
  });
  const report=scanFile(resolve(directory,"positive.compact"),{detectors:[rule.id],policies,compilerVersion:"0.34.0",zkirVersion:3});
  assert.equal(report.schemaVersion,"1.6.0");
  const validate=new Ajv({strict:false}).compile(JSON.parse(readFileSync("docs/schema/report.schema.json","utf8")));
  assert.equal(validate(report),true,JSON.stringify(validate.errors));
});
test("operation intent current nonce permits an exact independently supplied signed alias",()=>fixture(corrected()
  .replace("  const statement = OperationAuthorization {", "  const nonceAlias = echoNonce();\n  assert(nonceAlias == authorizationNonce, \"current nonce alias\");\n  const statement = OperationAuthorization {")
  .replace("nonce: authorizationNonce,", "nonce: nonceAlias,")+
  "\nwitness echoNonce(): Uint<64>;\n",file=>{
  assert.deepEqual(analyze(file),[[],[]]);
}));
test("operation intent explicit parameter context cannot substitute for actual write binding",()=>{
  const file=resolve(directory,"corrected.compact"),program=new Program(file,[],undefined,undefined,3,"0.34.0");
  const first=policies.operationIntent![0];
  const selected=resolvePolicies(program,{operationIntent:[{...first,inputs:[{field:"input",parameter:"next",context:true}]},policies.operationIntent![1]]});
  const facts=new Dataflow(program).analyzeOperationIntentEntry(selected.operationIntent![0].circuit);
  assert.ok(rule.run(facts,selected).some(item=>(item.metadata.missing as string[]).includes("undeclared-effect-value")));
  assert.throws(()=>validatePolicies({operationIntent:[{...first,inputs:[{field:"input",parameter:"next",context:true,writeValue:"document"}]}]},program.rootSource.ast.span));
});
function relaySource(assertions: string): string {
  const verification = `  assert(\n    secp256k1EcdsaVerify(keccak256<OperationAuthorization>(statement), controllerSignature(), pk),\n    "operation intent signature"\n  );`;
  return corrected().replace(verification,
    `  const verified = secp256k1EcdsaVerify(keccak256<OperationAuthorization>(statement), controllerSignature(), pk);\n  const relay = booleanRelay();\n  ${assertions}`) + "\nwitness booleanRelay(): Boolean;\n";
}
function relayFixture(assertions: string, check: (file: string) => void) { fixture(relaySource(assertions), check); }
test("operation intent inequality Boolean relay enforces the actual verifier",()=>relayFixture(
  'assert(verified != relay, "opposite"); assert(!relay, "false relay");',file=>{
    assert.deepEqual(analyze(file),[[],[]]);
  }));
test("operation intent negated equality Boolean relay enforces the actual verifier",()=>relayFixture(
  'assert(!verified == relay, "complement"); assert(!relay, "false relay");',file=>{
    assert.deepEqual(analyze(file),[[],[]]);
  }));
test("operation intent opposite inequality relay does not enforce true",()=>relayFixture(
  'assert(verified != relay, "opposite"); assert(relay, "true relay");',file=>{
    assert.ok(analyze(file).every(entry=>entry.flat().includes("enforced-operation-signature")));
  }));
test("operation intent opposite negated relay does not enforce true",()=>relayFixture(
  'assert(!verified == relay, "complement"); assert(relay, "true relay");',file=>{
    assert.ok(analyze(file).every(entry=>entry.flat().includes("enforced-operation-signature")));
  }));

test("operation intent unanchored inequality relay cannot enforce true",()=>relayFixture(
  'assert(verified != relay, "opposite");',file=>{
    assert.ok(analyze(file).every(entry=>entry.flat().includes("enforced-operation-signature")));
  }));
test("operation intent transitive complement relays preserve the exact outcome",()=>relayFixture(
  'const other = booleanRelay(); assert(verified != relay, "opposite"); assert(relay == !other, "complement"); assert(other, "true other");',file=>{
    assert.deepEqual(analyze(file),[[],[]]);
  }));
test("operation intent relay branch truth histories stay separate",()=>relayFixture(
  'if (disclose(relay)) { assert(!verified, "false verification"); } else { assert(verified, "true verification"); }',file=>{
    const rows=analyze(file);assert.ok(rows.every(entry=>entry.length===1 && entry[0].includes("enforced-operation-signature")));
  }));
test("operation intent relay truth after a protected write cannot enforce its signature",()=>fixture(relaySource(
  'assert(verified != relay, "opposite"); return relay;')
  .replace('circuit authorize(operation: Uint<8>, input: Field): []', 'circuit authorize(operation: Uint<8>, input: Field): Boolean')
  .replace('authorize(1 as Uint<8>, next);\n  document = disclose(next);','const gateRelay = authorize(1 as Uint<8>, next);\n  document = disclose(next);\n  assert(!gateRelay, "late relay truth");')
  .replace('authorize(2 as Uint<8>, document);\n  document = document - document;','const gateRelay = authorize(2 as Uint<8>, document);\n  document = document - document;\n  assert(!gateRelay, "late relay truth");'),file=>{
    assert.ok(analyze(file).every(entry=>entry.flat().includes("enforced-operation-signature")));
  }));
test("operation intent relay enforcement survives actual cached mutation replay",()=>fixture(relaySource(
  'assert(verified != relay, "opposite"); assert(!relay, "false relay");')
  .replace('document = disclose(next);','writeDocument(next);\n  writeDocument(next);')+
  '\ncircuit writeDocument(value: Field): [] { document = disclose(value); }\n',file=>{
    assert.deepEqual(analyze(file),[[],[]]);
    const program=new Program(file,[],undefined,undefined,3,"0.34.0"),selected=resolvePolicies(program,policies);
    const facts=new Dataflow(program,40000,256,50000,"instructions",true,true).analyzeOperationIntentEntry(selected.operationIntent![0].circuit);
    assert.ok(facts.metrics.statefulSummaryHits>0);
  }));

test("operation intent parity visits and retained evidence share exact proof budgets",()=>relayFixture(
  'assert(verified != relay, "opposite"); assert(!relay, "false relay");',file=>{
    const program=new Program(file,[],undefined,undefined,3,"0.34.0"),selected=resolvePolicies(program,policies);
    for(const engine of ["instructions","expressions"] as const) for(const cached of [false,true]) {
      const facts=new Dataflow(program,40000,256,50000,engine,cached,cached).analyzeOperationIntentEntry(selected.operationIntent![0].circuit);
      const path=facts.paths[0],predicates=path.predicates!.filter(predicate=>predicate.writesBefore===0);
      let work=0,values=0;
      const exact=intentBooleanRequirements(predicates,(w,v)=>{work+=w;values+=v;});
      const result=path.operations!.find(operation=>operation.name==="standard-library::secp256k1EcdsaVerify")!.result;
      assert.ok(exact.trueKeys().has(merkleDigestKey(result)!));
      for(const limit of [{work:work-1,values},{work,values:values-1}]) {
        let visits=0,retained=0;
        assert.throws(()=>intentBooleanRequirements(predicates,(w,v)=>{
          visits+=w;retained+=v;
          if(visits>limit.work || retained>limit.values) throw new Error("proof allowance");
        }).trueKeys(),/proof allowance/);
      }
      facts.operationIntentEvidence!.maxSteps=facts.metrics.steps+1;
      assert.deepEqual(rule.run(facts,selected),[]);
      assert.ok(facts.diagnostics.some(issue=>issue.code==="operation-intent-proof-unavailable" && issue.scope?.entry===selected.operationIntent![0].circuit));
    }
  }));
test("operation intent nested Boolean comparison relays retain required truth",()=>relayFixture(
  'const relation = verified != relay; const anchor = booleanRelay(); assert(relation == anchor, "relation relay"); assert(anchor, "true relation"); assert(!relay, "false relay");',file=>{
    assert.deepEqual(analyze(file),[[],[]]);
  }));
test("operation intent unsupported aggregate Boolean enforcement is scoped incomplete",()=>fixture(relaySource(
  'const actual = BoolRelayPair { first: verified, second: relay }; const required = BoolRelayPair { first: true, second: false }; assert(actual == required, "aggregate outcome");')+
  '\nstruct BoolRelayPair { first: Boolean; second: Boolean; }\n',file=>{
    const program=new Program(file,[],undefined,undefined,3,"0.34.0"),selected=resolvePolicies(program,policies);
    for(const engine of ["instructions","expressions"] as const) for(const cached of [false,true]) {
      const facts=new Dataflow(program,40000,256,50000,engine,cached,cached).analyzeOperationIntentEntry(selected.operationIntent![0].circuit);
      assert.equal(facts.diagnostics.length,0);
      assert.deepEqual(rule.run(facts,selected),[]);
      assert.ok(facts.diagnostics.some(issue=>issue.code==="operation-intent-proof-unavailable" && issue.scope?.entry===selected.operationIntent![0].circuit),JSON.stringify(facts.diagnostics));
    }
  }));
