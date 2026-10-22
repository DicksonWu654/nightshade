import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { reserveRefundEndpointFinding } from "../src/detectors/refund-endpoint.js";
import { discoverRefundEndpoints } from "../src/semantic/refund-endpoint.js";
import { certifyRefundEndpoint } from "../src/dataflow/refund-endpoint.js";
import assert from "node:assert/strict";
import test from "node:test";
import { relative, resolve } from "node:path";
import { symlinkSync } from "node:fs";
import { Program, scanFile } from "../src/index.js";
import { withFiles } from "./helpers.js";
import { observeRefundEndpoints } from "../src/analysis/refund-endpoint-observation.js";
import { unshieldedRefundEndpointReview as rule } from "../src/detectors/refund-endpoint.js";
const validator = `pure circuit verify(b:Uint<128>,p:Uint<128>,a:Uint<128>,q:Uint<128>):Boolean {
 assert(a>0,"a");assert(p<=a,"p");assert(b<=17592186044415,"b");assert(q<=17592186044415,"q");
 assert(p<=1099511627775,"p");assert(a<=1099511627775,"a");
 const bn=b as Uint<44>;const pn=p as Uint<40>;const an=a as Uint<40>;const qn=q as Uint<44>;
 const bp=((bn as Uint<84>)*(pn as Uint<84>)) as Uint<84>;
 const qa=((qn as Uint<84>)*(an as Uint<84>)) as Uint<84>;
 const next=((qa as Uint<85>)+(an as Uint<85>)) as Uint<85>;
 return (qa as Uint<85>)<=(bp as Uint<85>) && (bp as Uint<85>)<next;
}`;
const caller = `export circuit entry(b:Uint<128>,p:Uint<128>,a:Uint<128>,q:Uint<128>,color:Bytes<32>,dest:Either<ContractAddress,UserAddress>):[]{
 assert(verify(b,p,a,q),"formula"); const remainder=(b-q) as Uint<128>;
 sendUnshielded(disclose(color),disclose(remainder),disclose(dest));
}`;
const source = `pragma language_version >=0.23;import CompactStandardLibrary;${validator}${caller}`;
function check(text: string, count: number, incomplete = false, limits = {}) {
 withFiles({"main.compact":text}, dir => {
  const program = new Program(resolve(dir,"main.compact")); const result = observeRefundEndpoints(program,rule,limits);
  assert.equal(result.findings.length,count,JSON.stringify(result.diagnostics));
  assert.equal(result.diagnostics.length>0,incomplete,JSON.stringify(result.diagnostics));
  if(count) {assert.equal(result.coverage[0].evidence,"source-local-formula");assert.equal(result.findings[0].metadata.successfulHistory,"not-certified");}
 });
}
test("complete bounded formula endpoint is source-local and opt-in",()=>{check(source,1);assert.equal(rule.defaultEnabled,false);});
test("every pure assertion constrains selected witness",()=>check(source.replace('const bn=', 'assert(q<b,"strict");const bn='),0));
test("caller strict and late arithmetic constraints suppress selected witness",()=>{
 check(source.replace('const remainder=', 'assert(q<b,"strict");const remainder='),0);
 check(source.replace('disclose(dest));','disclose(dest));assert(q<b,"late");'),0);
});
test("unsupported pure body cannot donate partial formula",()=>check(source.replace('const bn=', 'if(b>0){assert(p<=a,"extra");}const bn='),0,true));
test("wrong formula and raw send are outside supported proposition",()=>{
 check(source.replace('&& (bp as Uint<85>)<next','&& (bp as Uint<85>)<=next'),0);
 check(source.replace('disclose(remainder)','disclose(q)'),0);
});
test("shared source certificate budget refuses without partial findings",()=>check(source,0,true,{maxSteps:10}));
test("source-local observation does not require baseline successful histories",()=>{
 withFiles({"main.compact":source},dir=>{
  const file=resolve(dir,"main.compact");const result=scanFile(file,{detectors:[rule.id],maxSteps:1});
  assert.equal(result.status,"incomplete");assert.ok(result.diagnostics.length);
 });
});
test("compiler-valid independent owned primary controls qualify only remainder sites",()=>{
 for(const [name,count] of [["positive",1],["intentional",1],["corrected",0],["lookalike",0],["alias-exact",1]] as const) {
  const program=new Program(resolve(`tests/corpus/drafts/arithmetic-endpoint57/${name}.compact`));
  const result=observeRefundEndpoints(program,rule,{});
  assert.equal(result.findings.length,count,`${name}: ${JSON.stringify(result.diagnostics)}`);
  assert.equal(result.diagnostics.length,0,`${name}: ${JSON.stringify(result.diagnostics)}`);
 }
});
test("all four actual roles and nested late constraints are checked",()=>{
 check(source.replace('const remainder=', 'assert(p<a,"strict");const remainder='),0);
 check(source.replace('disclose(dest));','disclose(dest));if(q==b){assert(q<b,"late");}'),0);
 check(source.replace('disclose(dest));','disclose(dest));const later=q;assert(later<b,"late");'),0);
});
test("relevant opaque pure checker cannot be silently omitted",()=>{
 const extra='pure circuit strict(x:Uint<128>,y:Uint<128>):Boolean{return x<y;}';
 check(source.replace(validator,validator+extra).replace('const remainder=', 'assert(strict(q,b),"strict");const remainder='),0,true);
});
test("loop-only validator does not dominate the after-loop send",()=>{
 check(source.replace('assert(verify(b,p,a,q),"formula");','for(const i of 0..1){assert(verify(b,p,a,q),"formula");}'),0);
});
test("raw ledger reads are not lexical snapshots and snapshots across writes stay distinct",()=>{
 const ledger='export ledger balance:Uint<128>;';
 check(source.replace(validator,ledger+validator).replace('assert(verify(b,p,a,q),"formula"); const remainder=(b-q)', 'assert(verify(balance,p,a,q),"formula"); const remainder=(balance-q)'),0,true);
 check(source.replace(validator,ledger+validator).replace('assert(verify(b,p,a,q),"formula"); const remainder=(b-q)', 'const saved=balance;assert(verify(saved,p,a,q),"formula");balance=2;const newer=balance; const remainder=(newer-q)'),0);
});
test("failing fixed witness does not imply universal endpoint exclusion",()=>{
 check(source.replace('assert(a>0,"a");','assert(a>1,"a");'),0);
});
test("independent boundary shapes keep the fixed-witness scope explicit",()=>{
 for(const [name,count] of [["branch-partial-guard",1],["map-snapshot-boundary",0],["map-fresh-reads-boundary",0],["unsafe-width-boundary",1],["zero-bond-boundary",1],["p-less-than-a-zero-bond-boundary",0]] as const) {
  const result=observeRefundEndpoints(new Program(resolve(`tests/corpus/drafts/arithmetic-endpoint57/${name}.compact`)),rule,{});
  assert.equal(result.findings.length,count,`${name}: ${JSON.stringify(result.diagnostics)}`);
  assert.equal(result.diagnostics.length,0,`${name}: ${JSON.stringify(result.diagnostics)}`);
 }
});
test("Counter mode explicitly refuses source certificates",()=>{
 withFiles({"main.compact":source},dir=>{
  const result=scanFile(resolve(dir,"main.compact"),{detectors:[rule.id],experimentalCounterQueries:true});
  assert.equal(result.status,"incomplete");assert.ok(result.diagnostics.some(d=>d.code==="refund-endpoint-counter-unavailable"));
  assert.equal(result.findings.length,0);
 });
});
test("all applicable sites refuse together on incomplete pure bodies",()=>{
 const text=source.replace(validator,validator+validator.replace('verify(', 'bad(').replace('const bn=', 'if(b>0){assert(p<=a,"extra");}const bn='))
   .replace('disclose(dest));','disclose(dest));assert(bad(b,p,a,q),"bad");sendUnshielded(disclose(color),disclose(remainder),disclose(dest));');
 check(text,0,true);
});
test("cumulative source value allowance remains exhausted across entries",()=>{
 check(source,0,true,{maxValues:1});
});
test("baseline budget diagnostics coexist with an independently complete local certificate",()=>{
 const text=source.replace(validator,'export ledger count:Counter;circuit slow():[]{for(const i of 0..200){count.increment(1);}}'+validator).replace('assert(verify(b,p,a,q),"formula");','slow();assert(verify(b,p,a,q),"formula");');
 withFiles({"main.compact":text},dir=>{
  const result=scanFile(resolve(dir,"main.compact"),{detectors:[rule.id],maxSteps:1000});
  assert.equal(result.status,"incomplete",JSON.stringify(result.diagnostics));assert.ok(result.diagnostics.length);
  assert.equal(result.findings.length,1,JSON.stringify(result.diagnostics));
  assert.ok(result.coverage.rules?.some(row=>row.detectorId===rule.id && row.evidence==="source-local-formula"));
 });
});
test("nonempty relevant loop constraints refuse and empty loops donate no checks",()=>{
 check(source.replace('const remainder=', 'for(const i of 0..1){assert(q<b,"loop");}const remainder='),0,true);
 check(source.replace('disclose(dest));','disclose(dest));for(const i of 0..1){assert(q<b,"loop");}'),0,true);
 check(source.replace('const remainder=', 'for(const i of 0..0){assert(q<b,"loop");}const remainder='),1);
});
test("oversized source literals retain the global source-type diagnostic",()=>{
 withFiles({"main.compact":source.replace('assert(a>0,"a");',`assert(a>0,"a");assert(b<=${'9'.repeat(100)},"large");`)},dir=>{
  const result=scanFile(resolve(dir,"main.compact"),{detectors:[rule.id]});
  assert.equal(result.status,"incomplete");assert.ok(result.diagnostics.some(d=>d.code==="literal-range"));assert.equal(result.findings.length,0);
 });
});
test("later live ledger P/A reads cannot reuse the selected argument snapshot",()=>{
 const text=source.replace(validator,'export ledger allocation:Uint<128>;'+validator)
  .replace('verify(b,p,a,q),"formula"','verify(b,p,allocation,q),"formula"').replace('const remainder=', 'assert(allocation>0,"later read");const remainder=');
 check(text,0,true);
});

test("source-discovery and issued certificate principals resist fabricated carriers",()=>{
 withFiles({"main.compact":source},dir=>{
  const program=new Program(resolve(dir,"main.compact"));
  const candidates=discoverRefundEndpoints(program,program.entries[0],()=>{});
  assert.throws(()=>certifyRefundEndpoint(program,{...candidates[0]},()=>{}),/attestation/);
  const certificate=candidates.map(candidate=>certifyRefundEndpoint(program,candidate,()=>{})).find(Boolean)!;
  assert.ok(Object.isFrozen(certificate));assert.ok(Object.isFrozen(certificate.candidate));assert.ok(Object.isFrozen(certificate.witness));
  assert.equal(Reflect.set(certificate,"formula","forged"),false);
  assert.equal(Reflect.set(certificate.candidate,"entry","other"),false);
 });
});
test("original frozen raw-parameter and literal-zero sites remain outside the new source theorem",()=>{
 const program=new Program(resolve("tests/corpus/known-bugs/counter-zero-unshielded-send-positive.compact"));
 const result=observeRefundEndpoints(program,rule,{});assert.equal(result.findings.length,0);assert.equal(result.diagnostics.length,0);
});

test("CLI detector show reads the relocated endpoint documentation",()=>{
 const output=execFileSync(process.execPath,[resolve("dist/src/cli.js"),"detector","show",rule.id,"--json"],{encoding:"utf8"});
 assert.match(output,/selected formal witness/);
});
test("emission reservation grows with imported file inventory and pathname size",()=>{
 withFiles({"main.compact":source},dir=>{
  const program=new Program(resolve(dir,"main.compact"));
  const candidate=discoverRefundEndpoints(program,program.entries[0],()=>{});
  const certificate=candidate.map(item=>certifyRefundEndpoint(program,item,()=>{})).find(Boolean)!;
  const measure=()=>{let steps=0,values=0;reserveRefundEndpointFinding(program,certificate,(work=1,retained=0)=>{steps+=work;values+=retained;});return {steps,values};};
  const original=measure(); const extra=resolve(dir,"x".repeat(180)+".compact");
  program.files.set(extra,program.files.values().next().value!);
  const expanded=measure();assert.ok(expanded.steps>original.steps);assert.ok(expanded.values>original.values);
  assert.throws(()=>reserveRefundEndpointFinding(program,certificate,(work=1)=>{if(work>4)throw new Error("exhausted before allocation");}),/exhausted/);
 });
});
test("mutating public discovery bindings cannot bypass a privately captured rejecting guard",()=>{
 withFiles({"main.compact":source.replace('const remainder=', 'const reject=q<b;assert(reject,"reject");const remainder=')},dir=>{
  const program=new Program(resolve(dir,"main.compact"));const candidates=discoverRefundEndpoints(program,program.entries[0],()=>{});
  for(const candidate of candidates){
   const mutable=candidate.bindings as Map<string,import("../src/model.js").Expr>;
   for(const [symbol,expr] of mutable)if(expr.kind==="binary"&&expr.name==="<")mutable.set(symbol,{kind:"literal",value:"true",args:[],span:expr.span});
   assert.equal(certifyRefundEndpoint(program,candidate,()=>{}),undefined);
  }
 });
});

test("refund fingerprint reservation treats pathname dollar sequences literally", context=>{
 const identifier="e".repeat(4096);
 const amounts:number[]=[];
 for(const token of ["plain", "$'"]) {
  const filename=`prefix${token.repeat(40)}.compact`;
  withFiles({[filename]:source.replace("export circuit entry(", `export circuit ${identifier}(`)},dir=>{
   const program=new Program(resolve(dir,filename));
   const certificate=discoverRefundEndpoints(program,program.entries[0],()=>{})
    .map(candidate=>certifyRefundEndpoint(program,candidate,()=>{})).find(Boolean)!;
   assert.ok(certificate);
   let values=0;
   const reserve=()=>reserveRefundEndpointFinding(program,certificate,(_work=1,retained=0)=>{
    values+=retained;if(values>20000)throw new Error("allowance exhausted");
   });
   assert.doesNotThrow(reserve);
   amounts.push(values);
   const result=observeRefundEndpoints(program,rule,{});
   context.diagnostic(JSON.stringify({token,values,findings:result.findings.length,diagnostics:result.diagnostics.map(d=>d.code)}));
   assert.equal(result.findings.length,1);
   assert.equal(result.diagnostics.length,0);
  });
 }
 assert.deepEqual(amounts,[amounts[0],amounts[0]]);
});

test("overlapping pathname replacement keeps one source identifier in the fingerprint",()=>{
 const identifier="e".repeat(4096), suffix="prefix"+("$&$'".repeat(3))+".compact";
 const root=suffix+".root.compact";
 const text=`import CompactStandardLibrary; import "Other";${validator}${caller}`
   .replace("export circuit entry(",`export circuit ${identifier}(`);
 withFiles({[suffix]:"module Other { export circuit get():Field{return 1;} }",[root]:text},dir=>{
  symlinkSync(resolve(dir,suffix),resolve(dir,"Other.compact"));
  const file=resolve(dir,root), program=new Program(file);
  const certificate=discoverRefundEndpoints(program,program.entries[0],()=>{})
   .map(candidate=>certifyRefundEndpoint(program,candidate,()=>{})).find(Boolean)!;
  assert.ok(certificate);
  const result=observeRefundEndpoints(program,rule,{});
  assert.equal(result.findings.length,1,JSON.stringify(result.diagnostics));
  assert.equal(result.diagnostics.length,0);
  let discriminator=`${certificate.candidate.entry}:${certificate.candidate.send.start}`;
  for(const loaded of [...program.files.keys()].sort((a,b)=>b.length-a.length))
   discriminator=discriminator.replaceAll(loaded,()=>relative(program.sourceRoot,loaded));
  assert.equal(discriminator.split(identifier).length-1,1);
  const key=[rule.id,relative(program.sourceRoot,program.root),
   relative(program.sourceRoot,certificate.candidate.send.file),certificate.candidate.send.start,discriminator].join(":");
  assert.equal(result.findings[0].fingerprint,createHash("sha256").update(key).digest("hex"));
 });
});
