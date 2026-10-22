import assert from "node:assert/strict";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile, type CompilerVersion } from "../src/index.js";
import { observeEnrollmentReview } from "../src/analysis/enrollment-review-observation.js";
import type { SuccessfulPath } from "../src/dataflow/index.js";
import { immutableOperandKey } from "../src/dataflow/immutable-key.js";
import { enforcedEqualities } from "../src/dataflow/predicates.js";
import { signatureKeyIdentityExclusions } from "../src/dataflow/signature-key.js";
import { enrollmentReviewScope } from "../src/semantic/enrollment-review.js";
import { storedSchnorrKeyEnrollmentReview as rule } from "../src/detectors/enrollment-review.js";
import { detectors } from "../src/detectors/index.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const header = `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger stored: JubjubPoint;
export ledger other: JubjubPoint;
`;
const writer = `export circuit enroll(pk:JubjubPoint):[] {stored=disclose(pk);}`;
const use = `export circuit use(msg:Vector<1,Field>,sig:JubjubSchnorrSignature):[] {assert(jubjubSchnorrVerify<1>(msg,sig,stored),"signature");}`;
const evidenceBase = process.env.ENROLLMENT44_EVIDENCE;
function fixture(label: string, source: string, run: (file: string, program: Program) => void, version: CompilerVersion = "0.34.0") {
  withFiles({ "main.compact": header + source }, directory => {
    const file = resolve(directory, "main.compact");
    const compiler = version === "0.35.0" ? process.env.COMPACTC_035_TEST : version === "0.35.0-rc.1" ? process.env.COMPACTC_035_RC1_TEST : process.env.COMPACTC_TEST;
    if (compiler) {
      const qualification = validateWithCompiler(compiler, file);
      if (evidenceBase) { mkdirSync(evidenceBase, { recursive: true }); writeFileSync(resolve(evidenceBase, `${label}-${version}.compact`), header + source); writeFileSync(resolve(evidenceBase, `${label}-${version}.json`), JSON.stringify(qualification, null, 2)); }
      assert.equal(qualification.valid, true, qualification.error);
    }
    run(file, new Program(file, [], undefined, undefined, 2, version));
  });
}
function expected(label: string, source: string, count: number, status = "complete", version: CompilerVersion = "0.34.0") {
  fixture(label, source, (file, program) => {
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const result = observeEnrollmentReview(program, rule, {}, undefined, { engine, cached });
      assert.equal(result.findings.length, count, `${label}/${engine}/${cached}: ${JSON.stringify(result.diagnostics)}`);
      assert.equal(result.diagnostics.length === 0, status === "complete", JSON.stringify(result.diagnostics));
      baseline ??= result.findings; assert.deepEqual(result.findings, baseline);
      for (const item of result.findings) {
        assert.equal(item.severity, "info"); assert.equal(item.metadata.sameDeclarationOnly, true);
        assert.equal(item.metadata.crossTransactionEqualityProven, false); assert.equal(item.metadata.signatureResultEnforced, true);
        assert.equal(item.metadata.unsafeEnrollmentProven, false); assert.equal(item.metadata.identityFeasibility, "not-proven");
      }
    }
    const result = scanFile(file, { detectors: [rule.id], compilerVersion: version });
    assert.equal(result.status, status, `${label}: ${JSON.stringify(result.diagnostics)}`);
    assert.equal(result.findings.length, count, label);
    assert.ok(!scanFile(file, { compilerVersion: version }).findings.some(item => item.detectorId === rule.id));
  }, version);
}

test("stored enrollment core requires both the actual writer and enforced exact canonical outcome", () => {
  expected("core", writer + use, 1);
  expected("use-only", use, 0);
  expected("write-only", writer, 0);
  expected("discarded", writer + use.replace('assert(jubjubSchnorrVerify<1>(msg,sig,stored),"signature")', 'jubjubSchnorrVerify<1>(msg,sig,stored)'), 0);
  expected("not-enforced-true", writer + use.replace('assert(jubjubSchnorrVerify<1>', 'assert(!jubjubSchnorrVerify<1>'), 0);
  expected("asserted-conjunction",writer+use.replace('sig,stored),"signature"','sig,stored) && msg[0]!=0 as Field,"signature"'),1);
  expected("boolean-equality", writer + use.replace('sig,stored),"signature"', 'sig,stored) == true,"signature"'), 1);
  expected("exact-forwarder", writer + `circuit check(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean{return jubjubSchnorrVerify<1>(msg,sig,pk);}` + use.replace('jubjubSchnorrVerify<1>(msg,sig,stored)', 'check(msg,sig,stored)'), 1);
  expected("computed-wrapper", writer + `circuit check(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean{jubjubSchnorrVerify<1>(msg,sig,pk);return true;}` + use.replace('jubjubSchnorrVerify<1>(msg,sig,stored)', 'check(msg,sig,stored)'), 0);
});

test("constant outcome parity is exact and unsupported dynamic relays are incomplete", () => {
  expected("boolean-inequality", writer + use.replace('sig,stored),"signature"', 'sig,stored) != false,"signature"'), 1);
  expected("negated-inequality", writer + use.replace('jubjubSchnorrVerify<1>(msg,sig,stored)', '!(jubjubSchnorrVerify<1>(msg,sig,stored) != true)'), 1);
  expected("false-inequality", writer + use.replace('sig,stored),"signature"', 'sig,stored) != true,"signature"'), 0);
  for (const [label, relation, assertion] of [
    ["equal", "==", "relay"], ["unequal", "!=", "!relay"], ["negated-unequal", "!=", "relay"],
  ]) {
    const outcome = label === "negated-unequal" ? "!jubjubSchnorrVerify<1>(msg,sig,stored)" : "jubjubSchnorrVerify<1>(msg,sig,stored)";
    expected(`dynamic-${label}`, writer + `export circuit use(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,relay:Boolean):[]{assert((${outcome}) ${relation} relay,"relation");assert(${assertion},"relay");}`, 0, "incomplete");
  }
});

test("conjunction outcome retention preserves nested comparisons, constants and negations", () => {
  const run = (label: string, gate: string, count: number, status = "complete") => expected(label,
    writer + `export circuit use(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,relay:Boolean):[]{
      const verified=jubjubSchnorrVerify<1>(msg,sig,stored);assert(${gate},"gate");}`, count, status);
  for (const [label, gate] of [
    ["lhs-equal-conjunction", "(verified == relay) && relay"],
    ["lhs-unequal-conjunction", "(verified != relay) && !relay"],
    ["lhs-negated-comparison-conjunction", "!(verified != relay) && relay"],
    ["lhs-negated-outcome-conjunction", "(!verified == relay) && !relay"],
    ["lhs-constant-composed-relay", "((verified == relay) == true) && relay"],
    ["nested-lhs-relay", "((verified == relay) && relay) && (msg[0] != 0 as Field)"],
    ["lhs-relay-with-exact-rhs", "(verified == relay) && verified"],
    ["negated-whole-relay-conjunction", "!((verified == relay) && relay)"],
    ["negated-short-circuit-relay", "!((verified == relay) && false)"],
  ]) run(label, gate, 0, "incomplete");
  for (const [label, gate, count] of [
    ["lhs-true-equality", "(verified == true) && relay", 1],
    ["lhs-false-inequality", "(verified != false) && relay", 1],
    ["lhs-negated-false-equality", "!(verified == false) && relay", 1],
    ["lhs-negated-outcome", "!verified && relay", 0],
    ["lhs-asserted-false-equality", "(verified == false) && relay", 0],
  ] as const) run(label, gate, count);
});

test("aggregate relay comparisons retain represented vector items and struct fields", () => {
  for (const [label, declarations, gate] of [
    ["vector-outcome-relay", "", "[verified] == [relay]"],
    ["nested-vector-outcome-relay", "", "([[verified]] == [[relay]]) && relay"],
    ["struct-outcome-relay", "struct Gate { result:Boolean; }", "Gate { result:verified } == Gate { result:relay }"],
    ["nested-struct-vector-outcome-relay", "struct Gate { result:Vector<1,Boolean>; }", "(Gate { result:[verified] } == Gate { result:[relay] }) && relay"],
  ]) expected(label, declarations + writer + `export circuit use(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,relay:Boolean):[]{
    const verified=jubjubSchnorrVerify<1>(msg,sig,stored);assert(${gate},"relation");assert(relay,"relay");}`, 0, "incomplete");
  expected("unrelated-aggregate-direct-outcome", writer + `export circuit use(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,relay:Boolean):[]{
    const verified=jubjubSchnorrVerify<1>(msg,sig,stored);assert([msg[0] == 0 as Field] == [relay],"message");assert(verified,"signature");}`, 1);
});

test("compound retention keeps exact canonical occurrences and bounded unavailable coverage", () => {
  expected("unrelated-canonical-conjunction", writer + `export circuit use(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint,relay:Boolean):[]{
    const unused=jubjubSchnorrVerify<1>(msg,sig,stored);const unrelated=jubjubSchnorrVerify<1>(msg,sig,pk);assert(unrelated && relay,"gate");}`, 0);
  fixture("compound-relay-budget", writer + `export circuit use(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,relay:Boolean):[]{
    const verified=jubjubSchnorrVerify<1>(msg,sig,stored);assert(([verified] == [relay]) && relay,"gate");}`, (file, program) => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      for (const options of [{}, { maxSteps: 1 }, { maxValues: 1 }, { maxSteps: 200 }, { maxValues: 350 }]) {
        const result=observeEnrollmentReview(program,rule,options,undefined,{engine,cached});
        assert.deepEqual(result.findings,[]);assert.ok(result.diagnostics.length);
        assert.ok(result.coverage.every(row=>row.status==="incomplete" && row.evidence==="unavailable"));
        assert.ok(result.diagnostics.length<=16);
        if(Object.keys(options).length===0)assert.ok(result.diagnostics.some(issue=>issue.message.includes("Dynamic verifier Boolean relay enforcement is unavailable")));
      }
    }
    const ordinary=scanFile(file,{detectors:["identity-signature-key"]});
    const selected=scanFile(file,{detectors:["identity-signature-key",rule.id]});
    assert.equal(selected.status,"incomplete");
    assert.deepEqual(selected.findings.filter(finding=>finding.detectorId!==rule.id),ordinary.findings);
    assert.deepEqual(selected.coverage.completedEntries,ordinary.coverage.completedEntries);
  });
});

test("compiler-qualified owned compound relay controls preserve complete and incomplete boundaries", () => {
  for (const name of ["lhs-inequality-conjunction", "aggregate-equality-relay", "nested-aggregate-conjunction", "unrelated-relay-direct-outcome"]) {
    const file=resolve("tests/corpus/drafts/enrollment44/compound-relays",`${name}.compact`);
    if(process.env.COMPACTC_TEST){
      const compiled=validateWithCompiler(process.env.COMPACTC_TEST,file,[],30000,3,"0.34.0");
      assert.equal(compiled.valid,true,`${name}: ${compiled.error}`);
    }
    const program=new Program(file,[],undefined,undefined,3,"0.34.0"), complete=name==="unrelated-relay-direct-outcome";
    let baseline:unknown;
    for(const engine of ["instructions","expressions"] as const)for(const cached of [false,true]){
      const result=observeEnrollmentReview(program,rule,{},undefined,{engine,cached});
      assert.equal(result.findings.length,complete?1:0,`${name}: ${JSON.stringify(result.diagnostics)}`);
      assert.equal(result.diagnostics.length===0,complete,name);
      if(!complete){
        assert.ok(result.coverage.every(row=>row.status==="incomplete" && row.evidence==="unavailable"));
        assert.ok(result.diagnostics.some(issue=>issue.message.includes("Dynamic verifier Boolean relay enforcement is unavailable")));
      }
      baseline??=result.findings;assert.deepEqual(result.findings,baseline,`${name}/${engine}/${cached}`);
    }
    const result=scanFile(file,{detectors:[rule.id],zkirVersion:3,compilerVersion:"0.34.0"});
    assert.equal(result.status,complete?"complete":"incomplete",name);
    assert.equal(result.findings.length,complete?1:0,name);
  }
});

test("identity guards apply to surviving exact points, including later atomic checks", () => {
  expected("write-guard", writer.replace('stored=', 'assert(pk != default<JubjubPoint>,"point");stored=') + use, 0);
  expected("use-guard", writer + use.replace('assert(jubjub', 'assert(stored != default<JubjubPoint>,"point");assert(jubjub'), 0);
  expected("later-write-guard", writer.replace('stored=disclose(pk);', 'stored=disclose(pk);assert(pk != default<JubjubPoint>,"point");') + use, 0);
  expected("native-write-guard", writer.replace('stored=', 'assert(ecMul(pk,8 as JubjubScalar) != default<JubjubPoint>,"point");stored=') + use, 0);
  expected("unrelated-message", writer + use.replace('assert(jubjub', 'assert(msg[0]!=0 as Field,"message");assert(jubjub'), 1);
  expected("unrelated-old-key", writer.replace('stored=', 'assert(stored != default<JubjubPoint>,"old");stored=') + use, 1);
  expected("other-parameter", `export circuit enroll(a:JubjubPoint,b:JubjubPoint):[]{assert(a!=default<JubjubPoint>,"other");stored=disclose(b);}` + use, 1);
});

test("writer inventory covers replacement, initialization and final overwrite order", () => {
  expected("replacement", writer.replace('stored=', 'assert(pk!=default<JubjubPoint>,"point");stored=') + `export circuit replace(pk:JubjubPoint):[]{stored=disclose(pk);}` + use, 1);
  expected("temporary-overwritten", `export circuit enroll(a:JubjubPoint,b:JubjubPoint):[]{stored=disclose(a);assert(b!=default<JubjubPoint>,"point");stored=disclose(b);}` + use, 0);
  expected("final-unguarded", `export circuit enroll(a:JubjubPoint,b:JubjubPoint):[]{assert(a!=default<JubjubPoint>,"point");stored=disclose(a);stored=disclose(b);}` + use, 1);
  expected("fixed-initialization", `constructor(){stored=ecMulGenerator(1 as JubjubScalar);}` + use, 0);
  expected("unknown-constructor", `constructor(pk:JubjubPoint){stored=disclose(pk);}` + use, 1);
  expected("one-time", `export ledger ready:Boolean;constructor(){ready=false;}export circuit initialize(pk:JubjubPoint):[]{assert(!ready,"once");stored=disclose(pk);ready=true;}` + use, 1);
  expected("branch-unguarded", `export circuit enroll(pk:JubjubPoint,flag:Boolean):[]{if(disclose(flag)){assert(pk!=default<JubjubPoint>,"point");}stored=disclose(pk);}` + use, 1);
  expected("branches-guarded", `export circuit enroll(pk:JubjubPoint,flag:Boolean):[]{if(disclose(flag)){assert(pk!=default<JubjubPoint>,"point");}else{assert(ecNeg(pk)!=default<JubjubPoint>,"point");}stored=disclose(pk);}` + use, 0);
});

test("opaque point checks and committed checkpoints remain incomplete", () => {
  expected("opaque-writer", `witness validPoint(pk:JubjubPoint):Boolean;` + writer.replace('stored=', 'assert(validPoint(pk),"opaque");stored=') + use, 0, "incomplete");
  expected("opaque-use", `witness validPoint(pk:JubjubPoint):Boolean;` + writer + use.replace('assert(jubjub', 'assert(validPoint(stored),"opaque");assert(jubjub'), 0, "incomplete");
  expected("opaque-message", `witness validMessage(msg:Vector<1,Field>):Boolean;` + writer + use.replace('assert(jubjub', 'assert(validMessage(msg),"message");assert(jubjub'), 1);
  expected("opaque-coordinate", writer + use.replace('assert(jubjub', 'assert(jubjubPointX(stored)!=0 as Field,"coordinate");assert(jubjub'), 0, "incomplete");
  expected("checkpoint", writer.replace('stored=disclose(pk);', 'stored=disclose(pk);kernel.checkpoint();') + use, 0, "incomplete");
  const deep = "ecNeg(".repeat(33) + "pk" + ")".repeat(33);
  expected("native-depth", writer.replace('stored=', `assert(${deep}!=default<JubjubPoint>,"point");stored=`) + use, 0, "incomplete");
});

test("canonical internal 0.35 identity rejection quiets the exact conjunction", () => {
  for (const version of ["0.35.0", "0.35.0-rc.1"] as const) expected("internal-rejection", writer + use, 0, "complete", version);
});

test("retained read-summary reuse, Cell snapshots and point namesakes preserve identity", () => {
  fixture("read-reuse", writer + `circuit read():JubjubPoint{return stored;}export circuit use(msg:Vector<1,Field>,sig:JubjubSchnorrSignature):[]{const a=read();const b=read();assert(jubjubSchnorrVerify<1>(msg,sig,a),"a");assert(jubjubSchnorrVerify<1>(msg,sig,b),"b");}`, (file, program) => {
    const cached = observeEnrollmentReview(program, rule, {}, undefined, { cached: true });
    assert.deepEqual(cached.diagnostics, []); assert.ok(cached.work.metrics.readSummaryHits > 0); assert.equal(cached.findings.length, 2);
    const uncached = observeEnrollmentReview(program, rule, {}, undefined, { cached: false });
    assert.equal(uncached.work.metrics.readSummaryHits, 0); assert.deepEqual(cached.findings, uncached.findings);
  });
  fixture("mutation-reuse", `circuit set(pk:JubjubPoint):[]{stored=disclose(pk);}export circuit enroll(pk:JubjubPoint):[]{set(pk);set(pk);}` + use, (file,program)=>{
    const cached=observeEnrollmentReview(program,rule,{},undefined,{cached:true}),uncached=observeEnrollmentReview(program,rule,{},undefined,{cached:false});
    assert.deepEqual(cached.diagnostics,[]);assert.deepEqual(uncached.diagnostics,[]);assert.ok(cached.work.metrics.statefulSummaryHits>0);assert.equal(uncached.work.metrics.statefulSummaryHits,0);
    assert.equal(cached.findings.length,1);assert.deepEqual(cached.findings,uncached.findings);
  });
  expected("native-cell", writer.replace('stored=disclose(pk)', 'stored.write(disclose(pk))') + use.replace('sig,stored)', 'sig,stored.read())'), 1);
  expected("namesake", writer + `module App{export circuit jubjubSchnorrVerify<#N>(msg:Vector<N,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean{return true;}}import App prefix App_;` + use.replace('jubjubSchnorrVerify<1>', 'App_jubjubSchnorrVerify<1>'), 0);
});

test("shared proof caps, missing baseline admission and malformed evidence cannot certify absence", () => {
  fixture("proof-budget", writer + use, (file, program) => {
    for (const options of [{maxSteps:1},{maxSteps:200},{maxValues:2},{maxValues:350},{maxPaths:1}]) {
      const result = observeEnrollmentReview(program, rule, options);
      assert.equal(result.findings.length, 0); assert.ok(result.diagnostics.length); assert.ok(result.coverage.every(row => row.status === "incomplete"));
    }
    const absent = observeEnrollmentReview(program, rule, {}, new Set());
    assert.ok(absent.diagnostics.length); assert.equal(absent.findings.length, 0);
    const entry = program.entries[0];
    const facts = new Dataflow(program).analyzeEnrollmentReviewEntry(entry);
    facts.enrollmentReviewEvidence = {...enrollmentReviewScope(program,()=>true), maxSteps:40000,maxPaths:256,maxValues:50000,outcomes:[]};
    assert.deepEqual(rule.run(facts), []); assert.ok(facts.diagnostics.length);
    const missing = new Dataflow(program).analyze(); assert.deepEqual(rule.run(missing), []); assert.ok(missing.diagnostics.length);
    const exact = () => {
      const scope=enrollmentReviewScope(program,()=>true);
      const rows=scope.entries.map(id=>new Dataflow(program).analyzeEnrollmentReviewEntry(id));
      const metrics={...rows[0].metrics};for(const key of Object.keys(metrics) as (keyof typeof metrics)[])metrics[key]=rows.reduce((sum,row)=>sum+row.metrics[key],0);
      return {...rows[0],paths:rows.flatMap(row=>row.paths),completedEntries:rows.flatMap(row=>row.completedEntries),diagnostics:[],metrics,
        enrollmentReviewEvidence:{...scope,maxSteps:40000,maxPaths:256,maxValues:50000,outcomes:rows.map((row,index)=>({entry:scope.entries[index],histories:row.paths.length}))}};
    };
    const intact=exact();assert.equal(rule.run(intact).length,1);assert.deepEqual(intact.diagnostics,[]);
    const damagedWrite=exact();damagedWrite.paths[0].writes.length=0;assert.deepEqual(rule.run(damagedWrite),[]);assert.ok(damagedWrite.diagnostics.length);
    const damagedPath=exact();damagedPath.paths.shift();assert.deepEqual(rule.run(damagedPath),[]);assert.ok(damagedPath.diagnostics.length);
    const damagedWriters=exact();damagedWriters.enrollmentReviewEvidence.writers=new Map();assert.deepEqual(rule.run(damagedWriters),[]);assert.ok(damagedWriters.diagnostics.length);
    const retained=exact();retained.enrollmentReviewEvidence.maxValues=retained.metrics.abstractValues+10;assert.deepEqual(rule.run(retained),[]);assert.ok(retained.diagnostics.length);
  });
  fixture("absent-baseline", `export circuit entry():[]{}`, (file, program) => {
    const result = observeEnrollmentReview(program, rule, {}, new Set());
    assert.ok(result.diagnostics.length); assert.ok(result.coverage.every(row=>row.status==="incomplete"));
  });
});

test("coverage admission and preparation failures retain bounded explicit unavailable results", () => {
  const extra = Array.from({ length: 64 }, (_, index) => `export circuit spare${index}():[]{}`).join("\n");
  fixture("coverage-admission-many-owned-entries", writer + use + extra, (file, program) => {
    const entries = program.entries.length;
    for (const options of [{ maxValues: 1 }, { maxSteps: 1 }]) {
      const result = observeEnrollmentReview(program, rule, options);
      assert.deepEqual(result.findings, []);
      assert.equal(result.coverage.length, 1);
      assert.deepEqual(result.coverage[0], { root: program.root, detectorId: rule.id, entry: program.entries[0],
        status: "incomplete", evidence: "unavailable", diagnosticCodes: ["enrollment-review-coverage-unavailable"] });
      assert.equal(result.diagnostics.length, 1);
      assert.equal(result.diagnostics[0].code, "enrollment-review-coverage-unavailable");
      assert.ok(result.diagnostics[0].message.includes(`${entries} entries`));
      assert.ok(result.diagnostics[0].message.includes("remaining entries are unobserved"));
      const scanned = scanFile(file, { detectors: [rule.id], ...options });
      assert.equal(scanned.status, "incomplete");
      assert.ok(scanned.diagnostics.some(issue => issue.code === "enrollment-review-coverage-unavailable"));
    }
    // All rows are admitted, baseline checks complete, and scope preparation
    // then exhausts. Reporting reuses that inventory and emits one summary.
    const partial = observeEnrollmentReview(program, rule, { maxSteps: entries * 3 + 5 });
    assert.deepEqual(partial.findings, []); assert.equal(partial.coverage.length, entries);
    assert.ok(partial.coverage.every(row => row.status === "incomplete" && row.evidence === "unavailable"
      && row.diagnosticCodes.length === 1 && row.diagnosticCodes[0] === "enrollment-review-preparation-unavailable"));
    assert.equal(partial.diagnostics.length, 1);
    assert.equal(partial.diagnostics[0].code, "enrollment-review-preparation-unavailable");
    const baseline = observeEnrollmentReview(program, rule, {}, new Set());
    assert.ok(baseline.diagnostics[0].message.includes("completed baseline semantics"));
    const complete = observeEnrollmentReview(program, rule, {});
    assert.deepEqual(complete.diagnostics, []); assert.equal(complete.findings.length, 1);
    assert.deepEqual(complete.coverage.map(row => row.entry), program.entries);
    assert.ok(complete.coverage.every(row => row.status === "complete" || row.status === "not-applicable"));
  });
});

test("admitted dependent inventory failure keeps proof diagnostics fixed-size", () => {
  const uses = Array.from({ length: 24 }, (_, index) => use.replace("circuit use(", `circuit use${index}(`)
    .replace("assert(jubjub", 'assert(validPoint(stored),"point");assert(jubjub')).join("\n");
  fixture("bounded-many-dependent-failure-reports", `witness validPoint(pk:JubjubPoint):Boolean;` + writer + uses, (_file, program) => {
    let proofDiagnostics = 0;
    const result = observeEnrollmentReview(program, { ...rule, run(facts) {
      const findings = rule.run(facts);
      proofDiagnostics = facts.diagnostics.length;
      return findings;
    } }, {});
    assert.deepEqual(result.findings, []); assert.equal(result.coverage.length, program.entries.length);
    assert.ok(result.coverage.every(row => row.status === "incomplete" && row.evidence === "unavailable"
      && row.diagnosticCodes.length === 1 && row.diagnosticCodes[0] === "enrollment-review-incomplete"));
    assert.equal(proofDiagnostics, 1);
    assert.equal(result.diagnostics.length, 2);
    assert.equal(result.diagnostics.at(-1)!.code, "enrollment-review-incomplete");
    assert.ok(result.diagnostics.slice(0, -1).every(issue => issue.code === "enrollment-review-evidence-unavailable"));
    assert.ok(result.diagnostics[0].message.includes(`all ${program.entries.length} dependent entries`));
  });
});

test("rejected signature helper admission constructs only the empty failure payload", () => {
  const path = Object.defineProperty({}, "predicates", { get() { throw new Error("Rejected workspace traversed predicates"); } }) as SuccessfulPath;
  const original = { Set, Map, WeakMap, WeakSet };
  const constructions = { Set: 0, Map: 0, WeakMap: 0, WeakSet: 0 };
  const calls: [number, number][] = [];
  try {
    for (const name of ["Set", "Map", "WeakMap", "WeakSet"] as const) {
      const observed = new Proxy(original[name], { construct(target, args, newTarget) {
        constructions[name]++; return Reflect.construct(target, args, newTarget);
      } });
      Object.assign(globalThis, { [name]: observed });
    }
    const result = signatureKeyIdentityExclusions(path, 4096, (work, values) => { calls.push([work, values]); return false; });
    assert.equal(result.complete, false); assert.equal(result.work, 0); assert.equal(result.excluded.size, 0);
  } finally { Object.assign(globalThis, original); }
  assert.deepEqual(calls, [[0, 4]]);
  assert.deepEqual(constructions, { Set: 1, Map: 0, WeakMap: 0, WeakSet: 0 });
});

test("shared helper meter rejection always leaves proof incomplete", () => {
  fixture("meter-rejection", writer.replace('stored=', 'assert(pk!=default<JubjubPoint>,"point");stored=') + use, (_file, program) => {
    const facts = new Dataflow(program).analyzeEnrollmentReviewEntry(program.entries[0]);
    assert.deepEqual(facts.diagnostics, []);
    const path = facts.paths[0], predicate = path.predicates![0], target = path.writes[0].after;
    const helpers = [
      (meter: (work: number, values: number) => boolean) => immutableOperandKey(target, 4096, undefined, meter),
      (meter: (work: number, values: number) => boolean) => enforcedEqualities(predicate.value, predicate.truth, meter),
      (meter: (work: number, values: number) => boolean) => signatureKeyIdentityExclusions(path, 4096, meter),
    ];
    for (const helper of helpers) {
      let totalWork = 0, totalValues = 0;
      assert.equal(helper((work, values) => { totalWork += work; totalValues += values; return true; }).complete, true);
      for (const dimension of ["work", "values"]) {
        const total = dimension === "work" ? totalWork : totalValues;
        for (let allowance = 0; allowance < total; allowance++) {
          let spent = 0;
          const result = helper((work, values) => { spent += dimension === "work" ? work : values; return spent <= allowance; });
          assert.equal(result.complete, false, `${dimension}/${allowance}/${total}`);
        }
      }
    }
  });
});

test("opt-in selection preserves ordinary detector findings and registry anchors", () => {
  fixture("baseline", writer + use, (file, program) => {
    const baseline = scanFile(file, {detectors:["identity-signature-key"]});
    const selected = scanFile(file, {detectors:["identity-signature-key",rule.id]});
    assert.deepEqual(selected.findings.filter(item=>item.detectorId!==rule.id),baseline.findings);
    const observation = selected.ruleObservationWork!.find(item=>item.detectorId===rule.id)!;
    for (const key of Object.keys(observation.metrics) as (keyof typeof observation.metrics)[]) assert.equal(selected.metrics[key] - observation.metrics[key],baseline.metrics[key],key);
    assert.deepEqual(selected.coverage.completedEntries,baseline.coverage.completedEntries);
    assert.equal(detectors[0].id,"ledger-bound-preimage-publication"); assert.equal(detectors.at(-1)!.id,"configured-membership-capacity-review");
    assert.equal(rule.defaultEnabled,false);
    const experimental=scanFile(file,{detectors:[rule.id],experimentalCounterQueries:true});
    assert.equal(experimental.status,"incomplete");assert.equal(experimental.findings.length,0);assert.ok(experimental.diagnostics.length);
  });
});

test("independently compiler-qualified owned triplets and repaired boundaries preserve source scope", () => {
  const manifest: { detector: string; cases: { file: string; lines: number[] }[] } =
    JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).storedSchnorrEnrollment44;
  assert.equal(manifest.detector, rule.id);
  const sourceSites = new Map(manifest.cases.map(item => [resolve("tests/corpus", item.file), item.lines]));
  const cases: [string, number][] = [
    ["positive",1],["corrected",0],["lookalike",0],["counter/positive",1],["counter/corrected",0],["counter/lookalike",0],
    ["boundaries/alternate-unchecked-replacement",1],["boundaries/imported-module-alias",1],
    ["boundaries/distinct-unrelated-cell",0],["boundaries/guarded-parameter-different-stored-value",1],
    ["boundaries/guard-old-snapshot-then-store-new",1],["boundaries/guard-then-unchecked-final-overwrite",1],
    ["boundaries/unchecked-then-guarded-final-overwrite",0],["boundaries/same-named-application-verifier",0],
    ["boundaries/exact-guarded-constructor-no-replacement",0],["boundaries/constructor-generator-no-external-writer",0],
    ["boundaries/exact-verifier-snapshot-then-revise",1],["boundaries/committed-checkpoint-prefix",0],
  ];
  for (const [name,count] of cases) {
    const file=resolve("tests/corpus/drafts/enrollment44",`${name}.compact`), checkpoint=name.includes("checkpoint");
    const zkir=checkpoint?2:3;
    if(process.env.COMPACTC_TEST){const compiled=validateWithCompiler(process.env.COMPACTC_TEST,file,[],30000,zkir,"0.34.0");assert.equal(compiled.valid,true,`${name}: ${compiled.error}`);}
    const program=new Program(file,[],undefined,undefined,zkir,"0.34.0");
    let baseline:unknown;
    for(const engine of ["instructions","expressions"] as const)for(const cached of [false,true]){
      const result=observeEnrollmentReview(program,rule,{},undefined,{engine,cached});
      assert.equal(result.findings.length,count,`${name}: ${JSON.stringify(result.diagnostics)}`);
      assert.equal(result.diagnostics.length===0,!checkpoint,`${name}: ${JSON.stringify(result.diagnostics)}`);
      baseline??=result.findings;assert.deepEqual(result.findings,baseline,`${name}/${engine}/${cached}`);
    }
    const result=scanFile(file,{detectors:[rule.id],zkirVersion:zkir,compilerVersion:"0.34.0"});
    assert.equal(result.status,checkpoint?"incomplete":"complete",`${name}: ${JSON.stringify(result.diagnostics)}`);assert.equal(result.findings.length,count,name);
    const expectedLines = sourceSites.get(file);
    if (expectedLines) assert.deepEqual(result.findings.map(finding => finding.location.line), expectedLines, name);
  }
  const positive=readFileSync(resolve("tests/corpus/drafts/enrollment44/counter/positive.compact"),"utf8");
  assert.ok(positive.includes("SPDX-License-Identifier: Apache-2.0"));
});
