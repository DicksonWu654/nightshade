import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type CompilerVersion } from "../src/index.js";
import { observeSignatureIdentity } from "../src/analysis/signature-identity-observation.js";
import { signatureKeyIdentityExclusionReview as rule } from "../src/detectors/signature-identity-review.js";
import { signatureKeyIdentityExclusions } from "../src/dataflow/signature-key.js";
import { signaturePointCurve } from "../src/semantic/signature-targets.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const header = `import CompactStandardLibrary;
export ledger stored: JubjubPoint;
export ledger secpStored: Secp256k1Point;
export ledger other: JubjubPoint;
circuit verify(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean {return jubjubSchnorrVerify<1>(msg,sig,pk);}
circuit ecdsa(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,pk:Secp256k1Point):Boolean {return secp256k1EcdsaVerify(msg,sig,pk);}
`;
function fixture(source: string, check: (file: string, program: Program) => void, version: CompilerVersion = "0.34.0", zkir: 2 | 3 = 3) {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    const compiler = version === "0.35.0" ? process.env.COMPACTC_035_TEST : version === "0.35.0-rc.1" ? process.env.COMPACTC_035_RC1_TEST : process.env.COMPACTC_TEST;
    if (compiler) { const result = validateWithCompiler(compiler, file, [], 30000, zkir, version); assert.equal(result.valid, true, result.error); }
    check(file, new Program(file, [], undefined, undefined, zkir, version));
  });
}
function matrix(source: string, expected: string[], incomplete = false) {
  fixture(header + source, (file, program) => {
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const observed = observeSignatureIdentity(program, rule, {}, undefined, { engine, cached });
      assert.equal(observed.diagnostics.length > 0, incomplete, JSON.stringify(observed.diagnostics));
      assert.deepEqual(observed.findings.map(item => item.metadata.entry).sort(), [...expected].sort());
      assert.ok(observed.findings.every(item => item.severity === "info" && item.metadata.keyKnownIdentity === false
        && item.metadata.curveMembershipModeled === false && item.metadata.subgroupMembershipModeled === false
        && item.metadata.signatureEnforcementProven === false));
      baseline ??= observed.findings; assert.deepEqual(observed.findings, baseline);
      assert.equal(observed.work.limits.maxSteps, 40000); assert.equal(observed.work.limits.maxPaths, 256); assert.equal(observed.work.limits.maxValues, 50000);
    }
    const scan = scanFile(file, { detectors: [rule.id], zkirVersion: 3 });
    assert.equal(scan.status, incomplete ? "incomplete" : "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(item => item.metadata.entry).sort(), [...expected].sort());
  });
}

test("original owned signature-input-key/stored-device-key keys retain both curves and message-only obligations", () => {
  for (const subject of ["signature-input-key", "stored-device-key"]) for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/synthetic-regressions/validation16/${subject}-${variant}.compact`);
    fixture(readFileSync(file, "utf8"), (temporary, program) => {
      const expected = subject === "signature-input-key" ? variant === "positive" ? [4, 7] : [5, 9] : variant === "positive" ? [10, 13] : [11, 15];
      let baseline: unknown;
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        const result = observeSignatureIdentity(program, rule, {}, undefined, { engine, cached });
        assert.deepEqual(result.diagnostics, []);
        assert.deepEqual(result.findings.map(item => item.location.line), variant === "corrected" ? [] : expected);
        assert.deepEqual(result.findings.map(item => item.metadata.curve), variant === "corrected" ? [] : ["JubjubPoint", "Secp256k1Point"]);
        baseline ??= result.findings; assert.deepEqual(result.findings, baseline);
      }
      const baselineScan = scanFile(temporary, { detectors: ["identity-signature-key"], zkirVersion: 3 });
      const selected = scanFile(temporary, { detectors: ["identity-signature-key", rule.id], zkirVersion: 3 });
      assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
      assert.deepEqual(selected.findings.filter(item => item.detectorId !== rule.id), baselineScan.findings);
      const work = selected.ruleObservationWork!.find(item => item.detectorId === rule.id)!;
      for (const key of Object.keys(work.metrics) as (keyof typeof work.metrics)[]) assert.equal(selected.metrics[key] - work.metrics[key], baselineScan.metrics[key], key);
    });
  }
});

test("exact caller guards, helper aliases and curve-specific inequalities exclude only that input", () => {
  matrix(`
circuit guarded(pk:JubjubPoint):JubjubPoint {assert(ecMul(pk,8 as JubjubScalar)!=default<JubjubPoint>,"cofactor");return pk;}
export circuit caller(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean {const alias=pk;return verify(msg,sig,alias);}
export circuit helper(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean {return verify(msg,sig,guarded(pk));}
export circuit secp(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,pk:Secp256k1Point):Boolean {assert(pk!=default<Secp256k1Point>,"identity");return ecdsa(msg,sig,pk);}
export circuit unrelated(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint,otherKey:JubjubPoint):Boolean {assert(otherKey!=default<JubjubPoint>,"other");return verify(msg,sig,pk);}
export circuit equivalent(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint,otherKey:JubjubPoint):Boolean {assert(pk==otherKey,"bind");assert(otherKey!=default<JubjubPoint>,"identity");return verify(msg,sig,pk);}
export circuit later(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean {const ok=verify(msg,sig,pk);assert(pk!=default<JubjubPoint>,"later");return ok;}
`, ["caller", "unrelated"]);
});

test("persistent snapshots and caller argument evaluation preserve storage revisions and rejected histories", () => {
  matrix(`
circuit replace():JubjubPoint {stored=disclose(other);return stored;}
export circuit retained(msg:Vector<1,Field>,sig:JubjubSchnorrSignature):Boolean {const old=stored;stored=disclose(other);assert(stored!=default<JubjubPoint>,"new");return verify(msg,sig,old);}
export circuit oldGuard(msg:Vector<1,Field>,sig:JubjubSchnorrSignature):Boolean {const old=stored;stored=disclose(other);assert(old!=default<JubjubPoint>,"old");return verify(msg,sig,stored);}
export circuit exact(msg:Vector<1,Field>,sig:JubjubSchnorrSignature):Boolean {const old=stored;stored=disclose(other);assert(old!=default<JubjubPoint>,"old");return verify(msg,sig,old);}
export circuit order(msg:Vector<1,Field>,sig:JubjubSchnorrSignature):Boolean {assert(stored!=default<JubjubPoint>,"old");return verify(msg,sig,replace());}
export circuit rejected(msg:Bytes<32>,sig:Secp256k1EcdsaSignature):Boolean {const result=ecdsa(msg,sig,secpStored);assert(false,"disabled");return result;}
`, ["retained", "oldGuard", "order"]);
});

test("mandatory original histories keep unchecked branches and do not union exclusions", () => {
  matrix(`
export circuit some(flag:Boolean,msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean {if(disclose(flag)){assert(pk!=default<JubjubPoint>,"identity");}return verify(msg,sig,pk);}
export circuit both(flag:Boolean,msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean {if(disclose(flag)){assert(pk!=default<JubjubPoint>,"identity");}else{assert(ecNeg(pk)!=default<JubjubPoint>,"identity");}return verify(msg,sig,pk);}
export circuit known(msg:Bytes<32>,sig:Secp256k1EcdsaSignature):Boolean {return ecdsa(msg,sig,default<Secp256k1Point>);}
`, ["some"]);
});

test("ordinary and shared read summaries retain invocation-local verifier operands", () => {
  fixture(header + `
circuit readKey():Secp256k1Point {return secpStored;}
export circuit entry(msg:Bytes<32>,sig:Secp256k1EcdsaSignature):[] {const a=readKey();const b=readKey();assert(ecdsa(msg,sig,a),"first");assert(ecdsa(msg,sig,b),"second");}
`, (_file, program) => {
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeSignatureIdentityEntry(program.entries[0]);
      assert.deepEqual(facts.diagnostics, []);
      if (cached) assert.ok(facts.metrics.readSummaryHits > 0); else assert.equal(facts.metrics.readSummaryHits, 0);
      const result = rule.run(facts); assert.deepEqual(facts.diagnostics, []); assert.equal(result.length, 1);
      const operations = facts.paths[0].operations!.filter(item => item.kind === "signature-verification");
      assert.equal(operations.length, 2); assert.equal(operations[0].args[2].identity, operations[1].args[2].identity);
      baseline ??= result; assert.deepEqual(result, baseline);
    }
  });
});

test("literal nonzero generator keys are quiet without inferring an inverse input property", () => {
  matrix(`
export circuit generated(msg:Vector<1,Field>,sig:JubjubSchnorrSignature):Boolean {return verify(msg,sig,ecMulGenerator(1 as JubjubScalar));}
export circuit generatedSecp(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,scalar:Secp256k1Scalar):Boolean {assert(scalar!=default<Secp256k1Scalar>,"nonzero");return ecdsa(msg,sig,ecMulGenerator(scalar));}
`, []);
});

test("relevant opaque predicates and transformed verification keys are incomplete", () => {
  matrix(`witness validPoint(pk:JubjubPoint):Boolean;
export circuit entry(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean {assert(validPoint(pk),"policy");return verify(msg,sig,pk);}
`, [], true);
  matrix(`export circuit entry(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,pk:Secp256k1Point):Boolean {assert(secp256k1PointX(pk)!=default<Secp256k1Base>,"coordinate");return ecdsa(msg,sig,pk);}
`, [], true);
  matrix(`export circuit entry(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean {return verify(msg,sig,ecNeg(pk));}
`, [], true);
});

test("metered typed closure refuses the other curve identity", () => {
  fixture(header + `export circuit entry(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,pk:Secp256k1Point):Boolean {assert(pk!=default<Secp256k1Point>,"identity");return ecdsa(msg,sig,pk);}`, (_file, program) => {
    const facts = new Dataflow(program).analyzeSignatureIdentityEntry(program.entries[0]);
    const path = facts.paths[0];
    const closure = signatureKeyIdentityExclusions(path, 40000, () => true, "JubjubPoint", value => signaturePointCurve(program, value.type ?? "") === "JubjubPoint");
    assert.equal(closure.complete, true); assert.equal(closure.excluded.size, 0);
  });
});

test("missing history evidence, unfinished baseline, unsupported profiles and exhausted budgets diagnose incomplete", () => {
  fixture(header + `export circuit entry(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,pk:Secp256k1Point):Boolean {return ecdsa(msg,sig,pk);}`, (file, program) => {
    const missing = new Dataflow(program).analyze(); assert.deepEqual(rule.run(missing), []); assert.ok(missing.diagnostics.length);
    const full = () => new Dataflow(program).analyzeSignatureIdentityEntry(program.entries[0]);
    for (const breakEvidence of [
      (facts: ReturnType<typeof full>) => { facts.paths[0].operations!.pop(); },
      (facts: ReturnType<typeof full>) => { facts.completedEntries.length = 0; },
      (facts: ReturnType<typeof full>) => { facts.signatureIdentityEvidence!.histories++; },
      (facts: ReturnType<typeof full>) => { facts.signatureIdentityEvidence!.maxSteps = facts.metrics.steps; },
      (facts: ReturnType<typeof full>) => { facts.signatureIdentityEvidence!.maxValues = facts.metrics.abstractValues; },
    ]) { const facts = full(); breakEvidence(facts); assert.deepEqual(rule.run(facts), []); assert.ok(facts.diagnostics.length); }
    for (const options of [{ maxSteps: 1 }, { maxValues: 1 }, { maxPaths: 1, maxSteps: 10 }]) {
      const scan = scanFile(file, { detectors: [rule.id], zkirVersion: 3, ...options });
      assert.equal(scan.status, "incomplete"); assert.equal(scan.findings.length, 0); assert.ok(scan.diagnostics.length);
    }
    const unavailable = observeSignatureIdentity(program, rule, {}, new Set()); assert.ok(unavailable.diagnostics.length);
    const experimental = scanFile(file, { detectors: [rule.id], zkirVersion: 3, experimentalCounterQueries: true });
    assert.equal(experimental.status, "incomplete"); assert.equal(experimental.findings.length, 0);
  });
});

test("exact pinned 0.35 stable and RC Schnorr internal rejection is quiet", () => {
  for (const version of ["0.35.0", "0.35.0-rc.1"] as const) fixture(`import CompactStandardLibrary;
export circuit entry(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean {return jubjubSchnorrVerify<1>(msg,sig,pk);}`, (file, program) => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const observed = observeSignatureIdentity(program, rule, {}, undefined, { engine, cached }); assert.deepEqual(observed.diagnostics, []); assert.deepEqual(observed.findings, []);
    }
    const scan = scanFile(file, { detectors: [rule.id], compilerVersion: version }); assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics)); assert.deepEqual(scan.findings, []);
  }, version, 2);
});

test("secp observations remain selected-only and ordinary known-identity semantics unchanged", () => {
  fixture(header + `export circuit entry(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,pk:Secp256k1Point):Boolean {return ecdsa(msg,sig,pk);}`, (file, program) => {
    const ordinary = new Dataflow(program,40000,256,50000,"instructions",true,true,"equivalent-states",false,false,"all",false,false,false,false,true).analyze();
    assert.ok(ordinary.paths.every(path => !path.operations?.some(item => item.kind === "signature-verification")));
    const selected = scanFile(file, { detectors: [rule.id], zkirVersion: 3 }); assert.equal(selected.findings.length, 1);
    const baseline = scanFile(file, { detectors: ["identity-signature-key"], zkirVersion: 3 }); assert.deepEqual(baseline.findings, []);
  });
});


test("callbacks reuse ordinary invocation transfers and empty sequences produce no verifier observation", () => {
  matrix(`
circuit check(pk:JubjubPoint,msg:Vector<1,Field>,sig:JubjubSchnorrSignature):Boolean {return verify(msg,sig,pk);}
circuit checkSecp(pk:Secp256k1Point,msg:Bytes<32>,sig:Secp256k1EcdsaSignature):Boolean {return ecdsa(msg,sig,pk);}
export circuit nonempty(pk:JubjubPoint,msg:Vector<1,Field>,sig:JubjubSchnorrSignature):Vector<1,Boolean> {return map(check,[pk],[msg],[sig]);}
export circuit empty():Vector<0,Boolean> {return map(check,[] as Vector<0,JubjubPoint>,[] as Vector<0,Vector<1,Field>>,[] as Vector<0,JubjubSchnorrSignature>);}
export circuit emptySecp():Vector<0,Boolean> {return map(checkSecp,[] as Vector<0,Secp256k1Point>,[] as Vector<0,Bytes<32>>,[] as Vector<0,Secp256k1EcdsaSignature>);}
`, ["nonempty"]);
});

test("shared mutation summaries replay the current key snapshot rather than cached guards", () => {
  fixture(header + `
circuit set(pk:Secp256k1Point):[] {secpStored=disclose(pk);}
export circuit entry(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,pk:Secp256k1Point):Boolean {set(pk);set(pk);return ecdsa(msg,sig,secpStored);}
`, (_file, program) => {
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false,true]) {
      const result=observeSignatureIdentity(program,rule,{},undefined,{engine,cached});
      assert.deepEqual(result.diagnostics,[]);assert.equal(result.findings.length,1);
      if(cached)assert.ok(result.work.metrics.statefulSummaryHits>0);else assert.equal(result.work.metrics.statefulSummaryHits,0);
      baseline??=result.findings;assert.deepEqual(result.findings,baseline);
    }
  });
});

test("other-curve native predicates and opaque message guards do not validate the exact key", () => {
  matrix(`
witness validMessage(msg:Bytes<32>):Boolean;
export circuit entry(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,pk:Secp256k1Point,otherKey:JubjubPoint):Boolean {
  assert(ecNeg(otherKey)!=default<JubjubPoint>,"unrelated curve");assert(validMessage(msg),"message");return ecdsa(msg,sig,pk);
}
`,["entry"]);
});

test("namesake verifiers stay outside scope; projected unknown keys and checkpoints remain unavailable", () => {
  matrix(`
module App {export circuit secp256k1EcdsaVerify(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,pk:Secp256k1Point):Boolean {return true;}}
import App prefix App_;
export circuit entry(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,pk:Secp256k1Point):Boolean {return App_secp256k1EcdsaVerify(msg,sig,pk);}
`, []);
  matrix(`export ledger keys:Map<Field,Secp256k1Point>;
export circuit entry(msg:Bytes<32>,sig:Secp256k1EcdsaSignature,index:Field):Boolean {return ecdsa(msg,sig,keys.lookup(disclose(index)));}
`, [], true);
  fixture(`import CompactStandardLibrary;export ledger value:Field;
export circuit entry(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint):Boolean {value=0 as Field;kernel.checkpoint();return jubjubSchnorrVerify<1>(msg,sig,pk);}
`, (_file, program)=>{const observed=observeSignatureIdentity(program,rule,{});assert.ok(observed.diagnostics.length);assert.deepEqual(observed.findings,[]);},"0.34.0",2);
});
