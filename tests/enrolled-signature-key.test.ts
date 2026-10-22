import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { Dataflow, Program, scanFile, type CompilerVersion } from "../src/index.js";
import { enrolledSignatureKeyReview as rule } from "../src/detectors/enrolled-signature-key.js";
import { identitySignatureKey } from "../src/detectors/signature-key.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
export ledger enrolled: JubjubPoint;
export ledger other: JubjubPoint;
circuit verify(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): Boolean {
  return jubjubSchnorrVerify<1>(msg, sig, pk);
}
`;
function fixture(body: string, expected: string[], version: CompilerVersion = "0.34.0", includeHeader = true): void {
  withFiles({ "main.compact": (includeHeader ? header : "") + body }, directory => {
    const file = resolve(directory, "main.compact");
    const compiler = version === "0.35.0" ? process.env.COMPACTC_035_TEST : version === "0.35.0-rc.1" ? process.env.COMPACTC_035_RC1_TEST : process.env.COMPACTC_TEST;
    if (compiler) { const compiled = validateWithCompiler(compiler, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file, [], undefined, undefined, 2, version);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, false, "all", false, false, false, false, true, false, false, false, false, false, new Set(), false, false, true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(findings.map(item => item.metadata.entry).sort(), [...expected].sort());
      assert.ok(findings.every(item => item.severity === "info" && item.metadata.keyKnownIdentity === false
        && item.metadata.subgroupMembershipModeled === false && item.metadata.unsafeEnrollmentProven === false));
      baseline ??= findings; assert.deepEqual(findings, baseline);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { detectors: [rule.id], compilerVersion: version, experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.deepEqual(scan.findings.map(item => item.metadata.entry).sort(), [...expected].sort());
    }
    assert.ok(!scanFile(file, { compilerVersion: version }).findings.some(item => item.detectorId === rule.id));
  });
}

test("persistent Schnorr review distinguishes unknown keys, exact caller guards, and known identity evidence", () => {
  fixture(`
export circuit unguarded(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  const pk=enrolled; assert(verify(msg, sig, pk), "signature");
}
export circuit corrected(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(enrolled != default<JubjubPoint>, "identity"); assert(verify(msg, sig, enrolled), "signature");
}
export circuit known(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(enrolled == default<JubjubPoint>, "identity"); assert(verify(msg, sig, enrolled), "signature");
}
export circuit parameter(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(verify(msg, sig, pk), "signature");
}
`, ["unguarded"]);
  withFiles({ "main.compact": header + `export circuit known(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
    assert(enrolled == default<JubjubPoint>, "identity"); assert(verify(msg, sig, enrolled), "signature");
  }` }, directory => {
    const scan = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id, identitySignatureKey.id] });
    assert.equal(scan.status, "complete");
    assert.deepEqual(scan.findings.map(item => item.detectorId), [identitySignatureKey.id]);
  });
});

test("identity guards follow immutable helper arguments and native identity-to-identity transfers", () => {
  fixture(`
circuit checked(pk: JubjubPoint): JubjubPoint {
  assert(pk != default<JubjubPoint>, "identity"); return pk;
}
export circuit helper(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(verify(msg,sig,checked(enrolled)), "signature");
}
export circuit multiplied(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(ecMul(enrolled,8 as JubjubScalar) != default<JubjubPoint>, "small-order rejection");
  assert(verify(msg,sig,enrolled), "signature");
}
export circuit negated(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(ecNeg(enrolled) != default<JubjubPoint>, "identity"); assert(verify(msg,sig,enrolled), "signature");
}
export circuit equality(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(pk != default<JubjubPoint>, "identity"); assert(enrolled == pk, "bound");
  assert(verify(msg,sig,enrolled), "signature");
}
export circuit later(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(verify(msg,sig,enrolled), "signature"); assert(enrolled != default<JubjubPoint>, "identity");
}
`, []);
});

test("persistent key guards do not cross revisions, snapshots, unrelated keys or exclusive branches", () => {
  fixture(`
export circuit staleGuard(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  const old=enrolled; enrolled=disclose(other); assert(old != default<JubjubPoint>, "old");
  assert(verify(msg,sig,enrolled), "signature");
}
export circuit retained(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  const old=enrolled; enrolled=disclose(other); assert(enrolled != default<JubjubPoint>, "new");
  assert(verify(msg,sig,old), "signature");
}
export circuit correctSnapshot(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  const old=enrolled; enrolled=disclose(other); assert(old != default<JubjubPoint>, "old");
  assert(verify(msg,sig,old), "signature");
}
export circuit unrelated(msg: Vector<1, Field>, sig: JubjubSchnorrSignature): [] {
  assert(other != default<JubjubPoint>, "other"); assert(verify(msg,sig,enrolled), "signature");
}
export circuit oneBranch(flag: Boolean,msg: Vector<1, Field>,sig: JubjubSchnorrSignature): [] {
  if(disclose(flag)){assert(enrolled != default<JubjubPoint>, "identity");}
  assert(verify(msg,sig,enrolled), "signature");
}
export circuit bothBranches(flag: Boolean,msg: Vector<1, Field>,sig: JubjubSchnorrSignature): [] {
  if(disclose(flag)){assert(enrolled != default<JubjubPoint>, "identity");}
  else {assert(ecNeg(enrolled) != default<JubjubPoint>, "identity");}
  assert(verify(msg,sig,enrolled), "signature");
}
export circuit conjunction(msg: Vector<1,Field>,sig:JubjubSchnorrSignature): [] {
  assert(enrolled != default<JubjubPoint> && other != default<JubjubPoint>, "keys");
  assert(verify(msg,sig,enrolled), "signature");
}
export circuit disjunction(msg: Vector<1,Field>,sig:JubjubSchnorrSignature): [] {
  assert(enrolled != default<JubjubPoint> || other != default<JubjubPoint>, "either key");
  assert(verify(msg,sig,enrolled), "signature");
}
`, ["staleGuard", "retained", "unrelated", "oneBranch"]);
  // The alternative that checks the other key has already refined this key
  // to known identity. Preserve the existing stronger rule at that boundary.
  withFiles({ "main.compact": header + `
export circuit disjunction(msg: Vector<1,Field>,sig:JubjubSchnorrSignature): [] {
  assert(enrolled != default<JubjubPoint> || other != default<JubjubPoint>, "either key");
  assert(verify(msg,sig,enrolled), "signature");
}` }, directory => {
    const scan = scanFile(resolve(directory,"main.compact"),{detectors:[rule.id,identitySignatureKey.id]});
    assert.equal(scan.status,"complete",JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(item=>item.detectorId),[identitySignatureKey.id]);
  });
});

test("canonical names, native transformations, Map projections and rejected histories delimit the review", () => {
  fixture(`
export ledger keys: Map<Field,JubjubPoint>;
module App { export circuit jubjubSchnorrVerify<#N>(msg: Vector<N,Field>,sig:JubjubSchnorrSignature,pk:JubjubPoint): Boolean {return true;} }
import App prefix A_;
export circuit namesake(msg:Vector<1,Field>,sig:JubjubSchnorrSignature): [] {assert(A_jubjubSchnorrVerify<1>(msg,sig,enrolled), "check");}
export circuit mapKey(msg:Vector<1,Field>,sig:JubjubSchnorrSignature,index:Field): [] {assert(verify(msg,sig,keys.lookup(disclose(index))), "signature");}
export circuit transformed(msg:Vector<1,Field>,sig:JubjubSchnorrSignature): [] {assert(verify(msg,sig,ecNeg(enrolled)), "signature");}
export circuit messagePolicy(msg:Vector<1,Field>,sig:JubjubSchnorrSignature): [] {assert(msg[0] != 0 as Field, "message");assert(verify(msg,sig,enrolled), "signature");}
export circuit rejected(msg:Vector<1,Field>,sig:JubjubSchnorrSignature): [] {assert(verify(msg,sig,enrolled), "signature");assert(false, "disabled");}
`, ["messagePolicy"]);
});

test("source-pinned 0.35 stable and RC verifiers reject unknown identity keys internally", () => {
  for (const version of ["0.35.0", "0.35.0-rc.1"] as const) fixture(`
export circuit verifyStored(msg: Vector<1,Field>,sig:JubjubSchnorrSignature): [] {assert(verify(msg,sig,enrolled), "signature");}
`, [], version);
});

test("missing, compressed or exhausted persistent signature evidence stays explicitly incomplete", () => {
  withFiles({ "main.compact": header + `export circuit entry(msg: Vector<1,Field>,sig:JubjubSchnorrSignature): [] {assert(verify(msg,sig,enrolled), "signature");}` }, directory => {
    const file = resolve(directory,"main.compact"), program = new Program(file);
    const missing = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(missing), []);
    assert.ok(missing.diagnostics.some(issue => issue.code === "signature-key-review-evidence-unavailable"));
    const exact = () => new Dataflow(program,40000,256,50000,"instructions",true,true,"equivalent-states",false,false,"all",false,false,false,false,true,false,false,false,false,false,new Set(),false,false,true).analyze();
    const damaged = exact();
    damaged.paths[0].predicates![0].value = { ...damaged.paths[0].predicates![0].value, predicateStructureLost: true };
    assert.deepEqual(rule.run(damaged), []);
    assert.ok(damaged.diagnostics.some(issue => issue.code === "signature-key-review-predicate-unavailable"));
    const exhausted = scanFile(file,{detectors:[rule.id],maxSteps:1});
    assert.equal(exhausted.status,"incomplete"); assert.ok(exhausted.diagnostics.length);
  });
});

test("owned persistent-key triplet is compiler-valid and selected-only", () => {
  for (const [name, expected] of [["positive",[29]],["corrected",[]],["lookalike",[]]] as const) {
    const file = resolve("tests/corpus/signature-key-review",`${name}.compact`);
    if(process.env.COMPACTC_TEST) { const compiled=validateWithCompiler(process.env.COMPACTC_TEST,file); assert.equal(compiled.valid,true,compiled.error); }
    const selected=scanFile(file,{detectors:[rule.id]});
    assert.equal(selected.status,"complete",JSON.stringify(selected.diagnostics));
    assert.deepEqual(selected.findings.map(item=>item.location.line),expected);
    assert.ok(!scanFile(file).findings.some(item=>item.detectorId===rule.id));
    // The same exact owned bytes also pass the engine/cache matrix above.
    fixture(readFileSync(file,"utf8"),name==="positive"?["signedIncrement"]:[],"0.34.0",false);
  }
});

test("actual read-summary reuse preserves exact persistent-key and guard snapshots", () => {
  withFiles({"main.compact":header+`
circuit readKey(): JubjubPoint { return enrolled; }
export circuit entry(msg:Vector<1,Field>,sig:JubjubSchnorrSignature): [] {
  const a=readKey();const b=readKey();assert(verify(msg,sig,a), "first");assert(verify(msg,sig,b), "second");
}`},directory=>{
    const file=resolve(directory,"main.compact"),program=new Program(file);
    if(process.env.COMPACTC_TEST){const compiled=validateWithCompiler(process.env.COMPACTC_TEST,file);assert.equal(compiled.valid,true,compiled.error);}
    let baseline:unknown;
    for(const engine of ["instructions","expressions"] as const)for(const cached of [false,true]){
      const facts=new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,false,"all",false,false,false,false,true,false,false,false,false,false,new Set(),false,false,true).analyze();
      assert.deepEqual(facts.diagnostics,[]);
      if(cached)assert.ok(facts.metrics.readSummaryHits>0);else assert.equal(facts.metrics.readSummaryHits,0);
      const findings=rule.run(facts);assert.deepEqual(facts.diagnostics,[]);assert.equal(findings.length,1);
      baseline??=findings;assert.deepEqual(findings,baseline);
    }
  });
});

test("explicit native Cell reads and native identity evidence limits preserve rule coverage", () => {
  fixture(`
export ledger stored: JubjubPoint;
export circuit directCell(msg:Vector<1,Field>,sig:JubjubSchnorrSignature): [] { assert(verify(msg,sig,stored.read()), "signature"); }
export circuit checkedCell(msg:Vector<1,Field>,sig:JubjubSchnorrSignature): [] { const pk=stored.read();assert(pk != default<JubjubPoint>, "identity");assert(verify(msg,sig,pk), "signature"); }
`,["directCell"]);
  const transformed = "ecNeg(".repeat(33) + "enrolled" + ")".repeat(33);
  withFiles({"main.compact":header+`export circuit entry(msg:Vector<1,Field>,sig:JubjubSchnorrSignature): [] {
    assert(${transformed} != default<JubjubPoint>, "identity");assert(verify(msg,sig,enrolled), "signature");
  }`},directory=>{
    const file=resolve(directory,"main.compact");
    if(process.env.COMPACTC_TEST){const compiled=validateWithCompiler(process.env.COMPACTC_TEST,file);assert.equal(compiled.valid,true,compiled.error);}
    const result=scanFile(file,{detectors:[rule.id]});
    assert.equal(result.status,"incomplete");assert.equal(result.findings.length,0);
    assert.ok(result.diagnostics.some(issue=>issue.code==="signature-key-review-predicate-unavailable"));
  });
});

test("ordinary all-predicate signature observations exclude opt-in identity metadata", () => {
  withFiles({ "main.compact": header + `
export circuit stored(msg: Vector<1,Field>,sig:JubjubSchnorrSignature): [] {
  assert(ecNeg(other) != default<JubjubPoint>, "other key");
  assert(verify(msg,sig,enrolled), "signature");
}
export circuit known(msg: Vector<1,Field>,sig:JubjubSchnorrSignature): [] {
  assert(verify(msg,sig,default<JubjubPoint>), "signature");
}` }, directory => {
    const file = resolve(directory,"main.compact"), program = new Program(file);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST,file);
      assert.equal(compiled.valid,true,compiled.error);
    }
    for (const engine of ["instructions","expressions"] as const) for (const cached of [false,true]) {
      const analyze = (observeSignatureKeyIdentity: boolean) => new Dataflow(program,40000,256,50000,engine,cached,cached,
        "equivalent-states",false,false,"all",false,false,false,false,true,false,false,false,false,false,
        new Set(),false,false,observeSignatureKeyIdentity).analyze();
      const ordinary = analyze(false), observed = analyze(true);
      assert.deepEqual(ordinary.diagnostics,[]); assert.deepEqual(observed.diagnostics,[]);
      assert.deepEqual(ordinary.completedEntries,observed.completedEntries);
      assert.deepEqual(identitySignatureKey.run(ordinary),identitySignatureKey.run(observed));
      const entry = program.entries.find(id => program.symbols.get(id)?.name === "stored")!;
      const before = ordinary.paths.find(path => path.entry === entry)!;
      const after = observed.paths.find(path => path.entry === entry)!;
      const operation = before.operations!.find(item => item.kind === "signature-verification")!;
      const optInOperation = after.operations!.find(item => item.kind === "signature-verification")!;
      assert.equal(Object.hasOwn(operation,"signatureKeyExcludesIdentity"),false);
      assert.equal(typeof optInOperation.signatureKeyExcludesIdentity,"boolean");
      const native = before.predicates![0].value.comparison!.left;
      const optInNative = after.predicates![0].value.comparison!.left;
      for (const key of ["pointIdentityInput","pointIdentityDepth","pointIdentityEvidenceLost"])
        assert.equal(Object.hasOwn(native,key),false);
      assert.ok(optInNative.pointIdentityInput);
      assert.equal(optInNative.pointIdentityDepth,1);
    }
  });
});
