import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { Ajv } from "ajv";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { lowEntropyHashDisclosure as digestRule } from "../src/detectors/small-domain-hash.js";
import { eitherPayloadMismatch as eitherRule } from "../src/detectors/either-payload.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

// Ten witness-selected storage writes: 1024 exact histories, above the default
// 256-path allowance, and a branch-expanding entry for source-query admission.
const expand = `  for (const i of 0..10) { if (disclose(bits[i])) { marks.insert(i as Uint<8>, true); } }\n`;
const header = `import CompactStandardLibrary;
export ledger digest: Bytes<32>;
export ledger stored: Bytes<32>;
export ledger marks: Map<Uint<8>, Boolean>;
`;

function certify(program: Program, entry: string, kind: "digest" | "either") {
  return (["instructions", "expressions"] as const).map(engine =>
    new Dataflow(program, 40000, 256, 50000, engine, true, true, "equivalent-states", false, true, kind === "either" ? "all" : "witness", false, false, false, true, false, kind === "either", kind === "digest")
      .conservativeRuleCertificate(entry, kind).status);
}

function exactFindings(program: Program, kind: "digest" | "either"): string[] {
  const facts = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true, kind === "either" ? "all" : "witness", false, false, false, true, false, kind === "either", kind === "digest").analyze();
  assert.deepEqual(facts.diagnostics, []);
  return [...new Set((kind === "digest" ? digestRule : eitherRule).run(facts).map(finding => String(finding.metadata.entry)))].sort();
}

function compile(file: string): void {
  if (!process.env.COMPACTC_TEST) return;
  const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
  assert.equal(compiled.valid, true, compiled.error);
}

test("digest absence certificates complete branch-expanding entries only without small private digest leaves", () => {
  withFiles({ "main.compact": header + `
export circuit large(bits: Vector<10, Boolean>, key: Bytes<32>): [] {
${expand}  digest = disclose(persistentHash<Vector<2, Bytes<32>>>([key, pad(32, "tag")]));
}
export circuit small(bits: Vector<10, Boolean>, flag: Boolean): [] {
${expand}  digest = disclose(persistentHash<Boolean>(flag));
}
export circuit joined(bits: Vector<10, Boolean>, a: Uint<8>, b: Uint<8>): [] {
${expand}  const chosen = disclose(bits[0]) ? a : b;
  stored = disclose(persistentHash<Uint<8>>(chosen));
}
export circuit unpublished(bits: Vector<10, Boolean>, flag: Boolean): [] {
${expand}  persistentHash<Boolean>(flag);
}
` }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const program = new Program(file);
    const entry = (name: string) => program.entries.find(id => id.endsWith(`::${name}`))!;
    assert.deepEqual(certify(program, entry("large"), "digest"), ["absent", "absent"]);
    // A represented small raw leaf and a joined leaf with a raw arm are candidates
    // whatever their publication; the certificate ignores sinks entirely.
    for (const name of ["small", "joined", "unpublished"]) assert.deepEqual(certify(program, entry(name), "digest"), ["candidate", "candidate"]);
    // The exact pass alone cannot complete these entries.
    const exact = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true, "witness", false, false, false, true, false, false, true).analyzeSubset([entry("large")]);
    assert.ok(exact.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    const report = scanFile(file, { detectors: [digestRule.id] });
    assert.equal(report.coverage.baselineStatus, "complete", JSON.stringify(report.diagnostics));
    const rows = new Map(report.coverage.rules!.filter(row => row.detectorId === digestRule.id).map(row => [program.symbols.get(row.entry)!.name, row]));
    assert.deepEqual([rows.get("large")!.status, rows.get("large")!.evidence, rows.get("large")!.diagnosticCodes], ["complete", "conservative-absence", []]);
    for (const name of ["small", "joined", "unpublished"]) {
      const row = rows.get(name)!;
      assert.deepEqual([row.status, row.evidence], ["incomplete", "exact-observation"], name);
      assert.ok(report.diagnostics.some(diagnostic => diagnostic.scope?.detectorId === digestRule.id && diagnostic.scope.entry === row.entry), name);
    }
    assert.equal(report.status, "incomplete");
    assert.deepEqual(report.findings.filter(finding => finding.detectorId === digestRule.id), []);
  });
});

test("digest certificate candidates match exact findings on non-expanding twins", () => {
  withFiles({ "main.compact": header + `
export circuit large(key: Bytes<32>): [] { digest = disclose(persistentHash<Vector<2, Bytes<32>>>([key, pad(32, "tag")])); }
export circuit small(flag: Boolean): [] { digest = disclose(persistentHash<Boolean>(flag)); }
export circuit joined(c: Boolean, a: Uint<8>, b: Uint<8>): [] { const chosen = disclose(c) ? a : b; stored = disclose(persistentHash<Uint<8>>(chosen)); }
export circuit narrowed(value: Field): [] { stored = disclose(persistentHash<Uint<8>>(value as Uint<8>)); }
` }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const program = new Program(file);
    assert.deepEqual(exactFindings(program, "digest"), ["joined", "narrowed", "small"]);
    for (const entry of program.entries) {
      const name = program.symbols.get(entry)!.name;
      assert.deepEqual(certify(program, entry, "digest"), name === "large" ? ["absent", "absent"] : ["candidate", "candidate"], name);
    }
  });
});

test("Either absence certificates require a constant active receiver tag at every selection", () => {
  withFiles({ "main.compact": header + `
export circuit active(bits: Vector<10, Boolean>, value: Bytes<32>): [] {
${expand}  const selected = right<Bytes<32>, Bytes<32>>(value);
  stored = disclose(selected.right);
}
export circuit inactive(bits: Vector<10, Boolean>, value: Bytes<32>): [] {
${expand}  const selected = right<Bytes<32>, Bytes<32>>(value);
  stored = disclose(selected.left);
}
export circuit unknownTag(bits: Vector<10, Boolean>, value: Either<Bytes<32>, Bytes<32>>): [] {
${expand}  assert(!value.is_left, "right");
  stored = disclose(value.right);
}
` }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const program = new Program(file);
    const entry = (name: string) => program.entries.find(id => id.endsWith(`::${name}`))!;
    assert.deepEqual(certify(program, entry("active"), "either"), ["absent", "absent"]);
    assert.deepEqual(certify(program, entry("inactive"), "either"), ["candidate", "candidate"]);
    // The tag is refined by the joined current constraints: the assertion makes
    // it the constant selecting the read arm.
    assert.deepEqual(certify(program, entry("unknownTag"), "either"), ["absent", "absent"]);
    const report = scanFile(file, { detectors: [eitherRule.id] });
    assert.equal(report.coverage.baselineStatus, "complete", JSON.stringify(report.diagnostics));
    const rows = new Map(report.coverage.rules!.filter(row => row.detectorId === eitherRule.id).map(row => [program.symbols.get(row.entry)!.name, row]));
    assert.deepEqual([rows.get("active")!.status, rows.get("active")!.evidence], ["complete", "conservative-absence"]);
    assert.deepEqual([rows.get("unknownTag")!.status, rows.get("unknownTag")!.evidence], ["complete", "conservative-absence"]);
    assert.deepEqual([rows.get("inactive")!.status, rows.get("inactive")!.evidence], ["incomplete", "exact-observation"]);
    assert.deepEqual(report.findings.filter(finding => finding.detectorId === eitherRule.id), []);
  });
});

test("Either certificate candidates match exact findings on non-expanding twins", () => {
  withFiles({ "main.compact": header + `
export circuit active(value: Bytes<32>): [] { const selected = right<Bytes<32>, Bytes<32>>(value); stored = disclose(selected.right); }
export circuit inactive(value: Bytes<32>): [] { const selected = right<Bytes<32>, Bytes<32>>(value); stored = disclose(selected.left); }
export circuit lateTag(value: Either<Bytes<32>, Bytes<32>>): [] { stored = disclose(value.left); assert(!value.is_left, "right"); }
export circuit unchecked(value: Either<Bytes<32>, Bytes<32>>): [] { stored = disclose(value.left); }
` }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const program = new Program(file);
    assert.deepEqual(exactFindings(program, "either"), ["inactive", "lateTag"]);
    for (const entry of program.entries) {
      const name = program.symbols.get(entry)!.name;
      // An unknown tag is a candidate even when no history reports it.
      assert.deepEqual(certify(program, entry, "either"), name === "active" ? ["absent", "absent"] : ["candidate", "candidate"], name);
    }
  });
});

test("certificate work shares the entry step allowance and never certifies an incomplete view", () => {
  withFiles({ "main.compact": header + `
export circuit large(bits: Vector<10, Boolean>, key: Bytes<32>): [] {
${expand}  digest = disclose(persistentHash<Bytes<32>>(key));
}
` }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const program = new Program(file);
    const entry = program.entries.find(id => id.endsWith("::large"))!;
    const flow = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true, "witness", false, false, false, true, false, false, true);
    const full = flow.conservativeRuleCertificate(entry, "digest");
    assert.equal(full.status, "absent");
    const starved = flow.conservativeRuleCertificate(entry, "digest", { steps: Math.floor(full.work.steps / 2), values: 50000 });
    assert.equal(starved.status, "incomplete");
    const report = scanFile(file, { detectors: [digestRule.id], maxSteps: Math.floor(full.work.steps / 2) });
    const row = report.coverage.rules!.find(item => item.detectorId === digestRule.id)!;
    assert.equal(row.status, "incomplete");
    assert.ok(row.diagnosticCodes.length > 0);
  });
});

test("two stable private digest leaves certify absence; publication or constraints of either do not", () => {
  withFiles({ "main.compact": header + `
export circuit salted(bits: Vector<10, Boolean>, flag: Boolean, salt: Bytes<32>, other: Bytes<32>): [] {
${expand}  digest = disclose(persistentHash<[Boolean, Bytes<32>, Bytes<32>]>([flag, salt, other]));
}
export circuit revealed(bits: Vector<10, Boolean>, flag: Boolean, salt: Bytes<32>, other: Bytes<32>): [] {
${expand}  stored = disclose(salt);
  digest = disclose(persistentHash<[Boolean, Bytes<32>, Bytes<32>]>([flag, salt, other]));
}
export circuit revealedBoth(bits: Vector<10, Boolean>, flag: Boolean, salt: Bytes<32>, other: Bytes<32>): [] {
${expand}  stored = disclose(salt); stored = disclose(other);
  digest = disclose(persistentHash<[Boolean, Bytes<32>, Bytes<32>]>([flag, salt, other]));
}
export circuit pinned(bits: Vector<10, Boolean>, flag: Boolean, salt: Bytes<32>, other: Bytes<32>): [] {
${expand}  assert(disclose(salt) == pad(32, "fixed"), "fixed salt"); assert(disclose(other) == pad(32, "other"), "fixed other");
  digest = disclose(persistentHash<[Boolean, Bytes<32>, Bytes<32>]>([flag, salt, other]));
}
export circuit single(bits: Vector<10, Boolean>, flag: Boolean): [] {
${expand}  digest = disclose(persistentHash<[Boolean, Bytes<32>]>([flag, pad(32, "context")]));
}
` }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const program = new Program(file);
    const entry = (name: string) => program.entries.find(id => id.endsWith(`::${name}`))!;
    // flag and the unpublished salt/other remain two stable private leaves.
    for (const name of ["salted", "revealed"]) assert.deepEqual(certify(program, entry(name), "digest"), ["absent", "absent"], name);
    for (const name of ["revealedBoth", "pinned", "single"]) assert.deepEqual(certify(program, entry(name), "digest"), ["candidate", "candidate"], name);
  });
  // Non-expanding twins: the exact oracle agrees on every classification.
  withFiles({ "main.compact": header + `
export circuit salted(flag: Boolean, salt: Bytes<32>, other: Bytes<32>): [] { digest = disclose(persistentHash<[Boolean, Bytes<32>, Bytes<32>]>([flag, salt, other])); }
export circuit revealed(flag: Boolean, salt: Bytes<32>, other: Bytes<32>): [] { stored = disclose(salt); stored = disclose(other); digest = disclose(persistentHash<[Boolean, Bytes<32>, Bytes<32>]>([flag, salt, other])); }
export circuit pinned(flag: Boolean, salt: Bytes<32>, other: Bytes<32>): [] { assert(disclose(salt) == pad(32, "fixed"), "fixed salt"); assert(disclose(other) == pad(32, "other"), "fixed other"); digest = disclose(persistentHash<[Boolean, Bytes<32>, Bytes<32>]>([flag, salt, other])); }
` }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const program = new Program(file);
    assert.deepEqual(exactFindings(program, "digest"), ["pinned", "revealed"]);
    for (const entry of program.entries) {
      const name = program.symbols.get(entry)!.name;
      assert.deepEqual(certify(program, entry, "digest"), name === "salted" ? ["absent", "absent"] : ["candidate", "candidate"], name);
    }
  });
});


test("certificate reports use schema 1.6; incomplete certificates and legacy-version claims are rejected",()=>{
  withFiles({"main.compact":header+`export circuit absence(bits: Vector<10,Boolean>,value: Bytes<32>): [] { ${expand} digest=disclose(persistentHash<Bytes<32>>(value)); }`},directory=>{
    const report=scanFile(resolve(directory,"main.compact"),{detectors:["low-entropy-hash-disclosure"]});
    assert.equal(report.status,"complete",JSON.stringify(report.diagnostics));
    assert.equal(report.schemaVersion,"1.6.0");
    assert.equal(report.coverage.rules![0].evidence,"conservative-absence");
    const ajv=new Ajv({strict:false,allErrors:true});
    const current=ajv.compile(JSON.parse(readFileSync("docs/schema/report.schema.json","utf8")));
    const legacy=ajv.compile(JSON.parse(readFileSync("docs/schema/report-1.1.schema.json","utf8")));
    const plain=JSON.parse(JSON.stringify(report));
    assert.equal(current(plain),true,JSON.stringify(current.errors));
    const invalid=structuredClone(plain);invalid.coverage.rules[0].status="incomplete";
    assert.equal(current(invalid),false);
    const budget=structuredClone(plain);budget.coverage.rules[0].diagnosticCodes=["analysis-budget"];
    assert.equal(current(budget),false);
    const oldClaim=structuredClone(plain);oldClaim.schemaVersion="1.1.0";
    delete oldClaim.coverage.noEntrypointRoots;
    assert.equal(legacy(oldClaim),false);
    const ordinary=JSON.parse(JSON.stringify(scanFile(resolve(directory,"main.compact"),{detectors:["unused-declaration"]})));
    ordinary.schemaVersion="1.1.0";
    delete ordinary.coverage.noEntrypointRoots;
    assert.equal(legacy(ordinary),true,JSON.stringify(legacy.errors));
  });
});


test("the final digest domain charge cannot certify absence beyond its work allowance",()=>{
  withFiles({"main.compact":`import CompactStandardLibrary; export ledger digest: Bytes<32>; export circuit entry(key: Bytes<32>): [] { digest=disclose(persistentHash<Bytes<32>>(key)); }`},directory=>{
    const file=resolve(directory,"main.compact");compile(file);
    const program=new Program(file);
    for(const engine of ["instructions","expressions"] as const) {
      const flow=new Dataflow(program,40000,256,50000,engine);
      const full=flow.conservativeRuleCertificate(program.entries[0],"digest");
      assert.equal(full.status,"absent");
      for(let allowance=full.work.steps-5;allowance<=full.work.steps;allowance++) {
        const limited=flow.conservativeRuleCertificate(program.entries[0],"digest",{steps:allowance,values:50000});
        if(limited.work.steps>allowance) assert.equal(limited.status,"incomplete",JSON.stringify(limited));
        if(limited.status==="absent") assert.ok(limited.work.steps<=allowance);
      }
    }
  });
});
