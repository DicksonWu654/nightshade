import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { mkdtempSync, writeFileSync as requireWrite, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { spawnSync, type SpawnOptions } from "node:child_process";
import { scanFile, scanFileIsolated, mergeResults, detectors } from "../src/index.js";
import { human, sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";
import { Dataflow, Program } from "../src/index.js";
import { ruleObservationIssue } from "../src/analysis/rule-diagnostics.js";

const fixture = `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger members: Map<Uint<8>, Field>;
export ledger digest: Bytes<32>;
witness flags(): Vector<10, Boolean>;
circuit branching(): [] {
  const selected = flags();
  for (const i of 0..10) { if (disclose(selected[i])) { members.insert(i as Uint<8>, 1 as Field); } }
  digest = disclose(persistentHash<Boolean>(selected[0]));
}
export circuit exhaustive(): [] { branching(); }
export circuit sameHelper(): [] { branching(); }
export circuit seeded(flag: Boolean): [] { digest = disclose(persistentHash<Boolean>(flag)); }
`;
const observed = new Set(["redundant-self-shielded-receive", "publicly-derivable-encryption-secret", "duplicate-shielded-mint", "either-payload-mismatch", "low-entropy-hash-disclosure", "identity-signature-key", "field-arithmetic-wraparound", "public-key-membership-authorization", "zero-amount-unshielded-send", "zero-amount-set-consumption-review", "merkle-insert-without-dedupe", "field-recomposition-range-review", "merkle-leaf-binding-review"]);
const baselineSelection = detectors.filter(rule => !rule.policyRequired && rule.defaultEnabled !== false && !observed.has(rule.id)).map(rule => rule.id);

test("compiler-valid cold imported source exhaustion is scoped to each affected rule, including workers and Counter mode", async context => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-source-budget-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = resolve(directory, "main.compact");
  requireWrite(resolve(directory, "Library.compact"), `pragma language_version >= 0.26.0;
    module Library { export circuit helper(flag: Boolean): [] {
      ${"if (disclose(flag)) {".repeat(70)} 1 as Field; ${"}".repeat(70)}
    } }`);
  requireWrite(file, `pragma language_version >= 0.26.0; import "Library"; import CompactStandardLibrary;
    export circuit run(): [] { helper(false); assert(true, "marker"); }
    export circuit verify(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): Boolean {
      return disclose(jubjubSchnorrVerify<1>(msg, sig, pk));
    }`);
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const affected = ["duplicated-branch-tail", "ignored-validation-result"];
  const options = { detectors: [...affected, "always-true-assertion"] };
  const baseline = scanFile(file, { detectors: ["always-true-assertion"] });
  assert.equal(baseline.status, "complete", JSON.stringify(baseline.diagnostics));
  assert.equal(baseline.findings.length, 1);
  for (const report of [scanFile(file, options), await scanFileIsolated(file, options)]) {
    assert.equal(report.status, "incomplete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.coverage.completedEntries, baseline.coverage.completedEntries);
    assert.deepEqual(report.findings, baseline.findings);
    assert.equal(report.diagnostics.length, affected.length * report.entrypoints.length);
    for (const row of report.coverage.rules!) {
      assert.equal(row.status, affected.includes(row.detectorId) ? "incomplete" : "complete");
      if (row.status === "incomplete") {
        assert.deepEqual(row.diagnosticCodes, ["source-observation-budget"]);
        assert.ok(report.diagnostics.some(issue => issue.scope?.detectorId === row.detectorId && issue.scope.entry === row.entry));
      }
    }
    assert.ok(report.diagnostics.every(issue => issue.code === "source-observation-budget" && issue.scope));
    assert.match(human(report), /Baseline analysis: complete; selected rules: incomplete/);
    const formatted = sarif(report) as { runs: { properties: { coverage: typeof report.coverage } }[] };
    assert.deepEqual(formatted.runs[0].properties.coverage, report.coverage);
  }
  const defaults = scanFile(file);
  assert.equal(defaults.coverage.baselineStatus, "complete");
  assert.equal(defaults.status, "incomplete");
  assert.ok(affected.every(id => defaults.coverage.rules!.filter(row => row.detectorId === id).every(row => row.status === "incomplete")));
  for (const report of [scanFile(file, { ...options, experimentalCounterQueries: true }),
    await scanFileIsolated(file, { ...options, experimentalCounterQueries: true })]) {
    assert.equal(report.status, "incomplete", JSON.stringify(report.diagnostics));
    assert.ok("analysis" in report);
    assert.ok(report.analysis.coverage.filter(row => affected.includes(row.detector)).every(row => row.status === "incomplete"));
    assert.ok(report.diagnostics.every(issue => issue.code === "source-observation-budget" && issue.scope));
  }
});

test("a rule observation failure with no entry retains its explicit root diagnostic", () => {
  withFiles({ "main.compact": "module Library { export circuit helper(): [] {} }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    assert.deepEqual(program.entries, []);
    const facts = new Dataflow(program).analyze();
    for (let i = 0; i < 2; i++) ruleObservationIssue(facts, "duplicated-branch-tail", "source-observation-budget", "exhausted");
    assert.equal(facts.diagnostics.length, 1);
    assert.equal(facts.diagnostics[0].scope, undefined);
    assert.equal(facts.diagnostics[0].code, "source-observation-budget");
    assert.deepEqual(facts.diagnostics[0].location, program.rootSource.ast.span);
  });
});

test("entry-scoped observation budgets preserve baseline coverage and independent complete findings", () => {
  withFiles({ "main.compact": fixture }, directory => {
    const file = resolve(directory,"main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST,file); assert.equal(compiled.valid,true,compiled.error); }
    const baseline = scanFile(file,{detectors:baselineSelection}), report = scanFile(file);
    assert.equal(baseline.status,"complete",JSON.stringify(baseline.diagnostics));
    assert.equal(report.coverage.baselineStatus,"complete");
    assert.equal(report.status,"incomplete");
    assert.deepEqual(report.coverage.completedEntries,baseline.coverage.completedEntries);
    assert.deepEqual(report.findings.filter(f => !observed.has(f.detectorId)),baseline.findings);
    const hash = report.coverage.rules!.filter(row => row.detectorId === "low-entropy-hash-disclosure");
    assert.deepEqual(hash.map(row => row.status),["incomplete","incomplete","complete"]);
    assert.deepEqual(report.findings.filter(f=>f.detectorId==="low-entropy-hash-disclosure").map(f=>f.metadata.entry),["seeded"]);
    for (const row of hash.filter(row=>row.status==="incomplete")) {
      assert.ok(report.diagnostics.some(d=>d.scope?.detectorId===row.detectorId&&d.scope.entry===row.entry));
      assert.ok(row.diagnosticCodes.includes("analysis-budget"));
    }
    assert.ok(report.coverage.rules!.filter(row=>row.detectorId==="either-payload-mismatch").every(row=>row.status==="not-applicable"));
    for (const item of report.ruleObservationWork!) assert.ok(item.metrics.abstractValues<=item.limits.maxValues+1);
    const extraValues = report.ruleObservationWork!.reduce((sum,item)=>sum+item.metrics.abstractValues,0);
    assert.equal(report.metrics.abstractValues,baseline.metrics.abstractValues+extraValues);
    assert.match(human(report),/Baseline analysis: complete; selected rules: incomplete/);
    assert.match(human(report),/Rule coverage low-entropy-hash-disclosure: 1 complete, 0 structurally absent, 2 unavailable\/incomplete/);
    const formatted = sarif(report) as {runs:{properties:{coverage:typeof report.coverage};invocations:{executionSuccessful:boolean;toolExecutionNotifications:{properties:{scope:unknown}}[]}[]}[]};
    assert.deepEqual(formatted.runs[0].properties.coverage,report.coverage);
    assert.equal(formatted.runs[0].invocations[0].executionSuccessful,false);
    assert.ok(formatted.runs[0].invocations[0].toolExecutionNotifications.every(n=>n.properties.scope));
    const cli = spawnSync(process.execPath,[resolve("dist/src/cli.js"),file,"--json","--fail-on","none","--min-severity","critical"],{encoding:"utf8"});
    assert.equal(cli.status,2,cli.stderr);
    const selected=JSON.parse(cli.stdout);assert.equal(selected.status,"incomplete");assert.equal(selected.coverage.baselineStatus,"complete");assert.equal(selected.findings.length,0);
    const warning = spawnSync(process.execPath, [resolve("dist/src/cli.js"), file, "--json", "--fail-on", "none", "--rule-incomplete", "warn"], { encoding: "utf8" });
    assert.equal(warning.status, 0, warning.stderr);
    assert.equal(JSON.parse(warning.stdout).status, "incomplete");
    assert.equal(JSON.parse(warning.stdout).coverage.baselineStatus, "complete");

  });
});

test("baseline errors remain global and unselected observation modes create no coverage rows", () => {
  withFiles({"main.compact":fixture},directory=>{
    const file=resolve(directory,"main.compact");
    const failed=scanFile(file,{maxSteps:1});
    assert.equal(failed.status,"incomplete");assert.equal(failed.coverage.baselineStatus,"incomplete");
    assert.ok(failed.diagnostics.some(d=>!d.scope));
    const baseline=scanFile(file,{detectors:baselineSelection});
    assert.equal(baseline.status,"complete");
    assert.ok(baseline.coverage.rules!.every(row=>!observed.has(row.detectorId)));
    assert.equal(baseline.ruleObservationWork,undefined);
  });
});

test("merging coverage retains incomplete obligations and rejects contradictory complete reports",()=>{
  withFiles({"main.compact":fixture},directory=>{
    const report=scanFile(resolve(directory,"main.compact"));
    const merged=mergeResults([report,report]);
    assert.equal(merged.status,"incomplete");assert.equal(merged.coverage.baselineStatus,"complete");
    assert.deepEqual(merged.coverage.rules,report.coverage.rules);
    const changed=structuredClone(report);
    const target=changed.coverage.rules!.find(row=>row.status==="incomplete")!;target.status="complete";target.diagnosticCodes=[];
    const conflict=mergeResults([report,changed]);
    assert.equal(conflict.status,"incomplete");
    assert.ok(conflict.diagnostics.some(d=>d.code==="rule-coverage-conflict"&&d.scope));
    assert.ok(conflict.coverage.rules!.some(row=>row.entry===target.entry&&row.detectorId===target.detectorId&&row.status==="incomplete"));
  });
});

test("a complete observation does not erase unsupported baseline effects",()=>{
  // Kernel checkpoints are modeled; a collection key with an unresolved hash choice is not.
  withFiles({"main.compact":`import CompactStandardLibrary;
export ledger seen: Set<Bytes<32>>;
export circuit unsupported(flag: Boolean, a: Bytes<32>, b: Bytes<32>): [] {
  seen.insert(disclose(flag) ? persistentHash<Vector<2, Bytes<32>>>([disclose(a), disclose(b)]) : persistentHash<Vector<2, Bytes<32>>>([disclose(b), disclose(a)]));
}
export circuit seeded(flag: Boolean): Bytes<32> { return disclose(persistentHash<Boolean>(flag)); }
`},directory=>{
    const file=resolve(directory,"main.compact");
    if(process.env.COMPACTC_TEST){const compiled=validateWithCompiler(process.env.COMPACTC_TEST,file);assert.equal(compiled.valid,true,compiled.error);}
    const report=scanFile(file);
    assert.equal(report.status,"incomplete");assert.equal(report.coverage.baselineStatus,"incomplete");
    assert.ok(report.diagnostics.some(d=>d.code==="unsupported-hash-choice"&&!d.scope));
    assert.ok(report.coverage.rules!.some(row=>row.detectorId==="low-entropy-hash-disclosure"&&row.entry.endsWith("::seeded")&&row.status==="complete"));
    assert.ok(report.findings.some(f=>f.detectorId==="low-entropy-hash-disclosure"));
  });
});

test("genuine successive root revisions cannot retain a contradicted absence certificate",()=>{
  withFiles({"main.compact":"export circuit entry(): [] {}"},directory=>{
    const file=resolve(directory,"main.compact"),options={detectors:["low-entropy-hash-disclosure"]};
    const absent=scanFile(file,options);
    requireWrite(file,`import CompactStandardLibrary; export circuit entry(value: Boolean): Bytes<32> { return disclose(persistentHash<Boolean>(value)); }`);
    if(process.env.COMPACTC_TEST){const compiled=validateWithCompiler(process.env.COMPACTC_TEST,file);assert.equal(compiled.valid,true,compiled.error);}
    const relevant=scanFile(file,options);
    for(const reports of [[absent,relevant],[relevant,absent]]){
      const merged=mergeResults(reports);
      assert.equal(merged.status,"incomplete");
      const row=merged.coverage.rules![0];assert.equal(row.status,"incomplete");assert.equal(row.evidence,"unavailable");
      assert.ok(row.diagnosticCodes.includes("rule-coverage-conflict"));
    }
  });
});

test("workers reject missing, duplicate and unrelated-root obligations while preserving legacy reports",async context=>{
  const directory=mkdtempSync(resolve(tmpdir(),"nightshade-rule-worker-"));
  context.after(()=>rmSync(directory,{recursive:true,force:true}));
  const file=resolve(directory,"main.compact"),payload=resolve(directory,"report.json");
  requireWrite(file,"export circuit entry(): [] {}");
  const options={detectors:["low-entropy-hash-disclosure"]};
  const genuine=scanFile(file,options);assert.equal(genuine.status,"complete");
  const original=childProcess.spawn;
  childProcess.spawn=((_command: string,_args?: readonly string[],settings?: SpawnOptions)=>original(process.execPath,["--input-type=module","-e",`import {readFileSync} from 'node:fs'; process.stdin.resume(); process.stdin.on('end',()=>console.log(readFileSync(process.argv[1],'utf8')));`,payload],settings ?? {})) as unknown as typeof original;
  syncBuiltinESMExports();
  try{
    for(const mutate of [
      (report: typeof genuine)=>{delete report.coverage.rules;},
      (report: typeof genuine)=>{report.coverage.rules=[];},
      (report: typeof genuine)=>{report.coverage.rules!.push(structuredClone(report.coverage.rules![0]));},
      (report: typeof genuine)=>{report.coverage.rules![0].root="unrelated.compact";},
      (report: typeof genuine)=>{report.status="incomplete";report.coverage.rules![0].evidence="conservative-absence";report.coverage.rules![0].status="incomplete";},
      (report: typeof genuine)=>{report.status="incomplete";report.coverage.rules![0].evidence="conservative-absence";report.coverage.rules![0].diagnosticCodes=["analysis-budget"];},
    ]){
      const malformed=structuredClone(genuine);mutate(malformed);requireWrite(payload,JSON.stringify(malformed));
      const report=await scanFileIsolated(file,options);assert.equal(report.status,"incomplete");assert.equal(report.diagnostics[0].code,"worker-protocol");
    }
    const legacy=structuredClone(genuine);delete legacy.coverage.rules;delete legacy.coverage.baselineStatus;delete legacy.ruleObservationWork;
    requireWrite(payload,JSON.stringify(legacy));assert.equal((await scanFileIsolated(file,options)).status,"complete");
    requireWrite(payload,JSON.stringify(genuine));assert.equal((await scanFileIsolated(file,options)).status,"complete");

    requireWrite(file, "contract Peer { circuit read(): Field; }");
    const empty = scanFile(file, options);
    requireWrite(payload, JSON.stringify(empty));
    assert.equal((await scanFileIsolated(file, options)).status, "complete");
    for (const mutate of [
      (report: typeof empty) => { report.diagnostics = []; },
      (report: typeof empty) => { report.diagnostics[0].message = "forged notice"; },
      (report: typeof empty) => { report.diagnostics[0].location.file = "unrelated.compact"; },
      (report: typeof empty) => { report.coverage.noEntrypointRoots = []; },
      (report: typeof empty) => { report.diagnostics.push({ ...report.diagnostics[0], code: "analysis-error" }); },
      (report: typeof empty) => { report.diagnostics.push(structuredClone(report.diagnostics[0])); },
    ]) {
      const malformed = structuredClone(empty); mutate(malformed);
      requireWrite(payload, JSON.stringify(malformed));
      assert.equal((await scanFileIsolated(file, options)).diagnostics[0].code, "worker-protocol");
    }

    requireWrite(file, "export circuit entry(): [] {} export circuit other(): [] {}");
    const counterOptions = { detectors: ["duplicated-branch-tail", "constant-condition"], experimentalCounterQueries: true };
    const counter = scanFile(file, counterOptions);
    assert.ok("analysis" in counter);
    const affected = counter.analysis.coverage[0];
    affected.status = "incomplete"; counter.status = "incomplete";
    counter.diagnostics.push({ code: "source-observation-budget", message: "exhausted", location: genuine.diagnostics[0]?.location ?? {
      file, start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2,
    }, scope: { kind: "rule", detectorId: affected.detector, entry: affected.entry } });
    requireWrite(payload, JSON.stringify(counter));
    assert.equal((await scanFileIsolated(file, counterOptions)).diagnostics[0].code, "source-observation-budget");
    for (const mutate of [
      (report: typeof counter) => { report.analysis.coverage.pop(); },
      (report: typeof counter) => { report.analysis.coverage.push({ ...report.analysis.coverage[0], status: "covered" }); },
      (report: typeof counter) => { report.analysis.coverage[0].entry = "unknown"; report.diagnostics[0].scope!.entry = "unknown"; },
      (report: typeof counter) => { report.analysis.coverage[0].detector = "unknown"; report.diagnostics[0].scope!.detectorId = "unknown"; },
    ]) {
      const malformed = structuredClone(counter); mutate(malformed); requireWrite(payload, JSON.stringify(malformed));
      const report = await scanFileIsolated(file, counterOptions);
      assert.equal(report.diagnostics[0].code, "worker-protocol");
    }
  }finally{childProcess.spawn=original;syncBuiltinESMExports();}
});
