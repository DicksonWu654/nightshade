import { keyedStateTargets } from "../src/semantic/keyed-state-targets.js";
import { keyedStateComponents } from "../src/semantic/keyed-state-components.js";
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, scanFileIsolated, detectors } from "../src/index.js";
import { keyedStateInvariantObservations } from "../src/dataflow/keyed-state-invariant.js";
import { inconsistentKeyedStateGuard as rule } from "../src/detectors/keyed-state-invariant.js";
import { withFiles } from "./helpers.js";

const base = "tests/corpus/synthetic-regressions/state16/";
const positive = readFileSync(base + "inconsistent-keyed-state-guard-case-17-positive.compact", "utf8");
function fixture(source: string, expected: number, inspect?: (facts: ReturnType<Dataflow["analyze"]>) => void) {
  withFiles({ "main.compact": source }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false, "all", false, true, false, false).analyze();
      assert.deepEqual(facts.diagnostics, []);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(findings.length, expected, `${engine}/${cached}`);
      oracle ??= findings; assert.deepEqual(findings, oracle);
      for (const finding of findings) { assert.equal(finding.severity, "info"); assert.equal(finding.metadata.invariantIntent, "unknown"); }
      inspect?.(facts);
    }
  });
}
test("faithful keyed-state triplet reports mixed approval histories only", () => {
  assert.equal(rule.defaultEnabled, false);
  for (const [variant, expected] of [["positive", 1], ["corrected", 0], ["lookalike", 0]] as const)
    fixture(readFileSync(base + `inconsistent-keyed-state-guard-case-17-${variant}.compact`, "utf8"), expected);
});
test("canonical collection identity and exact same-key checks need no naming conventions", () => {
  fixture(positive.replaceAll("approvals", "notes").replaceAll("tokenExists", "permitted"), 1);
  fixture(positive.replace("auth: Bytes<32>", "auth: Bytes<32>, otherId: Uint<128>").replace("tokenExists.member(disclose(id)), \"token exists\");\n    assert", "tokenExists.member(disclose(otherId)), \"token exists\");\n    assert"), 0);
  fixture(positive.replace("consumeApproval(id: Uint<128>)", "consumeApproval(id: Uint<128>, otherId: Uint<128>)").replace("assert(approvals.member(disclose(id))", "assert(approvals.member(disclose(otherId))"), 0);
});
test("consumer requirement must cover every successful history", () => {
  fixture(positive.replace("assert(tokenExists.member(disclose(id)), \"token exists\");\n  assert(approvals", "if (disclose(id) != 0) { assert(tokenExists.member(disclose(id)), \"token exists\"); }\n  assert(approvals"), 0);
});
test("late unchanged membership assertion constrains atomic successful insertion", () => {
  fixture(positive.replace("approvals.insert(disclose(id), disclose(spender));", "approvals.insert(disclose(id), disclose(spender));\n  assert(tokenExists.member(disclose(id)), \"late valid\");"), 0);
});
test("mutated prerequisite and removed insertion cannot certify a relationship", () => {
  fixture(positive.replace("approvals.insert(disclose(id), disclose(spender));", "tokenExists.remove(disclose(id));\n  approvals.insert(disclose(id), disclose(spender));"), 0);
  fixture(positive.replace("approvals.insert(disclose(id), disclose(spender));", "approvals.insert(disclose(id), disclose(spender));\n  approvals.remove(disclose(id));"), 0);
});
test("incomplete evidence and exhausted allowance diagnose instead of clean review", () => {
  fixture(positive, 1, facts => {
    for (const changed of [{ ...facts, collectionEvidence: false }, { ...facts, completedEntries: [] }, { ...facts, pathSemantics: "guard-cover" as const }]) {
      const result = keyedStateInvariantObservations(changed); assert.equal(result.observations.length, 0); assert.equal(result.diagnostics.length, facts.program.entries.length);
    }
    const bounded = keyedStateInvariantObservations(facts, 1); assert.equal(bounded.observations.length, 0); assert.equal(bounded.diagnostics.length, facts.program.entries.length);
  });
});
test("compiler-valid owned helper and boundary cases retain the structural contract", () => {
  for (const [variant, expected] of [["wrapper-gap", 1], ["same-key-guard", 0], ["unrelated-key", 0], ["invalidated-membership", 0], ["independent-set", 0], ["no-consumer-correlation", 0], ["guard-after-write", 0]] as const)
    fixture(readFileSync(base + `approval-cases24/keyed-state-${variant}.compact`, "utf8"), expected);
});
test("nonconstant Boolean membership relations diagnose unsupported proof", () => {
  fixture(positive, 1, facts => {
    const predicate = facts.paths.flatMap(path => path.predicates ?? []).find(predicate => predicate.value.collectionPredicate);
    assert.ok(predicate);
    const changed = { ...facts, paths: facts.paths.map(path => ({ ...path, predicates: (path.predicates ?? []).map(item => item === predicate ? { ...item, value: {
      flows: [], ledger: new Set<string>(), type: "Boolean", comparison: { operator: "==" as const, left: item.value,
        right: { flows: [], ledger: new Set<string>(), type: "Boolean", identity: "unknown-boolean" } },
    } } : item) })) };
    const result = keyedStateInvariantObservations(changed); assert.equal(result.observations.length, 0); assert.match(result.diagnostics[0].message, /nonconstant Boolean/);
  });
});

test("selected and supervised APIs retain whole-program relation with exact coverage", async context => {
  const file = resolve(base + "inconsistent-keyed-state-guard-case-17-positive.compact");
  assert.equal(detectors.find(detector => detector.id === rule.id), rule);
  assert.equal(rule.defaultEnabled, false);
  const options = { detectors: [rule.id] };
  const direct = scanFile(file, options);
  assert.equal(direct.status, "complete", JSON.stringify(direct.diagnostics));
  assert.equal(direct.findings.length, 1);
  assert.equal(direct.findings[0].severity, "info");
  assert.ok(direct.coverage.rules!.every(row => row.status === "complete" && row.evidence === "exact-observation"));
  const supervised = await scanFileIsolated(file, options);
  assert.equal(supervised.status, "complete", JSON.stringify(supervised.diagnostics));
  assert.deepEqual(supervised.findings, direct.findings);
  assert.deepEqual(supervised.coverage.rules, direct.coverage.rules);
  assert.ok(!scanFile(file).coverage.detectors.includes(rule.id));
  const exhausted = scanFile(file, { ...options, maxPaths: 1 });
  assert.equal(exhausted.status, "incomplete");
  assert.ok(exhausted.coverage.rules!.every(row => row.status === "incomplete"));
  assert.ok(exhausted.diagnostics.some(issue => issue.code === "keyed-state-evidence-unavailable"));
});
test("resolved membership absence needs no collection evidence and marks not-applicable", () => {
  withFiles({ "main.compact": "import CompactStandardLibrary; export circuit unchanged(id: Field): Field { return id; }" }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    const facts = new Dataflow(program).analyze();
    const result = keyedStateInvariantObservations({ ...facts, completedEntries: [], pathSemantics: "guard-cover", collectionEvidence: false });
    assert.deepEqual(result.observations, []); assert.deepEqual(result.diagnostics, []);
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "complete");
    assert.equal(scan.coverage.rules![0].status, "not-applicable");
    assert.equal(scan.coverage.rules![0].evidence, "structural-absence");
  });
});
test("unrelated incomplete baseline remains incomplete beside structural absence", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary; export ledger result: Field;
    export circuit branching(flag: Boolean): [] { if (disclose(flag)) { result = 1 as Field; } else { result = 2 as Field; } }` }, directory => {
    const file = resolve(directory, "main.compact");
    const report = scanFile(file, { detectors: [rule.id], maxValues: 1 });
    assert.equal(report.status, "incomplete");
    assert.equal(report.coverage.baselineStatus, "incomplete");
    assert.equal(report.coverage.rules![0].status, "not-applicable");
    assert.ok(report.diagnostics.length);
    assert.ok(!report.diagnostics.some(issue => issue.code === "keyed-state-evidence-unavailable"));
  });
});

test("unrelated compare-exchange entry is excluded without hiding baseline gaps", async () => {
  const neighbor = `
circuit exchange(a: Uint<16>, b: Uint<16>): Vector<2, Uint<16>> { return a >= b ? [a,b] : [b,a]; }
export circuit sorted(v: Vector<5, Uint<16>>): Vector<5, Uint<16>> {
  const a = exchange(v[0],v[1]); const b = exchange(a[1],v[2]); const c = exchange(b[1],v[3]);
  const d = exchange(c[1],v[4]); const e = exchange(a[0],b[0]); const f = exchange(e[1],c[0]);
  const g = exchange(f[1],d[0]); const h = exchange(e[0],f[0]); const i = exchange(h[1],g[0]);
  const j = exchange(h[0],i[0]); return [j[0],j[1],i[1],g[1],d[1]];
}`;
  withFiles({ "main.compact": positive + neighbor }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const before = [...program.entries];
    const relevant = program.entries.filter(entry => !entry.endsWith("::sorted"));
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false,true]) {
      const facts = new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,false,"all",false,true,false,false).analyzeSubset(relevant);
      facts.keyedStateEvidence = { entries: relevant, maxSteps: 40000, maxValues: 50000 };
      assert.equal(rule.run(facts).length,1); assert.deepEqual(facts.diagnostics,[]); assert.deepEqual(program.entries,before);
    }
    const report = scanFile(program.root,{detectors:[rule.id]});
    assert.equal(report.findings.length,1);
    assert.equal(report.coverage.rules!.find(row=>row.entry.endsWith("::sorted"))!.status,"not-applicable");
    assert.ok(report.ruleObservationWork!.find(item=>item.detectorId===rule.id)!.metrics.steps > 0);
  });
});
test("bounded applicability and relation work cannot certify dropped entries", () => {
  withFiles({"main.compact":positive},directory=>{
    const program=new Program(resolve(directory,"main.compact"));
    const facts=new Dataflow(program,40000,256,50000,"instructions",true,true,"equivalent-states",false,false,"all",false,true,false,false).analyze();
    facts.keyedStateEvidence={entries:[program.entries[0]],maxSteps:40000,maxValues:50000};
    const rejected=keyedStateInvariantObservations(facts);
    assert.ok(rejected.diagnostics.some(issue=>/Excluded entry/.test(issue.message)));
    const report=scanFile(program.root,{detectors:[rule.id],maxSteps:1});
    assert.equal(report.status,"incomplete"); assert.ok(report.diagnostics.some(issue=>issue.code==="keyed-state-applicability-budget"));
  });
});

test("resolved callback edges prevent false keyed-state absence", () => {
  withFiles({"main.compact": `import CompactStandardLibrary; export ledger present: Set<Field>;
    circuit check(id: Field): Boolean { return present.member(disclose(id)); }
    export circuit callbacks(ids: Vector<2,Field>): Vector<2,Boolean> { return map(check, ids); }`},directory=>{
    const program=new Program(resolve(directory,"main.compact"));
    assert.equal(keyedStateTargets(program,program.entries[0]).applicable,true);
    assert.equal(keyedStateTargets(program,program.entries[0],1).complete,false);
    const report=scanFile(program.root,{detectors:[rule.id]});
    assert.equal(report.coverage.rules![0].status,"complete");
    assert.equal(report.coverage.rules![0].evidence,"exact-observation");
  });
});

const detachedBranches = `
export ledger isolated: Map<Field,Field>;
export circuit detached(key: Field, flags: Vector<3,Boolean>): [] {
  if (disclose(flags[0])) { isolated.insert(disclose(key), 1 as Field); }
  if (disclose(flags[1])) { isolated.insert(disclose(key), 2 as Field); }
  if (disclose(flags[2])) { isolated.insert(disclose(key), 3 as Field); }
}`;

test("completed keyed component survives a disjoint applicable component's path gap", () => {
  withFiles({ "main.compact": positive + detachedBranches }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const plan = keyedStateComponents(program);
    assert.equal(plan.complete, true); assert.equal(plan.components.length, 2);
    const before = [...program.entries];
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false,true]) {
      const facts = new Dataflow(program,40000,2,50000,engine,cached,cached,"equivalent-states",false,false,"all",false,true,false,false).analyze();
      assert.ok(facts.diagnostics.some(issue => issue.code === "analysis-budget"));
      const result = keyedStateInvariantObservations(facts);
      assert.equal(result.observations.length, 1, `${engine}/${cached}`);
      assert.equal(result.diagnostics.length, 1);
      assert.ok(result.diagnostics[0].scope?.entry?.endsWith("::detached"));
    }
    const report = scanFile(program.root, { detectors: [rule.id], maxPaths: 2 });
    assert.equal(report.findings.length, 1); assert.equal(report.status, "incomplete");
    assert.equal(report.coverage.baselineStatus, "incomplete");
    assert.ok(report.diagnostics.some(issue => !issue.scope && issue.code === "analysis-budget"));
    assert.deepEqual(report.coverage.rules!.map(row => [row.entry.split("::").at(-1),row.status]),
      [["_approve","complete"],["consumeApproval","complete"],["detached","incomplete"]]);
    assert.ok(report.coverage.rules!.at(-1)!.diagnosticCodes.includes("keyed-state-evidence-unavailable"));
    assert.deepEqual(program.entries, before);
  });
});

test("disjoint incomplete state cannot fabricate corrected or lookalike keyed relationships", () => {
  for (const variant of ["corrected","lookalike"] as const) withFiles({"main.compact":
    readFileSync(base+`inconsistent-keyed-state-guard-case-17-${variant}.compact`,"utf8")+detachedBranches},directory=>{
    const report=scanFile(resolve(directory,"main.compact"),{detectors:[rule.id],maxPaths:2});
    assert.equal(report.findings.length,0); assert.equal(report.status,"incomplete");
    assert.deepEqual(report.coverage.rules!.map(row=>row.status),["complete","complete","incomplete"]);
  });
});

test("a may-alias root write or ordinary read dependency joins keyed components", () => {
  for (const source of [
    positive + detachedBranches.replace(/isolated\.insert\(disclose\(key\), [123] as Field\);/g, "approvals.insert(disclose(key) as Uint<128>, default<Bytes<32>>);"),
    positive.replace("approvals.insert(disclose(id), disclose(spender));", "const dependency = bridge; approvals.insert(disclose(id), disclose(spender));")
      + detachedBranches.replace("export ledger isolated:", "export ledger bridge: Field; export ledger isolated:").replace("if (disclose(flags[0]))", "const dependency = bridge; if (disclose(flags[0]))"),
  ]) withFiles({ "main.compact": source }, directory => {
    const program = new Program(resolve(directory,"main.compact"));
    const plan = keyedStateComponents(program); assert.equal(plan.complete,true); assert.equal(plan.components.length,1);
    const report = scanFile(program.root,{detectors:[rule.id],maxPaths:2});
    assert.equal(report.findings.length,0); assert.ok(report.coverage.rules!.every(row=>row.status==="incomplete"));
  });
});

test("non-membership root writers and zero-iteration callbacks remain dependencies", () => {
  withFiles({ "main.compact": positive + `
    circuit check(id: Uint<128>): Boolean { return tokenExists.member(disclose(id)); }
    export circuit callbacks(ids: Vector<0,Uint<128>>): Vector<0,Boolean> { return map(check,ids); }
    export circuit remove(id: Uint<128>): [] { approvals.remove(disclose(id)); }
  ` },directory=>{
    const program=new Program(resolve(directory,"main.compact"));
    const plan=keyedStateComponents(program); assert.equal(plan.complete,true); assert.equal(plan.components.length,1);
    assert.equal(plan.components[0].entries.length,4);
    const selected=program.entries.filter(entry=>!entry.endsWith("::remove"));
    const facts=new Dataflow(program,40000,256,50000,"instructions",true,true,"equivalent-states",false,false,"all",false,true,false,false).analyzeSubset(selected);
    facts.keyedStateEvidence={entries:selected,maxSteps:40000,maxValues:50000};
    const result=keyedStateInvariantObservations(facts); assert.equal(result.observations.length,0); assert.equal(result.diagnostics.length,4);
  });
});

test("component roots retain semantic module identity rather than spelling", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
    module Store<#N> { export ledger value: Map<Field,Field>; export circuit put(key: Field): [] { value.insert(disclose(key),0 as Field); } }
    import Store<1> prefix A_; import Store<2> prefix B_;
    export circuit first(key: Field): [] { A_put(key); }
    export circuit second(key: Field): [] { B_put(key); }
  ` },directory=>{
    const program=new Program(resolve(directory,"main.compact")); const plan=keyedStateComponents(program);
    assert.equal(plan.complete,true); assert.equal(plan.components.length,2);
    assert.notEqual(plan.components[0].roots[0],plan.components[1].roots[0]);
  });
});

test("unknown callee scope and unfinished dependency traversal cannot certify disjointness", () => {
  withFiles({ "main.compact": positive + `
    contract Callee { circuit notify(x: Field): []; }
    export circuit external(peer: Callee): [] { const publicPeer = disclose(peer); publicPeer.notify(0 as Field); }
  ` },directory=>{
    const program=new Program(resolve(directory,"main.compact")); const plan=keyedStateComponents(program);
    assert.equal(plan.complete,false); assert.match(plan.reason!,/unknown ledger scope/);
    assert.deepEqual(plan.components,[]);
    const report=scanFile(program.root,{detectors:[rule.id]});
    assert.equal(report.findings.length,0); assert.ok(report.coverage.rules!.every(row=>row.status==="incomplete"));
    assert.ok(report.coverage.rules!.every(row=>row.diagnosticCodes.includes("keyed-state-component-unavailable")));
  });
  withFiles({"main.compact":positive+detachedBranches},directory=>{
    const program=new Program(resolve(directory,"main.compact")); const plan=keyedStateComponents(program,1);
    assert.equal(plan.complete,false); assert.deepEqual(plan.components,[]);
  });
});

test("unsupported membership relation remains local to its certified component", () => {
  withFiles({ "main.compact": positive + `
    export ledger isolated: Set<Field>;
    export circuit unrelated(key: Field, flag: Boolean): [] {
      assert(isolated.member(disclose(key)) == disclose(flag), "unsupported relation");
    }
  ` },directory=>{
    const report=scanFile(resolve(directory,"main.compact"),{detectors:[rule.id]});
    assert.equal(report.findings.length,1); assert.equal(report.status,"incomplete");
    assert.deepEqual(report.coverage.rules!.map(row=>row.status),["complete","complete","incomplete"]);
    assert.ok(report.diagnostics.some(issue=>/nonconstant Boolean/.test(issue.message)&&issue.scope?.entry?.endsWith("::unrelated")));
  });
});

test("unrelated storage branches inside the writer still require whole-entry completion", () => {
  const source=positive.replace("auth: Bytes<32>","auth: Bytes<32>, flags: Vector<3,Boolean>")
    .replace("approvals.insert(disclose(id), disclose(spender));",`approvals.insert(disclose(id), disclose(spender));
      if (disclose(flags[0])) { isolated.insert(0 as Field,1 as Field); }
      if (disclose(flags[1])) { isolated.insert(1 as Field,2 as Field); }
      if (disclose(flags[2])) { isolated.insert(2 as Field,3 as Field); }`)+"\nexport ledger isolated: Map<Field,Field>;";
  withFiles({"main.compact":source},directory=>{
    const report=scanFile(resolve(directory,"main.compact"),{detectors:[rule.id],maxPaths:2});
    assert.equal(report.findings.length,0); assert.equal(report.status,"incomplete");
    assert.ok(report.coverage.rules!.every(row=>row.status==="incomplete"));
    assert.ok(report.coverage.rules!.every(row=>row.diagnosticCodes.includes("keyed-state-evidence-unavailable")));
  });
});


test("relation recheck exhaustion preserves unrelated absence rows in supervised reports", async () => {
  const directory = mkdtempSync(resolve(tmpdir(), "owned-keyed-protocol-"));
  try {
    const source = positive + "\n" + Array.from({ length: 30 }, (_, index) =>
      `export circuit read${index}(id: Uint<128>): Boolean { return tokenExists.member(disclose(id)); }`).join("\n")
      + "\nexport circuit unrelated(): Field { return 0 as Field; }\n";
    const file = resolve(directory, "main.compact"); writeFileSync(file, source);
    const program = new Program(file), plan = keyedStateComponents(program);
    assert.equal(plan.complete, true);
    const entries = plan.components.filter(component => component.applicable).flatMap(component => component.entries);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, false, "all", false, true, false, false).analyzeSubset(entries);
      assert.deepEqual(facts.diagnostics, []);
      facts.keyedStateEvidence = { entries, maxSteps: facts.metrics.steps + plan.work - 1, maxValues: 50000 };
      const result = keyedStateInvariantObservations(facts);
      assert.deepEqual(result.observations, []);
      assert.equal(result.diagnostics.length, entries.length);
      assert.ok(result.diagnostics.every(issue => entries.includes(issue.scope!.entry)));
    }
    // The first dependency certificate succeeds, but the shared relation recheck
    // has insufficient remaining work. Its gap cannot invalidate absence rows.
    const options = { detectors: [rule.id], maxSteps: plan.work + 100 };
    const direct = scanFile(file, options);
    assert.equal(direct.status, "incomplete");
    assert.equal(direct.coverage.baselineStatus, "complete");
    const unrelated = direct.coverage.rules!.find(row => row.entry.endsWith("::unrelated"))!;
    assert.equal(unrelated.status, "not-applicable");
    assert.equal(unrelated.evidence, "structural-absence");
    assert.deepEqual(unrelated.diagnosticCodes, []);
    assert.ok(direct.diagnostics.some(issue => issue.code === "keyed-state-evidence-unavailable"));
    assert.ok(direct.diagnostics.every(issue => issue.scope?.entry !== unrelated.entry));
    const supervised = await scanFileIsolated(file, options);
    assert.ok(!supervised.diagnostics.some(issue => issue.code.startsWith("worker-")), JSON.stringify(supervised.diagnostics));
    assert.equal(supervised.status, "incomplete");
    assert.deepEqual(supervised.coverage.rules, direct.coverage.rules);
    assert.deepEqual(supervised.diagnostics, direct.diagnostics);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
