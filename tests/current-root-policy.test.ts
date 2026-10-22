import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { currentRootObservations } from "../src/analysis/current-root.js";
import { currentRootPolicyMismatch as rule } from "../src/detectors/current-root.js";
import { resolvePolicies, validatePolicies, type Policies } from "../src/policies.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";
import { human, sarif } from "../src/reporting/index.js";

const header = `import CompactStandardLibrary;
ledger tree: HistoricMerkleTree<2,Field>;
export ledger accepted: MerkleTreeDigest;
`;
const selected: Policies = { currentRootMembership: [{ circuit: "entry", ledger: "tree" }] };
const entry = (body: string) => `export circuit entry(root:MerkleTreeDigest,b:Boolean):[]{${body} accepted=disclose(root);}`;
const check = 'assert(tree.checkRoot(disclose(root)),"membership");';

function fixture(source: string, reasons: string[], unavailable = false, policies = selected) {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file), resolved = resolvePolicies(program, policies);
    const circuit = resolved.currentRootMembership![0].circuit;
    let expectedPaths: string[] | undefined, expectedFindings: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, false, "all", true, false, false, false).analyzeCurrentRootEntry(circuit);
      assert.equal(facts.diagnostics.length, 0, JSON.stringify(facts.diagnostics));
      assert.deepEqual(facts.completedEntries, [circuit]);
      const paths = semanticPaths(facts); expectedPaths ??= paths; assert.deepEqual(paths, expectedPaths);
      const findings = rule.run(facts, resolved);
      assert.deepEqual(findings.map(finding => finding.metadata.reason), reasons);
      assert.equal(facts.diagnostics.length > 0, unavailable);
      if (unavailable) assert.ok(facts.diagnostics.every(issue => issue.code === "current-root-policy-unavailable" && issue.scope?.kind === "rule"));
      for (const finding of findings) {
        assert.equal(finding.metadata.freshnessPoint, "enforcement");
        assert.equal(finding.metadata.staleRootAcceptance, "not-proven");
      }
      expectedFindings ??= findings; assert.deepEqual(findings, expectedFindings);
    }
    const scan = scanFile(file, { detectors: [rule.id], policies });
    assert.equal(scan.coverage.baselineStatus, "complete", JSON.stringify(scan.diagnostics));
    assert.equal(scan.status, unavailable ? "incomplete" : "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(finding => finding.metadata.reason), reasons);
    assert.equal(scan.coverage.rules!.find(row => row.entry === circuit)!.status, unavailable ? "incomplete" : "complete");
  });
}

test("explicit current-root policy distinguishes historical storage, native current storage and cleared history", () => {
  fixture(header + entry(check), ["query-not-current-only"]);
  fixture(header.replace("HistoricMerkleTree", "MerkleTree") + entry(check), []);
  fixture(header + entry('tree.resetHistory();' + check), []);
  fixture(header + entry('tree.resetToDefault();' + check), []);
  fixture(header + entry('tree.insert(1 as Field);tree.resetHistory();' + check), []);
});

test("saved current checks lose guard-time freshness after overlapping insertion or history reset", () => {
  for (const kind of ["HistoricMerkleTree", "MerkleTree"]) for (const mutation of ["tree.insert(1 as Field);", "tree.resetToDefault();"]) {
    fixture(header.replace("HistoricMerkleTree", kind) + entry(`${kind === "HistoricMerkleTree" ? "tree.resetHistory();" : ""}
      const q=tree.checkRoot(disclose(root));${mutation}assert(q,"saved check");`), ["overlapping-write-before-enforcement"]);
  }
  fixture(header + entry('const q=tree.checkRoot(disclose(root));tree.resetHistory();assert(q,"old historic query");'), ["query-not-current-only"]);
});

test("check enforcement preserves Boolean aliases and polarity without treating negative guards or tautologies as membership", () => {
  for (const guard of ['assert(q==true,"true");','assert(q!=false,"not false");','const n=!q;assert(!n,"twice negated");'])
    fixture(header + entry('const q=tree.checkRoot(disclose(root));' + guard), ["query-not-current-only"]);
  for (const guard of ['assert(!q,"negative");','assert(q==false,"false");','assert(q==q,"tautology");'])
    fixture(header + entry('const q=tree.checkRoot(disclose(root));' + guard), []);
});

test("query in helper retains invocation operands, saved Boolean and real mutation order", () => {
  fixture(header + `circuit query(root:MerkleTreeDigest):Boolean{return tree.checkRoot(disclose(root));}
    circuit require(q:Boolean):[]{assert(q,"helper guard");}` + entry('tree.resetHistory();const q=query(root);tree.insert(1 as Field);require(q);'), ["overlapping-write-before-enforcement"]);
  fixture(header + `circuit query(root:MerkleTreeDigest):Boolean{return tree.checkRoot(disclose(root));}`
    + entry('tree.resetHistory();const first=query(root);tree.insert(1 as Field);tree.resetHistory();const fresh=query(root);assert(fresh,"fresh");'), []);
});

test("positive optional branch guard is reviewed on its own history; later tree writes are outside guard-time contract", () => {
  fixture(header + entry('if(tree.checkRoot(disclose(root))){accepted=disclose(root);}'), ["query-not-current-only"]);
  fixture(header + entry('tree.resetHistory();' + check + 'tree.insert(1 as Field);'), []);
});

test("Map sibling writes preserve guard-time freshness while aliases and ancestor replacement remove it", () => {
  const nested = `import CompactStandardLibrary;ledger trees:Map<Field,MerkleTree<2,Field>>;
    export ledger accepted:MerkleTreeDigest;`;
  const policies: Policies = { currentRootMembership: [{ circuit: "entry", ledger: "trees" }] };
  for (const [mutation, reasons] of [
    ['trees.lookup(2 as Field).insert(1 as Field);', []],
    ['trees.lookup(disclose(key)).insert(1 as Field);', ["overlapping-write-before-enforcement"]],
    ['trees.resetToDefault();', ["overlapping-write-before-enforcement"]],
    ['trees.remove(1 as Field);', ["overlapping-write-before-enforcement"]],
    ['trees.insertDefault(1 as Field);', ["overlapping-write-before-enforcement"]],
  ] as const) fixture(nested + `export circuit entry(root:MerkleTreeDigest,key:Field):[]{
    const q=trees.lookup(1 as Field).checkRoot(disclose(root));${mutation}assert(q,"saved child");accepted=disclose(root);}`, [...reasons], false, policies);
  fixture(nested + `export circuit entry(root:MerkleTreeDigest,key:Field):[]{
    assert(trees.lookup(disclose(key)).checkRoot(disclose(root)),"dynamic current");accepted=disclose(root);}`, [], false, policies);
  fixture(nested.replace('Map<Field,MerkleTree', 'Map<Field,HistoricMerkleTree') + `export circuit entry(root:MerkleTreeDigest,key:Field):[]{
    assert(trees.lookup(disclose(key)).checkRoot(disclose(root)),"dynamic historic");accepted=disclose(root);}`, ["query-not-current-only"], false, policies);
});

test("nonliteral Boolean equality chains are explicitly unavailable, never a clean current-root certificate", () => {
  fixture(header + entry('const q=tree.checkRoot(disclose(root));assert(b==q,"alias");tree.insert(1 as Field);assert(b,"enforce alias");'), [], true);
});

test("numeric Boolean encodings do not erase enforcement into a clean policy result", () => {
  for (const guard of ['assert((q as Field)==(1 as Field),"encoded true");',
    'assert((q as Field)==(0 as Field),"encoded false");',
    'assert((q as Uint<8>)>(0 as Uint<8>),"encoded positive");'])
    fixture(header + entry('const q=tree.checkRoot(disclose(root));' + guard), [], true);
});

test("native digest encodings of observed check Booleans cannot become a clean absence certificate", () => {
  fixture(header + entry('const q=tree.checkRoot(disclose(root));assert(persistentHash<Boolean>(q)==persistentHash<Boolean>(true),"encoded membership");'), [], true);
  fixture(header + entry('const q=tree.checkRoot(disclose(root));assert(persistentHash<Vector<2,Boolean>>([q,true])==persistentHash<Vector<2,Boolean>>([true,true]),"nested encoding");'), [], true);
  fixture(header + entry('const unused=tree.checkRoot(disclose(root));assert(persistentHash<Boolean>(b)==persistentHash<Boolean>(true),"unrelated Boolean hash");'), []);
});

test("equivalent repeated queries retain all candidate invocation sites without selecting the unused one", () => withFiles({ "main.compact": header
  + 'circuit query(root:MerkleTreeDigest):Boolean{return tree.checkRoot(disclose(root));}'
  + entry('tree.resetHistory();const first=query(root);const unused=query(root);tree.insert(1 as Field);assert(first,"saved first");') }, directory => {
  const file = resolve(directory, "main.compact");
  if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
  const scan = scanFile(file, { detectors: [rule.id], policies: selected });
  assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
  assert.equal(scan.findings.length, 1);
  assert.equal(scan.findings[0].metadata.queryOccurrence, "equivalent-candidates");
  const queries = scan.findings[0].metadata.candidateQueries as { invocationSites: { start: number }[] }[];
  assert.equal(queries.length, 2);
  assert.notDeepEqual(queries[0].invocationSites, queries[1].invocationSites);
  assert.equal(scan.findings[0].source, undefined);
}));

test("certified exact histories without a query remain quiet, including skipped-query branches", () => {
  fixture(header + entry('if(disclose(b)){' + check + '}'), ["query-not-current-only"]);
  fixture(header + entry(''), []);
});

test("saved query can be fresh at an earlier guard and uncertified when reused after mutation", () => {
  fixture(header + entry('tree.resetHistory();const q=tree.checkRoot(disclose(root));assert(q,"first guard");tree.insert(1 as Field);assert(q,"later guard");'), ["overlapping-write-before-enforcement"]);
});

test("checkpoint-projected guard positions cannot certify an earlier prefix", () => {
  fixture(header + entry('tree.resetHistory();const q=tree.checkRoot(disclose(root));accepted=disclose(root);kernel.checkpoint();tree.insert(1 as Field);assert(q,"late saved guard");'), [], true);
});

test("policy observation exhaustion stays separate from baseline completion and is reported in human/JSON/SARIF", () => withFiles({ "main.compact": header + entry(check.repeat(8)) }, directory => {
  const file = resolve(directory, "main.compact"), unconstrained = scanFile(file, { detectors: [rule.id], policies: selected });
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const observed = unconstrained.ruleObservationWork![0].metrics;
  const baseline = unconstrained.metrics.steps - observed.steps;
  assert.ok(observed.steps - 1 >= baseline, "fixture must separate baseline work from extra rule evidence");
  const scan = scanFile(file, { detectors: [rule.id], policies: selected, maxSteps: observed.steps - 1 });
  assert.equal(scan.coverage.baselineStatus, "complete");
  assert.equal(scan.status, "incomplete");
  assert.deepEqual(scan.findings, []);
  assert.ok(scan.diagnostics.every(issue => issue.scope?.detectorId === rule.id));
  assert.ok(scan.coverage.rules!.some(row => row.status === "incomplete" && row.detectorId === rule.id));
  assert.match(human(scan), /incomplete/i);
  assert.match(JSON.stringify(sarif(scan)), /current-root-policy-mismatch/);
}));

test("current-root policy is opt-in; no policy does not infer freshness intent", () => withFiles({ "main.compact": header + entry(check) }, directory => {
  const file = resolve(directory, "main.compact");
  const defaultScan = scanFile(file), unconfigured = scanFile(file, { detectors: [rule.id] });
  assert.ok(!defaultScan.coverage.detectors.includes(rule.id));
  assert.deepEqual(unconfigured.findings, []);
  assert.ok(unconfigured.coverage.rules!.every(row => row.status === "not-applicable"));
  const configured = scanFile(file, { detectors: [rule.id], policies: selected });
  assert.match(human(configured), /current-root-policy-mismatch/);
  const sarifReport = sarif(configured) as { runs: { results: { ruleId: string }[] }[] };
  assert.equal(sarifReport.runs[0].results![0].ruleId, rule.id);
}));

test("lost history positions, checkpoint prefixes and exhausted evidence remain rule-scoped incomplete", () => withFiles({ "main.compact": header + entry('tree.resetHistory();' + check) }, directory => {
  const program = new Program(resolve(directory, "main.compact")), policies = resolvePolicies(program, selected), circuit = program.entries[0];
  for (const fault of ["query-position", "predicate-position", "operation-position", "work-budget", "value-budget"] as const) {
    const facts = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, false, "all", true, false, false, false).analyzeCurrentRootEntry(circuit);
    const path = facts.paths[0];
    if (fault === "query-position") delete path.operations![0].writesBefore;
    if (fault === "predicate-position") path.predicates![0].writesBefore = path.writes.length + 1;
    if (fault === "operation-position") path.predicates![0].operationsBefore = path.operations!.length + 1;
    if (fault === "work-budget") facts.currentRootEvidence!.maxSteps = facts.metrics.steps + 1;
    if (fault === "value-budget") facts.currentRootEvidence!.maxValues = facts.metrics.abstractValues;
    const observed = currentRootObservations(facts, policies);
    assert.deepEqual(observed.observations, []);
    assert.equal(observed.diagnostics.length, 1, fault);
    assert.equal(observed.diagnostics[0].scope?.kind, "rule");
  }
}));

test("selectors require canonical native trees, exported circuits and bounded dense configuration", () => withFiles({ "main.compact": header + entry(check) }, directory => {
  const file = resolve(directory, "main.compact"), location = new Program(file).rootSource.ast.span;
  assert.throws(() => validatePolicies({ currentRootMembership: Array(2) }, location), /dense/);
  assert.throws(() => validatePolicies({ currentRootMembership: Array.from({ length: 65 }, () => ({ circuit: "entry", ledger: "tree" })) }, location), /64/);
  const invalid = scanFile(file, { detectors: [rule.id], policies: { currentRootMembership: [{ circuit: "entry", ledger: "accepted" }] } });
  assert.equal(invalid.status, "incomplete"); assert.equal(invalid.diagnostics[0].code, "invalid-policy");
}));

test("current-root guard policy retains its contract on pinned historical and newer compiler profiles", () => {
  const profiles = [["0.30.0", process.env.COMPACTC_030_TEST], ["0.31.1", process.env.COMPACTC_031_TEST],
    ["0.33.0-rc.2", process.env.COMPACTC_033_RC2_TEST], ["0.35.0", process.env.COMPACTC_035_TEST]] as const;
  for (const [version, compiler] of profiles) for (const kind of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-current-root-${kind}.compact`);
    if (compiler) {
      const compiled = validateWithCompiler(compiler, file, [], 30000, 2, version);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const report = scanFile(file, { compilerVersion: version, detectors: [rule.id],
      policies: { currentRootMembership: [{ circuit: "record", ledger: "permitted" }] } });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(finding => finding.location.line), kind === "positive" ? [32] : []);
  }
});
