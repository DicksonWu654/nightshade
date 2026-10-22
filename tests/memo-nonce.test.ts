import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile } from "../src/index.js";
import { memoNoncePairs } from "../src/dataflow/memo-nonce.js";
import { resettableMemoNonce as rule } from "../src/detectors/memo-nonce.js";
import { resettableListNonce as coinRule } from "../src/detectors/resettable-nonce.js";
import { detectors } from "../src/detectors/index.js";
import { MEMO_NONCE_APPEND } from "../src/semantic/memo-nonce-targets.js";
import { withFiles } from "./helpers.js";

const prefix = `import CompactStandardLibrary;
ledger queues: Map<Bytes<32>, List<Bytes<32>>>;
witness fresh(): Bytes<32>;
`;
const positiveBody = `assert(recipient.is_left,"account");
assert(recipient.left.bytes == disclose(key),"recipient");
const i = queues.lookup(disclose(key)).length() as Uint<64>;
const coin = evolveNonce(i,pad(32,"coin"));
const payload = evolveNonce(i,pad(32,"memo"));
mintShieldedToken(default<Bytes<32>>,1,coin,disclose(recipient));
queues.lookup(disclose(key)).pushFront(payload);`;
const source = (body = positiveBody, reset = "queues.lookup(disclose(key)).resetToDefault();", helpers = "") => `${prefix}${helpers}
export circuit credit(key: Bytes<32>, other: Bytes<32>, recipient: Either<ZswapCoinPublicKey,ContractAddress>): [] { ${body} }
export circuit prune(key: Bytes<32>): [] { ${reset} }`;

function analyze(program: Program, engine: "instructions" | "expressions", cached: boolean, observe = true) {
  return new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,true,"all",false,false,false,true,
    false,false,true,false,true,false,observe ? new Set([MEMO_NONCE_APPEND]) : undefined).analyze();
}

function check(input: string, expected: number) {
  withFiles({ "main.compact": input }, directory => {
    const file = resolve(directory,"main.compact"), program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions","expressions"] as const) for (const cached of [false,true]) {
      const facts = analyze(program,engine,cached);
      assert.deepEqual(facts.diagnostics,[]);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics,[]);
      assert.equal(findings.length,expected,JSON.stringify(findings));
      baseline ??= findings;
      assert.deepEqual(findings,baseline);
      for (const finding of findings) {
        assert.equal(finding.severity,"info");
        assert.equal(finding.metadata.payloadRole,"not-inferred");
        assert.equal(finding.metadata.consumerRelation,"same-exact-selected-list-revision");
        assert.equal(finding.metadata.recipientRelation,"active-account-bytes-equal-selected-key");
      }
      assert.equal(memoNoncePairs(facts,program.entries,0).complete,false);
    }
    for (const experimentalCounterQueries of [false,true]) {
      const report = scanFile(file,{detectors:[rule.id],experimentalCounterQueries});
      assert.equal(report.status,"complete",JSON.stringify(report.diagnostics));
      assert.equal(report.findings.length,expected);
    }
  });
}

test("paired canonical coin and direct stored evolution bind exact selected recipient List", () => check(source(),1));
test("independent recipient selectors do not become equal through may-alias storage", () => {
  check(source(positiveBody.replace("pushFront(payload)","pushFront(payload)").replace("queues.lookup(disclose(key)).pushFront","queues.lookup(disclose(other)).pushFront")),0);
  check(source(positiveBody.replace("recipient.left.bytes == disclose(key)","recipient.left.bytes != disclose(key)")),0);
  check(source(positiveBody.replace('assert(recipient.left.bytes == disclose(key),"recipient");',"")),0);
});
test("transitive successful recipient equality is immutable operand evidence", () => {
  check(source(positiveBody.replace('assert(recipient.left.bytes == disclose(key),"recipient");',
    'assert(recipient.left.bytes == disclose(other),"recipient"); assert(disclose(other)==disclose(key),"relay");')),1);
});
test("fresh seed or independent coin index does not establish paired sole-extent evolution", () => {
  check(source(positiveBody.replace('pad(32,"memo")','disclose(fresh())')),0);
  check(source(positiveBody.replace('evolveNonce(i,pad(32,"coin"))','evolveNonce(0,disclose(fresh()))')),0);
  check(source(positiveBody.replace('evolveNonce(i,pad(32,"memo"))','evolveNonce(i+1,pad(32,"memo"))')),0);
});
test("fresh coin with resettable stored evolution is paired-scope quiet, not memo repair", () => {
  check(source(positiveBody.replace('evolveNonce(i,pad(32,"coin"))','disclose(fresh())')),0);
  const report = scanFile(resolve("tests/corpus/synthetic-regressions/state16/resettable-list-nonce-case-18-lookalike.compact"),{detectors:[rule.id]});
  assert.equal(report.status,"complete",JSON.stringify(report.diagnostics));
  assert.equal(report.findings.length,0);
});
test("an arbitrary hash or encoded index payload is not an exact evolved payload", () => {
  check(source(positiveBody.replace("pushFront(payload)","pushFront(persistentHash<Bytes<32>>(payload))")),0);
  check(source(positiveBody.replace("pushFront(payload)","pushFront(i as Bytes<32>)")),0);
  check(source(positiveBody.replace("pushFront(payload)","pushFront(disclose(fresh()))")),0);
});
test("coin and payload snapshots and append receiver must share the current revision", () => {
  check(source(positiveBody.replace('const payload =', 'queues.lookup(disclose(key)).pushFront(default<Bytes<32>>); const payload =')
    .replace('evolveNonce(i,pad(32,"memo"))','evolveNonce(queues.lookup(disclose(key)).length() as Uint<64>,pad(32,"memo"))')),0);
  check(source(positiveBody.replace("queues.lookup(disclose(key)).pushFront(payload);",
    "queues.lookup(disclose(key)).resetToDefault(); queues.lookup(disclose(key)).pushFront(payload);")),0);
});
test("different literal reset selection and aborted reset cannot provide cross-entry reset", () => {
  const fixed = positiveBody.replaceAll("disclose(key)",'pad(32,"A")');
  check(source(fixed,'queues.lookup(pad(32,"B")).resetToDefault();'),0);
  check(source(fixed,'queues.lookup(pad(32,"A")).resetToDefault();'),1);
  check(source(positiveBody,'queues.lookup(disclose(key)).resetToDefault(); assert(false,"abort");'),0);
});
test("absent-slot initialization and empty-only replacement cannot restart a used extent", () => {
  check(source(positiveBody,'assert(!queues.member(disclose(key)),"absent"); queues.insertDefault(disclose(key));'),0);
  check(source(positiveBody,'assert(queues.lookup(disclose(key)).isEmpty(),"empty"); queues.lookup(disclose(key)).resetToDefault();'),0);
  check(source(positiveBody,'assert(queues.lookup(disclose(key)).length()==0,"empty"); queues.lookup(disclose(key)).resetToDefault();'),0);
  check(source(positiveBody,'assert(queues.lookup(disclose(key)).length()==1,"observed"); queues.lookup(disclose(key)).resetToDefault();'),1);
});
test("exclusive histories cannot donate one another's consumers", () => {
  const body = positiveBody.replace('mintShieldedToken(default<Bytes<32>>,1,coin,disclose(recipient));\nqueues.lookup(disclose(key)).pushFront(payload);',
    'if (disclose(key)==disclose(other)) { mintShieldedToken(default<Bytes<32>>,1,coin,disclose(recipient)); } else { queues.lookup(disclose(key)).pushFront(payload); }');
  check(source(body),0);
});
test("ordinary canonical helper return and List mutation replay preserve operand snapshots", () => {
  const helpers = `circuit derive(i: Uint<64>, seed: Bytes<32>): Bytes<32> {return evolveNonce(i,seed);}
  circuit append(key: Bytes<32>, value: Bytes<32>): [] {queues.lookup(disclose(key)).pushFront(value);}`;
  check(source(positiveBody.replaceAll("evolveNonce(","derive(").replace("queues.lookup(disclose(key)).pushFront(payload);","append(key,payload);"),undefined,helpers),1);
});
test("local evolveNonce namesake does not supply canonical evolution", () => {
  const local = source(positiveBody.replace('evolveNonce(i,pad(32,"memo"))','evolveNonce(i>0)'))
    .replace("import CompactStandardLibrary;","import CompactStandardLibrary;\nimport CompactStandardLibrary prefix S_;")
    .replace('evolveNonce(i,pad(32,"coin"))','S_evolveNonce(i,pad(32,"coin"))');
  check(local+'\ncircuit evolveNonce(flag: Boolean): Bytes<32> {return pad(32,"marker");}',0);
});
test("selected observer with incomplete cross-entry evidence is diagnostic", () => {
  withFiles({"main.compact":source()},directory => {
    const program = new Program(resolve(directory,"main.compact"));
    for (const missing of ["entry","predicates","mint"] as const) {
      const facts = analyze(program,"instructions",true);
      if (missing === "entry") facts.completedEntries.pop();
      else if (missing === "predicates") facts.predicateScope = "witness";
      else facts.mintEvidence = undefined;
      assert.deepEqual(rule.run(facts),[]);
      assert.ok(facts.diagnostics.some(issue=>issue.code==="memo-nonce-evidence-unavailable"));
    }
    const report=scanFile(program.root,{detectors:[rule.id],maxSteps:8});
    assert.equal(report.status,"incomplete"); assert.equal(report.findings.length,0);
  });
});
test("direct registry dispatch preserves complete ordinary facts and findings", () => {
  withFiles({"main.compact":source()},directory => {
    const program = new Program(resolve(directory,"main.compact"));
    const ordinary = new Dataflow(program).analyze();
    const before = structuredClone({diagnostics:ordinary.diagnostics,paths:ordinary.paths,metrics:ordinary.metrics});
    assert.deepEqual(rule.run(ordinary),[]);
    assert.deepEqual({diagnostics:ordinary.diagnostics,paths:ordinary.paths,metrics:ordinary.metrics},before);
    const baseline = new Dataflow(program).analyze(), withCompanion = new Dataflow(program).analyze();
    const expected=detectors.filter(detector=>detector!==rule).flatMap(detector=>detector.run(baseline));
    assert.deepEqual(detectors.flatMap(detector=>detector.run(withCompanion)),expected);
    assert.deepEqual(withCompanion.diagnostics,baseline.diagnostics);
    assert.deepEqual(withCompanion.paths,baseline.paths);
    assert.deepEqual(withCompanion.metrics,baseline.metrics);
  });
});
test("companion is opt-in and separate observations preserve complete coin finding objects", () => {
  withFiles({"main.compact":source()},directory => {
    const file=resolve(directory,"main.compact");
    assert.equal(rule.defaultEnabled,false);
    const coin=scanFile(file,{detectors:[coinRule.id]});
    const paired=scanFile(file,{detectors:[coinRule.id,rule.id]});
    assert.deepEqual(paired.findings.filter(f=>f.detectorId===coinRule.id),coin.findings);
    assert.equal(paired.findings.filter(f=>f.detectorId===rule.id).length,1);
    const ordinary=analyze(new Program(file),"instructions",true,false);
    assert.equal(ordinary.paths.some(path=>path.operations?.some(op=>op.kind==="list-append")),false);
    for(const path of ordinary.paths) for(const op of path.operations??[]) {
      assert.equal(op.args[2]?.nonceEvolution?.index.listLengthSnapshot?.receiver,undefined);
    }
  });
});
