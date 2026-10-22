import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { observeListGrowth } from "../src/analysis/list-growth-observation.js";
import { zeroTransferRetainedListReview as rule } from "../src/detectors/list-growth.js";
import { withFiles } from "./helpers.js";

const header = "import CompactStandardLibrary;\nexport ledger records:Map<Bytes<32>,List<Bytes<32>>>;\n";
const parameters = "recipient:Bytes<32>,color:Bytes<32>,amount:Uint<128>,memo:Bytes<32>";
const send = 'sendUnshielded(disclose(color),disclose(amount),right<ContractAddress,UserAddress>(UserAddress{bytes:disclose(recipient)}));';
const append = 'records.lookup(disclose(recipient)).pushFront(disclose(memo));';
const length = 'const before=records.lookup(disclose(recipient)).length();';
const positive = `${header}export circuit entry(${parameters}):[]{${length}${send}${append}}`;
function fixture(source: string, check: (file: string, program: Program) => void) {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    check(file, new Program(file));
  });
}
function matrix(program: Program, count: number, incomplete = false) {
  let baseline: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const result = observeListGrowth(program, rule, {}, undefined, { engine, cached });
    assert.equal(result.findings.length, count, JSON.stringify(result));
    assert.equal(result.diagnostics.length > 0, incomplete, JSON.stringify(result.diagnostics));
    assert.deepEqual(result.work.limits, { maxSteps: 40000, maxPaths: 256, maxValues: 50000 });
    baseline ??= result.findings; assert.deepEqual(result.findings, baseline);
    assert.ok(result.findings.every(row => row.severity === "info" && row.metadata.minimum === "0"
      && row.metadata.contention === "not-inferred" && row.metadata.applicationImpact === "not-inferred"));
  }
}

test("exact actual send and retained List share recipient; default remains opt-in", () => fixture(positive, (file, program) => {
  matrix(program, 1);
  const result = observeListGrowth(program, rule, {});
  assert.equal(result.findings[0].metadata.sameRevisionLengthBeforeAppend, true);
  assert.equal(scanFile(file, { detectors: [rule.id] }).findings.filter(row => row.detectorId === rule.id).length, 1);
  assert.equal(scanFile(file).findings.filter(row => row.detectorId === rule.id).length, 0);
}));

test("late actual guards and independent positive amount retain exact bounds", () => {
  for (const guard of ['assert(disclose(amount)>0,"late");','assert(disclose(amount)!=0,"late");'])
    fixture(`${header}export circuit entry(${parameters}):[]{${send}${append}${guard}}`, (_file, program) => matrix(program, 0));
  fixture(`${header}export circuit entry(${parameters},unused:Uint<128>):[]{assert(disclose(amount)>0,"actual");${send}${append}}`, (_file, program) => matrix(program, 0));
  fixture(`${header}export circuit entry(${parameters},unused:Uint<128>):[]{assert(disclose(unused)>0,"unused");${send}${append}}`, (_file, program) => matrix(program, 1));
});

test("aliases and mandatory equality bind the recipient; inequality and dependency overlap do not", () => {
  fixture(`${header}export circuit entry(${parameters},other:Bytes<32>):[]{assert(disclose(other)==disclose(recipient),"same");${send}${append.replace('disclose(recipient)', 'disclose(other)')}}`, (_file, program) => matrix(program, 1));
  fixture(`${header}export circuit entry(${parameters},other:Bytes<32>):[]{assert(disclose(other)!=disclose(recipient),"different");${send}${append.replace('disclose(recipient)', 'disclose(other)')}}`, (_file, program) => matrix(program, 0));
  fixture(`${header}export circuit entry(${parameters}):[]{const alias=recipient;${send}${append.replace('disclose(recipient)', 'disclose(alias)')}}`, (_file, program) => matrix(program, 1));
  fixture(`${header}export circuit entry(${parameters}):[]{const key=(recipient as Field) as Bytes<32>;${send}${append.replace('disclose(recipient)', 'disclose(key)')}}`, (_file, program) => matrix(program, 0));
});

test("exclusive branch effects and independent exported entries never form a pair", () => {
  fixture(`${header}export circuit entry(${parameters},flag:Boolean):[]{if(disclose(flag)){${send}}else{${append}}}`, (_file, program) => matrix(program, 0));
  fixture(`${header}export circuit transfer(${parameters}):[]{${send}}\nexport circuit store(${parameters}):[]{${append}}`, (_file, program) => matrix(program, 0));
});

test("ordinary helper transfers, callback calls and zero iteration preserve order", () => {
  fixture(`${header}circuit work(${parameters}):Field{${length}${send}${append}return 0 as Field;}
export circuit entry(${parameters}):Field{return work(recipient,color,amount,memo);}`, (_file, program) => matrix(program, 1));
  fixture(`${header}circuit work(${parameters}):Field{${send}${append}return 0 as Field;}
export circuit entry(${parameters}):Vector<1,Field>{return map(work,[recipient],[color],[amount],[memo]);}
export circuit empty():Vector<0,Field>{return map(work,[] as Vector<0,Bytes<32>>,[] as Vector<0,Bytes<32>>,[] as Vector<0,Uint<128>>,[] as Vector<0,Bytes<32>>);}`, (_file, program) => {
    matrix(program, 1);
    assert.deepEqual(observeListGrowth(program, rule, {}).findings.map(row => row.metadata.entry), ["entry"]);
  });
});

test("later overlapping pop/remove/reset refuse retention; later push preserves it", () => {
  for (const mutation of ['records.lookup(disclose(recipient)).popFront();','records.remove(disclose(recipient));','records.resetToDefault();'])
    fixture(`${header}export circuit entry(${parameters}):[]{${send}${append}${mutation}}`, (_file, program) => matrix(program, 0, true));
  fixture(`${header}export circuit entry(${parameters}):[]{${send}${append}${append}}`, (_file, program) => matrix(program, 2));
});

test("length subtype needs the same revision; actual append needs no length query", () => {
  fixture(`${header}export circuit entry(${parameters},other:Bytes<32>):[]{${length}records.insertDefault(disclose(other));${send}${append}}`, (_file, program) => {
    matrix(program, 1);
    assert.equal(observeListGrowth(program, rule, {}).findings[0].metadata.sameRevisionLengthBeforeAppend, false);
  });
  fixture(`${header}export circuit entry(${parameters}):[]{${send}${append}}`, (_file, program) => {
    matrix(program, 1);
    assert.equal(observeListGrowth(program, rule, {}).findings[0].metadata.sameRevisionLengthBeforeAppend, false);
  });
});

test("wildcard storage rereads do not identify recipient bytes; immutable saved snapshots do", () => {
  const store = `${header}export ledger addresses:Map<Bytes<32>,Bytes<32>>;`;
  fixture(`${store}export circuit entry(${parameters},key:Bytes<32>):[]{
    sendUnshielded(disclose(color),disclose(amount),right<ContractAddress,UserAddress>(UserAddress{bytes:addresses.lookup(disclose((key as Field) as Bytes<32>))}));
    records.lookup(addresses.lookup(disclose((key as Field) as Bytes<32>))).pushFront(disclose(memo));}`, (_file, program) => matrix(program, 0));
  fixture(`${store}export circuit entry(${parameters},key:Bytes<32>):[]{const saved=addresses.lookup(disclose(key));
    sendUnshielded(disclose(color),disclose(amount),right<ContractAddress,UserAddress>(UserAddress{bytes:saved}));
    records.lookup(saved).pushFront(disclose(memo));}`, (_file, program) => matrix(program, 1));
});

test("recipient arm constraints are history-local, and native namesakes are quiet", () => {
  fixture(`${header}export circuit entry(color:Bytes<32>,amount:Uint<128>,memo:Bytes<32>,to:Either<ContractAddress,UserAddress>):[]{
    assert(!disclose(to.is_left),"user");sendUnshielded(disclose(color),disclose(amount),disclose(to));records.lookup(disclose(to.right.bytes)).pushFront(disclose(memo));}`, (_file, program) => matrix(program, 1));
  fixture(`${header}export circuit entry(color:Bytes<32>,amount:Uint<128>,memo:Bytes<32>,to:Either<ContractAddress,UserAddress>):[]{
    sendUnshielded(disclose(color),disclose(amount),disclose(to));records.lookup(disclose(to.right.bytes)).pushFront(disclose(memo));}`, (_file, program) => matrix(program, 1));
  fixture(`${header}module Local {export circuit sendUnshielded(color:Bytes<32>,amount:Uint<128>,recipient:Bytes<32>):[]{return;}}
import Local prefix Local_;
export circuit entry(${parameters}):[]{Local_sendUnshielded(disclose(color),disclose(amount),disclose(recipient));${append}}`, (_file, program) => matrix(program, 0));
});

test("resource refusal and missing baseline remain explicit without resetting budgets", () => fixture(positive, (_file, program) => {
  for (const limits of [{ maxSteps: 1 }, { maxPaths: 0 }, { maxValues: 1 }, { maxValues: 500 }]) {
    const result = observeListGrowth(program, rule, limits);
    assert.equal(result.findings.length, 0); assert.ok(result.diagnostics.length);
    assert.ok(result.coverage.some(row => row.status === "incomplete"));
  }
  const result = observeListGrowth(program, rule, {}, new Set());
  assert.equal(result.findings.length, 0); assert.ok(result.diagnostics.length);
  for (const fault of ["congruence", "proof-budget", "history"] as const) {
    const selected = new Dataflow(program).analyzeZeroTransferListEntry(program.entries[0]);
    if (fault === "proof-budget") selected.listGrowthEvidence!.maxSteps = selected.metrics.steps;
    if (fault === "history") selected.paths[0].complementaryHistory = undefined;
    if (fault === "congruence") {
      const append = selected.paths[0].operations!.find(row => row.kind === "list-append")!;
      append.args[0].region!.collectionSelectors![0].value = { flows: [], ledger: new Set(), type: "Bytes<32>" };
    }
    assert.equal(rule.run(selected).length, 0);
    assert.ok(selected.diagnostics.some(row => row.code === "list-growth-evidence-incomplete"));
  }
  const facts = new Dataflow(program).analyze();
  assert.equal(rule.run(facts).length, 0); assert.ok(facts.diagnostics.some(row => row.code === "list-growth-evidence-incomplete"));
}));

test("selected refusal retains one entry diagnostic regardless of unrelated exports", () => {
  const source = `${header}export circuit failing(${parameters}):[]{${send}${append}records.lookup(disclose(recipient)).popFront();}`;
  const unrelated = Array.from({ length: 30 }, (_, index) => `export circuit quiet${index}():[]{return;}`).join("\n");
  fixture(source, (_singleFile, single) => fixture(`${source}\n${unrelated}`, (_manyFile, many) => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const entry = many.entries.find(id => many.symbols.get(id)?.name === "failing")!;
      const selected = new Dataflow(many, 40000, 256, 50000, engine, cached, cached).analyzeZeroTransferListEntry(entry);
      const reference = new Dataflow(single, 40000, 256, 50000, engine, cached, cached).analyzeZeroTransferListEntry(single.entries[0]);
      assert.equal(rule.run(selected).length, 0);
      assert.equal(rule.run(reference).length, 0);
      assert.equal(selected.diagnostics.length, 1);
      assert.deepEqual(selected.diagnostics[0].scope, { kind: "rule", detectorId: rule.id, entry });
      assert.deepEqual(selected.diagnostics[0].location, many.functions.get(entry)!.declaration.span);
      assert.deepEqual(selected.metrics, reference.metrics);
      const unselected = new Dataflow(many, 40000, 256, 50000, engine, cached, cached).analyzeSubset([entry]);
      assert.equal(rule.run(unselected).length, 0);
      assert.equal(unselected.diagnostics.length, 1);
      assert.equal(unselected.diagnostics[0].scope, undefined);
      assert.deepEqual(unselected.diagnostics[0].location, many.rootSource.ast.span);
    }
  }));
});

test("multi-entry refusal preserves coverage scope and cumulative value allowance", () => {
  const source = `${header}
export circuit failing(${parameters}):[]{${send}${append}records.lookup(disclose(recipient)).popFront();}
export circuit quiet():[]{return;}
export circuit success(${parameters}):[]{${send}${append}}`;
  fixture(source, (_file, program) => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const execution = { engine, cached }, completed = new Set(program.entries);
      const full = observeListGrowth(program, rule, {}, completed, execution);
      assert.deepEqual(full.coverage.map(row => row.status), ["incomplete", "not-applicable", "complete"]);
      assert.equal(full.findings.length, 1);
      assert.equal(full.findings[0].metadata.entry, "success");
      assert.equal(full.diagnostics.length, 2);
      assert.ok(full.diagnostics.every(issue => issue.scope?.entry === program.entries[0]));
      assert.deepEqual(full.coverage[0].diagnosticCodes, ["list-growth-evidence-incomplete", "list-growth-preparation-unavailable"]);
      assert.ok(full.coverage.slice(1).every(row => row.diagnosticCodes.length === 0));
      const maxValues = full.work.metrics.abstractValues - 1;
      const limited = observeListGrowth(program, rule, { maxValues }, completed, execution);
      assert.deepEqual(limited.coverage.map(row => row.status), ["incomplete", "not-applicable", "incomplete"]);
      assert.equal(limited.findings.length, 0);
      assert.ok(limited.work.metrics.abstractValues >= maxValues);
      assert.equal(limited.work.limits.maxValues, maxValues);
      assert.deepEqual(limited.diagnostics.filter(issue => issue.scope?.entry === program.entries[0]), full.diagnostics);
      assert.ok(limited.diagnostics.some(issue => issue.scope?.entry === program.entries[2]));
      assert.ok(limited.diagnostics.every(issue => issue.scope?.entry !== program.entries[1]));
    }
  });
});

// Root supplies the separately committed owned fixture inputs at qualification.
const ownedDirectory = resolve(process.env.ZERO_LIST50_FIXTURES ?? "tests/corpus/drafts/zero-list50");
test("owned source-first triplets and controls preserve declared exact sites", { skip: !existsSync(ownedDirectory) }, () => {
  const variants = [
    ["positive.compact", 1, false], ["corrected.compact", 0, false], ["lookalike.compact", 0, false],
    ["counter/positive.compact", 1, false], ["counter/corrected.compact", 0, false], ["counter/lookalike.compact", 0, false],
    ["controls/helper.compact", 1, false], ["controls/independent-amount.compact", 0, false],
    ["controls/late-positive-guard.compact", 0, false], ["controls/disjoint-branches.compact", 0, false],
    ["controls/same-name-native-lookalike.compact", 0, false], ["controls/intentional-zero-linked-growth.compact", 1, false],
    ["controls/append-then-pop.compact", 0, true], ["controls/append-then-reset.compact", 0, true],
  ] as const;
  for (const [file, count, incomplete] of variants)
    fixture(readFileSync(resolve(ownedDirectory, file), "utf8"), (_file, program) => matrix(program, count, incomplete));
});
