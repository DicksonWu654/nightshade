import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type CompilerVersion } from "../src/index.js";
import { observeComplementarySend } from "../src/analysis/complementary-send-observation.js";
import { zeroAmountComplementarySendReview as rule } from "../src/detectors/complementary-send.js";
import { successfulIntegerConstraints } from "../src/dataflow/arithmetic-safety.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const corpus = "tests/corpus/drafts/complementary47/";
const labels = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).complementarySendReview47 as {
  cases: { file: string; lines: number[]; status?: "incomplete" }[];
};
const header = "import CompactStandardLibrary;\n";
const parameters = "color:Bytes<32>,recipient:Either<ContractAddress,UserAddress>,total:Uint<128>,part:Uint<128>";
const checks = 'assert(disclose(total)>0 as Uint<128>,"total");assert(disclose(part)<=disclose(total),"part");';
const sends = 'const remainder=total-part;sendUnshielded(disclose(color),disclose(part),disclose(recipient));sendUnshielded(disclose(color),disclose(remainder),disclose(recipient));';
const positive = `${header}export circuit entry(${parameters}):[]{${checks}${sends}}`;

function fixture(source: string, check: (file: string, program: Program) => void,
  version: CompilerVersion = "0.34.0", zkir: 2 | 3 = 2) {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    const compiler = version === "0.31.1" ? process.env.COMPACTC_031_TEST : process.env.COMPACTC_TEST;
    if (compiler) { const result = validateWithCompiler(compiler, file, [], 30000, zkir, version); assert.equal(result.valid, true, result.error); }
    check(file, new Program(file, [], undefined, undefined, zkir, version));
  });
}

function matrix(program: Program, expected: number, incomplete = false) {
  let baseline: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const observed = observeComplementarySend(program, rule, {}, undefined, { engine, cached });
    assert.equal(observed.diagnostics.length > 0, incomplete, JSON.stringify(observed.diagnostics));
    assert.equal(observed.findings.length, expected, JSON.stringify(observed.findings));
    assert.ok(observed.findings.every(item => item.severity === "info" && item.metadata.partMinimum === "0"
      && item.metadata.remainderMinimum === "0" && BigInt(String(item.metadata.totalMinimum)) > 0n
      && item.metadata.endpointFeasibility === "not-proven" && item.metadata.applicationImpact === "not-inferred"));
    baseline ??= observed.findings; assert.deepEqual(observed.findings, baseline);
    assert.deepEqual(observed.work.limits, { maxSteps: 40000, maxPaths: 256, maxValues: 50000 });
  }
}

test("independent owned pair controls preserve exact relation and both endpoint envelopes", () => {
  for (const item of labels.cases.filter(row => !row.file.includes("/counter/"))) {
    fixture(readFileSync(resolve("tests/corpus", item.file), "utf8"), (file, program) => {
      const incomplete = item.status === "incomplete";
      matrix(program, item.lines.length, incomplete);
      const selected = scanFile(file, { detectors: [rule.id], zkirVersion: 2 });
      assert.equal(selected.status, incomplete ? "incomplete" : "complete", JSON.stringify(selected.diagnostics));
      assert.deepEqual(selected.findings.map(finding => finding.location.line), item.lines, item.file);
    });
  }
});

test("supported historical/native profiles and aliases retain exact unsigned subtraction", () => {
  for (const [version, zkir] of [["0.31.1", 2], ["0.34.0", 2], ["0.34.0", 3]] as const)
    fixture(positive, (_file, program) => matrix(program, 1), version, zkir);
  for (const variant of ["positive", "corrected", "quiet-independent-amounts"])
    fixture(readFileSync(resolve(corpus, `${variant}.compact`), "utf8"), (_file, program) => matrix(program, variant === "positive" ? 1 : 0), "0.31.1");
  fixture(`${header}export circuit entry(color:Bytes<32>,recipient:Either<ContractAddress,UserAddress>,total:Uint<248>,part:Uint<128>):[]{
    assert(disclose(total)>0 as Uint<248>,"total");const remainder=(total-(part as Uint<248>)) as Uint<128>;
    sendUnshielded(disclose(color),disclose(part),disclose(recipient));sendUnshielded(disclose(color),disclose(remainder),disclose(recipient));}`,
    (_file, program) => matrix(program, 1));
  fixture(`${header}circuit remainder(t:Uint<128>,p:Uint<128>):Uint<128>{return (t-p) as Uint<128>;}
    export circuit entry(${parameters}):[]{${checks}const a=part as Uint<128>;const r=remainder(total,a);
    sendUnshielded(disclose(color),disclose(r),disclose(recipient));sendUnshielded(disclose(color),disclose(a),disclose(recipient));}`,
    (_file, program) => matrix(program, 1));
});

test("late exact guards constrain earlier atomic sends without inverting subtraction", () => {
  for (const guard of ['assert(disclose(part)>0 as Uint<128>,"late");', 'assert(disclose(remainder)!=0 as Uint<128>,"late");'])
    fixture(`${header}export circuit entry(${parameters}):[]{${checks}${sends}${guard}}`, (_file, program) => matrix(program, 0));
  fixture(`${header}export circuit entry(${parameters}):[]{${checks}${sends}assert(false,"disabled");}`, (_file, program) => matrix(program, 0));
  fixture(`${header}export circuit entry(${parameters}):[]{${checks}const remainder=((total as Field)-(part as Field)) as Uint<128>;
    sendUnshielded(disclose(color),disclose(part),disclose(recipient));sendUnshielded(disclose(color),disclose(remainder),disclose(recipient));}`,
    (_file, program) => matrix(program, 0));
});

test("exact selector snapshots retain color equality within their ledger revision", () => {
  fixture(`${header}export ledger colors:Map<Bytes<32>,Bytes<32>>;
    export circuit entry(${parameters},key:Bytes<32>):[]{${checks}const c=colors.lookup(disclose(key));const remainder=total-part;
    sendUnshielded(disclose(c),disclose(part),disclose(recipient));sendUnshielded(disclose(c),disclose(remainder),disclose(recipient));}`,
    (_file, program) => matrix(program, 1));
  fixture(`${header}export ledger colors:Map<Bytes<32>,Bytes<32>>;
    export circuit entry(${parameters},key:Bytes<32>):[]{${checks}const remainder=total-part;
    sendUnshielded(disclose(colors.lookup(disclose(key))),disclose(part),disclose(recipient));
    sendUnshielded(disclose(colors.lookup(disclose(key))),disclose(remainder),disclose(recipient));}`,
    (_file, program) => matrix(program, 1));
  fixture(`${header}export ledger colors:Map<Bytes<32>,Bytes<32>>;
    export circuit entry(${parameters},key:Bytes<32>):[]{${checks}const selector=(key as Field) as Bytes<32>;const remainder=total-part;
    sendUnshielded(disclose(colors.lookup(disclose(selector))),disclose(part),disclose(recipient));
    sendUnshielded(disclose(colors.lookup(disclose(selector))),disclose(remainder),disclose(recipient));}`,
    (_file, program) => matrix(program, 0));

});

test("callbacks reuse ordinary transfers and retain zero-iteration semantics", () => {
  fixture(`${header}circuit pair(${parameters}):Field{${checks}${sends}return 0 as Field;}
    export circuit nonempty(${parameters}):Vector<1,Field>{return map(pair,[color],[recipient],[total],[part]);}
    export circuit empty():Vector<0,Field>{return map(pair,[] as Vector<0,Bytes<32>>,[] as Vector<0,Either<ContractAddress,UserAddress>>,[] as Vector<0,Uint<128>>,[] as Vector<0,Uint<128>>);}`,
    (_file, program) => {
      matrix(program, 1);
      const result = observeComplementarySend(program, rule, {});
      assert.deepEqual(result.findings.map(item => item.metadata.entry), ["nonempty"]);
      assert.ok(result.coverage.filter(row => program.symbols.get(row.entry)?.name === "empty").every(row => row.status === "complete"));
    });
});

test("source pair identity ignores unrelated send ordinals and distinguishes helper callsites", () => {
  fixture(`${header}export circuit entry(${parameters},flag:Boolean):[]{${checks}
    if(disclose(flag)){sendUnshielded(disclose(color),1,disclose(recipient));}${sends}}`, (_file, program) => matrix(program, 1));
  fixture(`${header}circuit pair(${parameters}):[]{${checks}${sends}}
    export circuit entry(${parameters},otherTotal:Uint<128>,otherPart:Uint<128>):[]{
    pair(color,recipient,total,part);pair(color,recipient,otherTotal,otherPart);}`, (_file, program) => {
      // Instruction histories consume more retained values here. Refusal is
      // explicit; complete reference histories still identify the same pairs.
      let complete: unknown;
      for (const cached of [false, true]) {
        const refused = observeComplementarySend(program, rule, {}, undefined, { engine: "instructions", cached });
        assert.equal(refused.findings.length, 0);
        assert.ok(refused.diagnostics.some(issue => issue.code === "complementary-send-retention-budget"));
        assert.ok(refused.coverage.every(row => row.status === "incomplete"));
        assert.ok(refused.work.metrics.abstractValues > refused.work.limits.maxValues);
        const observed = observeComplementarySend(program, rule, {}, undefined, { engine: "expressions", cached });
        assert.deepEqual(observed.diagnostics, []); assert.equal(observed.findings.length, 2);
        assert.ok(observed.coverage.every(row => row.status === "complete"));
        complete ??= observed.findings; assert.deepEqual(observed.findings, complete);
      }
    });
  fixture(`${header}circuit pair(${parameters}):[]{${checks}${sends}}
    export circuit entry(${parameters},otherTotal:Uint<128>,otherPart:Uint<128>):[]{
    pair(color,default<Either<ContractAddress,UserAddress>>,total,part);pair(color,default<Either<ContractAddress,UserAddress>>,otherTotal,otherPart);}`, (_file, program) => matrix(program, 2));
});

test("selected constraint reconstruction meters recursive closures before allocation", () => {
  fixture(`${header}export circuit entry(${parameters},alias:Uint<128>,mirror:Uint<128>):[]{
    assert(total==alias,"alias");assert(alias==mirror,"mirror");assert(disclose(mirror)>0 as Uint<128>,"positive");${sends}}`,
    (_file, program) => {
      const entry = program.entries.find(id => program.symbols.get(id)?.name === "entry")!;
      const ordinary = new Dataflow(program).analyzeSubset([entry]);
      const path = ordinary.paths[0];
      // Obtain all predicates through the selected observer, then reconstruct
      // a fresh state twice. The meter counts nested alias closure work rather
      // than just the external predicate visits.
      const selected = new Dataflow(program).analyzeComplementarySendEntry(entry);
      assert.deepEqual(selected.diagnostics, []);
      const predicates = selected.paths[0].predicates!;
      let visits = 0, work = 0, retained = 0;
      const result = successfulIntegerConstraints(predicates, () => {}, undefined, (steps, values) => {
        visits++; work += steps; retained += values;
      });
      assert.equal(result.status, "complete"); assert.ok(visits > predicates.length * 10);
      assert.ok(work > predicates.length * 10); assert.ok(retained > predicates.length * 16);
      let bounded = 0;
      assert.throws(() => successfulIntegerConstraints(predicates, () => {}, undefined, (_steps, values) => {
        bounded += values; if (bounded > retained / 2) throw new Error("bounded reconstruction");
      }), /bounded reconstruction/);
      assert.ok(path);
    });
});

test("summaries keep current storage identities and never reuse fresh computed amount snapshots", () => {
  fixture(`${header}circuit amount(p:Field):Field{return p+0;}
    export circuit entry(color:Bytes<32>,recipient:Either<ContractAddress,UserAddress>,total:Uint<128>,part:Field):[]{assert(disclose(total)>0 as Uint<128>,"total");const p=amount(part) as Uint<128>;const other=amount(part) as Uint<128>;const remainder=total-other;
    sendUnshielded(disclose(color),disclose(p),disclose(recipient));sendUnshielded(disclose(color),disclose(remainder),disclose(recipient));}`,
    (_file, program) => {
      matrix(program, 0);
      assert.ok(new Dataflow(program).analyze().metrics.summaryHits > 0);
    });
  fixture(`${header}export ledger storedColor:Bytes<32>;
    circuit readColor():Bytes<32>{return storedColor;}
    circuit setColor(c:Bytes<32>):[]{storedColor=disclose(c);}
    export circuit entry(${parameters}):[]{${checks}setColor(color);setColor(color);const a=readColor();const b=readColor();const remainder=total-part;
    sendUnshielded(disclose(a),disclose(part),disclose(recipient));sendUnshielded(disclose(b),disclose(remainder),disclose(recipient));}`,
    (_file, program) => {
      matrix(program, 1);
      const entry = program.entries.find(id => program.symbols.get(id)?.name === "entry")!;
      const cached = new Dataflow(program).analyzeComplementarySendEntry(entry);
      assert.ok(cached.metrics.readSummaryHits > 0); assert.ok(cached.metrics.statefulSummaryHits > 0);
    });
});

test("frozen Counter controls retain ordinary pair results and refuse unsupported query evidence", () => {
  for (const variant of ["positive", "corrected", "quiet"])
    fixture(readFileSync(resolve(corpus, "counter", `${variant}.compact`), "utf8"), (file, program) => {
      matrix(program, variant === "positive" ? 1 : 0);
      const queries = scanFile(file, { detectors: [rule.id], experimentalCounterQueries: true });
      assert.equal(queries.status, "incomplete"); assert.equal(queries.findings.length, 0); assert.ok(queries.diagnostics.length);
    });
});

test("original history markers, missing numeric operands, and shared budgets refuse clean evidence", () => {
  fixture(positive, (file, program) => {
    const full = () => new Dataflow(program).analyzeComplementarySendEntry(program.entries.find(id => program.symbols.get(id)?.name === "entry")!);
    const ordinary = new Dataflow(program).analyze(); assert.deepEqual(rule.run(ordinary), []); assert.ok(ordinary.diagnostics.length);
    for (const breakEvidence of [
      (facts: ReturnType<typeof full>) => { facts.paths[0].operations!.pop(); },
      (facts: ReturnType<typeof full>) => { facts.paths[0].predicates!.pop(); },
      (facts: ReturnType<typeof full>) => { delete facts.paths[0].complementaryHistory; },
      (facts: ReturnType<typeof full>) => { facts.completedEntries.length = 0; },
      (facts: ReturnType<typeof full>) => { facts.complementarySendEvidence!.histories++; },
      (facts: ReturnType<typeof full>) => { facts.complementarySendEvidence!.maxSteps = facts.metrics.steps; },
      (facts: ReturnType<typeof full>) => { facts.complementarySendEvidence!.maxValues = facts.metrics.abstractValues; },
      (facts: ReturnType<typeof full>) => { const amount = facts.paths[0].operations!.find(item => item.kind === "circuit-invocation" && item.args[1]?.numericExpression)?.args[1]; if (amount) { amount.identity = undefined; amount.mintSnapshot = undefined; } },
    ]) { const facts = full(); breakEvidence(facts); assert.deepEqual(rule.run(facts), []); assert.ok(facts.diagnostics.length); }
    for (const options of [{ maxSteps: 1 }, { maxValues: 1 }, { maxPaths: 1 }, { maxSteps: 250 }, { maxValues: 900 }]) {
      const selected = scanFile(file, { detectors: [rule.id], zkirVersion: 2, ...options });
      assert.equal(selected.status, "incomplete"); assert.equal(selected.findings.length, 0); assert.ok(selected.diagnostics.length);
    }
    const incomplete = observeComplementarySend(program, rule, {}, new Set()); assert.ok(incomplete.diagnostics.length);
    // A retained-container refusal must preserve consumed values/diagnostics,
    // and remove all unfinished histories without rerunning an empty analysis.
    const entry = program.entries.find(id => program.symbols.get(id)?.name === "entry")!;
    const completed = full();
    for (const maxValues of [completed.metrics.abstractValues - 1, completed.metrics.abstractValues - 8]) {
      const terminalRefusal = new Dataflow(program, 40000, 256, maxValues).analyzeComplementarySendEntry(entry);
      assert.ok(terminalRefusal.diagnostics.length); assert.ok(terminalRefusal.metrics.abstractValues > maxValues);
      assert.deepEqual(terminalRefusal.completedEntries, []); assert.deepEqual(terminalRefusal.paths, []);
      assert.equal(terminalRefusal.complementarySendEvidence, undefined);
    }
    const refused = new Dataflow(program, 40000, 256, 900).analyzeComplementarySendEntry(entry);
    assert.ok(refused.diagnostics.length); assert.ok(refused.metrics.abstractValues >= 900);
    assert.deepEqual(refused.completedEntries, []); assert.deepEqual(rule.run(refused), []);
  });
});

test("unsupported relevant profiles and checkpoints diagnose; single sends certify structural absence", () => {
  fixture(positive, (file, _program) => {
    const unsupported = new Program(file, [], undefined, undefined, 2, "0.33.0-rc.2");
    const result = observeComplementarySend(unsupported, rule, {}); assert.ok(result.diagnostics.length); assert.equal(result.findings.length, 0);
  });
  fixture(`${header}export circuit entry(color:Bytes<32>,recipient:Either<ContractAddress,UserAddress>,part:Uint<128>):[]{
    sendUnshielded(disclose(color),disclose(part),disclose(recipient));}`, (file, _program) => {
    const unsupported = new Program(file, [], undefined, undefined, 2, "0.33.0-rc.2");
    const result = observeComplementarySend(unsupported, rule, {}); assert.deepEqual(result.diagnostics, []);
    assert.ok(result.coverage.every(row => row.status === "not-applicable"));
  });
  fixture(`${header}export circuit entry(${parameters}):[]{${checks}${sends}kernel.checkpoint();}`,
    (_file, program) => matrix(program, 0, true));
});

test("ordinary defaults and the broad zero-send rule retain findings and all baseline costs", () => {
  fixture(positive, (file, _program) => {
    for (const detectors of [undefined, ["zero-amount-unshielded-send"]]) {
      const ordinary = scanFile(file, { detectors, zkirVersion: 2 });
      assert.equal(ordinary.status, "complete", JSON.stringify(ordinary.diagnostics));
      assert.ok(ordinary.findings.every(item => item.detectorId !== rule.id));
      const selected = scanFile(file, { detectors: [...(detectors ?? ordinary.coverage.detectors), rule.id], zkirVersion: 2 });
      assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
      assert.deepEqual(selected.findings.filter(item => item.detectorId !== rule.id), ordinary.findings);
      const work = selected.ruleObservationWork!.find(item => item.detectorId === rule.id)!;
      for (const key of Object.keys(work.metrics) as (keyof typeof work.metrics)[]) assert.equal(selected.metrics[key] - work.metrics[key], ordinary.metrics[key], key);
    }
  });
});
