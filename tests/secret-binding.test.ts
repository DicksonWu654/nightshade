import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { observeSecretBindings } from "../src/analysis/secret-binding-observation.js";
import { secretBindingDivergenceReview as rule } from "../src/detectors/secret-binding.js";
import { withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
export ledger identity:Map<Bytes<32>,Bytes<32>>;
export ledger encryption:Map<Bytes<32>,Bytes<32>>;
export ledger balance:Map<Bytes<32>,Uint<64>>;
witness firstSecret():Bytes<32>;
witness secondSecret():Bytes<32>;
circuit first(s:Bytes<32>):Bytes<32>{return persistentHash<Vector<2,Bytes<32>>>([pad(32,"account"),s]);}
circuit second(s:Bytes<32>):Bytes<32>{return persistentHash<Vector<2,Bytes<32>>>([pad(32,"encryption"),s]);}
`;
const base = 'assert(first(firstSecret())==identity.lookup(disclose(k)),"identity");';
const extra = 'assert(second(secondSecret())==encryption.lookup(disclose(k)),"encryption");';
const write = 'balance.insert(disclose(k),0 as Uint<64>);';
const weak = `export circuit weak(k:Bytes<32>,other:Bytes<32>):[]{${base}${write}}`;
const strong = `export circuit strong(k:Bytes<32>,other:Bytes<32>):[]{${base}${extra}${write}}`;
const positive = header + weak + strong;

function fixture(source: string, check: (file: string, program: Program) => void) {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    check(file, new Program(file, [], undefined, undefined, 2, "0.34.0"));
  });
}
function matrix(program: Program, expected: number) {
  let reference: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const result = observeSecretBindings(program, rule, {}, undefined, { engine, cached });
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.findings.length, expected, JSON.stringify(result.findings));
    assert.deepEqual(result.work.limits, { maxSteps: 40000, maxPaths: 256, maxValues: 50000 });
    assert.ok(result.findings.every(item => item.severity === "info" && item.metadata.majorityPremise === false
      && item.metadata.crossEntryValueEquality === "not-inferred" && item.metadata.applicationImpact === "not-inferred"));
    reference ??= result.findings; assert.deepEqual(result.findings, reference);
  }
}

test("original secret-binding triplet admits only the sweep balance occurrence in every engine/cache mode", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/drafts/auth39/secret-binding-${variant}.compact`);
    const program = new Program(file, [], undefined, undefined, 2, "0.34.0");
    matrix(program, variant === "positive" ? 1 : 0);
    const selected = scanFile(file, { detectors: [rule.id], zkirVersion: 2 });
    assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
    assert.deepEqual(selected.findings.map(item => item.location.line), variant === "positive" ? [35] : []);
    const ordinary = scanFile(file, { zkirVersion: 2 });
    assert.ok(ordinary.findings.every(item => item.detectorId !== rule.id));
  }
});

test("independently authored case boundaries retain exact review sites and late atomic binding", () => {
  const cases: [string, number[]][] = [["boolean-and-both", [12]], ["boolean-or-alternative", []],
    ["different-exact-key", []], ["different-witness-same-domain", []], ["helper-alias-preserves-binding", [21]],
    ["intentional-weaker-same-key", [18]], ["late-second-binding", [12]], ["record-revision", []],
    ["same-witness-different-domain", []]];
  for (const [name, lines] of cases) {
    const file = resolve(`tests/corpus/drafts/secret-binding49/controls/${name}.compact`);
    const program = new Program(file, [], undefined, undefined, 2, "0.34.0");
    matrix(program, lines.length);
    const result = observeSecretBindings(program, rule, {});
    assert.deepEqual(result.findings.map(item => item.location.line), lines, name);
    // The latePeer's line16 mutation has its additional binding. Only the
    // separate identity-only weakWriter can match this completed sibling.
    if (name === "late-second-binding") assert.ok(result.findings.every(item => item.metadata.entry === "weakWriter"));
  }
});

test("one stronger sibling is a structural comparison without a majority or inferred policy", () => {
  fixture(positive, (_file, program) => matrix(program, 1));
  fixture(header + weak + strong + `export circuit publicWrite(k:Bytes<32>):[]{${write}}`, (_file, program) => matrix(program, 1));
  fixture(header + weak.replace("export circuit", "// Intentionally permits identity-only maintenance.\nexport circuit") + strong,
    (_file, program) => matrix(program, 1));
  fixture(header + weak.replace(write, extra + write) + strong, (_file, program) => matrix(program, 0));
});

test("an absent constructor or first exported entry does not own matching work", () => {
  fixture(header + 'constructor() {}export circuit firstEntry():[]{}' + weak + strong,
    (_file, program) => matrix(program, 1));
});

test("the exact mutation key must match both trusted records within its original history", () => {
  fixture(header + weak.replace(write, write.replace("disclose(k)", "disclose(other)")) + strong, (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace(extra, extra.replace("disclose(k)", "disclose(other)")), (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace(write, write.replace("disclose(k)", "disclose(other)")), (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace(write, write + 'balance.insert(disclose(other),1 as Uint<64>);'), (_file, program) => matrix(program, 1));
});

test("required direct, transitive, late and alias key equalities retain the actual additional binding", () => {
  for (const [name, lines] of [["direct", []], ["transitive", []], ["late", []], ["alias", []],
    ["unequal", [14]], ["optional", [14]]] as [string, number[]][]) {
    const file = resolve(`tests/corpus/drafts/secret-binding49/guarded-key-controls/${name}.compact`);
    const program = new Program(file, [], undefined, undefined, 2, "0.34.0");
    matrix(program, lines.length);
    assert.deepEqual(observeSecretBindings(program, rule, {}).findings.map(item => item.location.line), lines, name);
  }
});

test("unresolved compound/native key congruence is unavailable rather than a missing binding", () => {
  const aggregateHeader = header.replaceAll("Map<Bytes<32>,", "Map<Vector<2,Bytes<32>>,");
  const aggregateWeak = weak.replaceAll('k:Bytes<32>,other:Bytes<32>', 'k:Vector<2,Bytes<32>>,other:Vector<2,Bytes<32>>')
    .replace(base + write, base + 'assert(k==other,"same components");' + extra.replace('disclose(k)', 'disclose(other)') + write);
  const aggregateStrong = strong.replaceAll('k:Bytes<32>,other:Bytes<32>', 'k:Vector<2,Bytes<32>>,other:Vector<2,Bytes<32>>');
  const opaqueAggregate = (aggregateHeader + aggregateWeak.replace('assert(k==other,"same components");', '') + aggregateStrong)
    .replaceAll('Map<Vector<2,Bytes<32>>,', 'Map<Vector<257,Bytes<32>>,')
    .replaceAll('k:Vector<2,Bytes<32>>,other:Vector<2,Bytes<32>>', 'k:Vector<257,Bytes<32>>,other:Vector<257,Bytes<32>>');
  const derivedWeak = weak.replace(base + write,
    'const a=first(k);const b=first(other);assert(k==other,"same native inputs");'
    + base.replace('disclose(k)', 'disclose(a)') + extra.replace('disclose(k)', 'disclose(b)') + write.replace('disclose(k)', 'disclose(a)'));
  for (const source of [aggregateHeader + aggregateWeak + aggregateStrong, opaqueAggregate, header + derivedWeak + strong])
    fixture(source, (_file, program) => {
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        const result = observeSecretBindings(program, rule, {}, undefined, { engine, cached });
        assert.equal(result.findings.length, 0);
        assert.ok(result.diagnostics.some(issue => issue.code === "secret-binding-evidence" && issue.message.includes("collection-key congruence")), JSON.stringify(result.diagnostics));
        assert.ok(result.coverage.every(row => row.status === "incomplete"));
      }
    });
  fixture(aggregateHeader + aggregateWeak.replace('disclose(other)', 'disclose(k)') + aggregateStrong,
    (_file, program) => matrix(program, 0));
  fixture(header + derivedWeak.replace('assert(k==other,"same native inputs");', 'assert(a==b,"same exact native outputs");') + strong,
    (_file, program) => matrix(program, 0));
});

test("canonical witness, constant domain and trusted record must each be distinct", () => {
  fixture(header + weak + strong.replace("secondSecret()", "firstSecret()"), (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace("second(secondSecret())", "first(secondSecret())"), (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace("encryption.lookup", "identity.lookup"), (_file, program) => matrix(program, 0));
  fixture(header + weak.replace("first(firstSecret())", "second(firstSecret())") + strong, (_file, program) => matrix(program, 0));
  fixture(header + weak.replace("first(firstSecret())", "first(secondSecret())") + strong, (_file, program) => matrix(program, 0));
});

test("trusted record revisions are checked at the mutation and the binding assertion", () => {
  const rewrite = 'encryption.insert(disclose(other),pad(32,"replacement"));';
  fixture(header + weak + strong.replace(extra, rewrite + extra), (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace(write, rewrite + write), (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace(write, write + rewrite), (_file, program) => matrix(program, 1));
  const rewriteBase = 'identity.insert(disclose(other),pad(32,"replacement"));';
  fixture(header + weak.replace(write, rewriteBase + write) + strong, (_file, program) => matrix(program, 0));
});

test("late unchanged bindings constrain atomic success and cannot become missing-binding findings", () => {
  fixture(header + weak.replace(write, write + extra) + strong, (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace(extra + write, write + extra), (_file, program) => matrix(program, 1));
  fixture(header + weak + strong.replace(extra + write, write + 'encryption.insert(disclose(k),pad(32,"x"));' + extra),
    (_file, program) => matrix(program, 0));
});

test("aliases and repeated helper calls preserve canonical declaration families and ordered writes", () => {
  const helper = `circuit auth(k:Bytes<32>):[]{${base}${extra}}`;
  fixture(header + helper + weak + strong.replace(base + extra, 'const alias=k;auth(alias);auth(alias);'), (_file, program) => matrix(program, 1));
  fixture(header + helper + weak + strong.replace(base + extra, 'auth(other);'), (_file, program) => matrix(program, 0));
});

test("two invocations of one mutating helper retain distinct effect sites and finding identities", () => {
  fixture(header + `circuit mutate(k:Bytes<32>):[]{${write}}`
    + weak.replace(write, 'mutate(k);mutate(k);') + strong, (_file, program) => {
      matrix(program, 2);
      const result = observeSecretBindings(program, rule, {});
      assert.equal(new Set(result.findings.map(item => item.fingerprint)).size, 2);
      assert.notDeepEqual(result.findings[0].metadata.effectCallSites, result.findings[1].metadata.effectCallSites);
      assert.deepEqual(result.findings.map(item => item.metadata.effectOrdinal), [0, 1]);
      assert.ok(result.findings.every(item => item.trace.some(step => step.kind === "call")));
    });
});

test("Boolean alternatives and exclusive histories never donate an additional binding", () => {
  const a = 'first(firstSecret())==identity.lookup(disclose(k))';
  const b = 'second(secondSecret())==encryption.lookup(disclose(k))';
  fixture(header + weak + strong.replace(base + extra, `assert(${a}&&${b},"both");`), (_file, program) => matrix(program, 1));
  fixture(header + weak + strong.replace(base + extra, `assert(${a}||${b},"either");`), (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace('other:Bytes<32>', 'other:Bytes<32>,flag:Boolean').replace(extra, `if(disclose(flag)){${extra}}`),
    (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace('other:Bytes<32>', 'other:Bytes<32>,flag:Boolean').replace(base + extra, `if(disclose(flag)){${base}}else{${extra}}`),
    (_file, program) => matrix(program, 0));
});

test("published or publicly fixed raw preimages cannot supply the private binding comparison", () => {
  fixture(header + "export ledger publishedSecret:Bytes<32>;" + weak + strong.replace(extra, 'const secret=secondSecret();publishedSecret=disclose(secret);assert(second(secret)==encryption.lookup(disclose(k)),"binding");'),
    (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace(extra, 'const secret=secondSecret();assert(secret==pad(32,"known"),"known");assert(second(secret)==encryption.lookup(disclose(k)),"binding");'),
    (_file, program) => matrix(program, 0));
  fixture(header + weak + strong.replace('second(secondSecret())', 'persistentHash<Bytes<32>>(secondSecret())'), (_file, program) => matrix(program, 0));
});

test("selection, capture and matching refusals retain incomplete coverage and do not retry", () => {
  fixture(positive, (_file, program) => {
    for (const options of [{ maxValues: 1 }, { maxSteps: 1 }, { maxSteps: 60 }, { maxValues: 300 }]) {
      const result = observeSecretBindings(program, rule, options);
      assert.equal(result.findings.length, 0); assert.ok(result.diagnostics.length);
      assert.ok(result.coverage.filter(row => row.status !== "not-applicable").every(row => row.status === "incomplete" && row.evidence === "unavailable"));
    }
    let calls = 0;
    const refuse = { ...rule, run(facts: Parameters<typeof rule.run>[0]) {
      calls++;
      facts.secretBindingEvidence!.maxValues = facts.metrics.abstractValues;
      return rule.run(facts);
    } };
    const matched = observeSecretBindings(program, refuse, {});
    assert.equal(calls, 1); assert.equal(matched.findings.length, 0);
    assert.ok(matched.diagnostics.some(item => item.code === "secret-binding-budget"));
    assert.ok(matched.coverage.every(row => row.status === "incomplete"));
    const unavailable = observeSecretBindings(program, rule, {}, new Set());
    assert.equal(unavailable.findings.length, 0); assert.ok(unavailable.diagnostics.length);
    const unselected = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(unselected), []);
    assert.ok(unselected.diagnostics.some(item => item.code === "secret-binding-evidence"));
  });
});

test("selected entry API restores ordinary behavior on a reused Dataflow instance", () => {
  fixture(positive, (_file, program) => {
    const fresh = new Dataflow(program).analyze();
    const reused = new Dataflow(program);
    assert.throws(() => reused.analyzeSecretBindingEntry("unknown-entry"), /exported entry/);
    const selected = reused.analyzeSecretBindingEntry(program.entries[0]);
    assert.ok(selected.secretBindingEvidence);
    const ordinary = reused.analyze();
    assert.equal(ordinary.secretBindingEvidence, undefined);
    assert.deepEqual(ordinary, fresh);
  });
});

test("path exhaustion preserves diagnostics rather than a quiet sibling subset", () => {
  fixture(header + weak + strong.replace('other:Bytes<32>', 'other:Bytes<32>,flag:Boolean').replace(write, `if(disclose(flag)){${write}}else{balance.insert(disclose(k),1 as Uint<64>);}`),
    (_file, program) => {
      const result = observeSecretBindings(program, rule, { maxPaths: 1 });
      assert.equal(result.findings.length, 0); assert.ok(result.diagnostics.length);
      assert.ok(result.coverage.every(row => row.status === "incomplete"));
    });
});

test("canonical checkpoints in direct/helper/callback closures refuse atomic-history evidence", () => {
  for (const source of [header + weak + strong.replace(extra + write, write + 'kernel.checkpoint();' + extra),
    header + 'circuit boundary():[]{kernel.checkpoint();}' + weak + strong.replace(extra + write, write + 'boundary();' + extra),
    header + 'circuit boundary(x:Bytes<32>):Bytes<32>{kernel.checkpoint();return x;}' + weak
      + strong.replace(extra + write, write + 'const result=map(boundary,[k,other]);' + extra)])
    fixture(source, (_file, program) => {
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        const result = observeSecretBindings(program, rule, {}, undefined, { engine, cached });
        assert.equal(result.findings.length, 0);
        assert.ok(result.diagnostics.some(item => item.message.includes("canonical kernel checkpoint")));
        assert.ok(result.coverage.every(row => row.status === "incomplete"));
      }
    });
  fixture(header + 'circuit checkpoint():[]{}' + weak + strong.replace(extra + write, 'checkpoint();' + extra + write),
    (_file, program) => matrix(program, 1));
});

test("large aggregate collection keys spend retained identity encodings in source execution", () => {
  fixture(header + 'export ledger largeKeys:Map<Vector<64,Bytes<32>>,Uint<64>>;'
    + 'export circuit large(k:Vector<64,Bytes<32>>):[]{const digest=first(firstSecret());largeKeys.insert(disclose(k),0 as Uint<64>);}',
    (_file, program) => {
      const entry = program.entries[0];
      const ordinary = new Dataflow(program, 40000, 256, 50000, "instructions", false, false,
        "equivalent-states", false, false, "all", false, true, false, false, false, false, true).analyzeSubset([entry]);
      assert.deepEqual(ordinary.diagnostics, []);
      const maxValues = ordinary.metrics.abstractValues + 100;
      const selected = new Dataflow(program, 40000, 256, maxValues, "instructions", false, false,
        "equivalent-states", false, false, "all", false, true, false, false, false, false, true).analyzeSecretBindingEntry(entry);
      assert.ok(selected.diagnostics.some(issue => issue.code === "secret-binding-retention-budget"), JSON.stringify(selected));
      assert.ok(!selected.completedEntries.includes(entry));
      assert.ok(selected.secretBindingEvidence?.entrySteps.has(entry));
    });
});

test("original fixture bytes remain the owned source-first input", () => {
  const source = readFileSync("tests/corpus/drafts/auth39/secret-binding-positive.compact", "utf8");
  assert.equal(source.split("\n")[34].trim(), 'balances.insert(disclose(account), 0 as Uint<64>);');
});

test("valid declaration-only input has no selected-rule diagnostics or empty entry scope", () => {
  fixture('import CompactStandardLibrary;witness secret():Bytes<32>;', (_file, program) => {
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(facts), []); assert.deepEqual(facts.diagnostics, []);
    const result = observeSecretBindings(program, rule, {});
    assert.deepEqual(result.coverage, []); assert.deepEqual(result.diagnostics, []);
  });
});
