import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Program } from "../src/index.js";
import type { AbstractValue, Flow, RuntimeOperation, StateWrite, SuccessfulPredicate } from "../src/dataflow/index.js";
import { merkleEffectPairs } from "../src/dataflow/merkle-enforcement.js";
import { equalityDependencies } from "../src/dataflow/equality-dependencies.js";
import { withFiles } from "./helpers.js";

test("aggregate supplied digests charge every candidate in exact and conservative matching", () => {
  withFiles({ "main.compact": "export ledger accepted: Field; export circuit accept(value: Field): [] { accepted = disclose(value); }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const ledger = [...program.symbols.values()].find(symbol => symbol.name === "accepted")!;
    const location = program.rootSource.ast.span;
    const flows: Flow[] = Array.from({ length: 3 }, (_, index) => ({
      source: { id: `digest-${index}`, kind: "entry-parameter", name: `digest-${index}`, location, merkleDigest: true },
      form: "raw", trace: [],
    }));
    const items: AbstractValue[] = flows.map(flow => ({ type: "Field", identity: flow.source.id, flows: [flow], ledger: new Set() }));
    const after: AbstractValue = { type: "Vector<3,Field>", flows, items, ledger: new Set() };
    const write: StateWrite = { ledger: ledger.id, region: [], location, before: { flows: [], ledger: new Set() }, after,
      excludedBefore: [], guards: [], callPath: [] };
    const common = { writes: [write], operations: [], predicates: [] };
    const results = [];
    for (const observations of [common, { ...common, entry: program.entries[0] }]) {
      // The previous one-supplied-root reservation would finish in ten units.
      const short = merkleEffectPairs(program, observations, new Set(), flow => flow.source.id, 10);
      assert.equal(short.status, "matching");
      assert.equal(short.work, 13); // write + three inputs + 3 dependencies * 3 roots
      assert.equal("pairs" in short, false, "an exhausted result cannot expose partial finding evidence");
      const edge = merkleEffectPairs(program, observations, new Set(), flow => flow.source.id, 15);
      assert.equal(edge.status, "effect-matching");
      assert.equal("pairs" in edge, false);
      const enough = merkleEffectPairs(program, observations, new Set(), flow => flow.source.id, 16);
      assert.equal(enough.status, "complete");
      assert.equal(enough.work, 16);
      if (enough.status !== "complete") continue;
      assert.deepEqual(enough.pairs.map(pair => pair.root.digest.identity), flows.map(flow => flow.source.id));
      assert.ok(enough.pairs.every(pair => pair.root.origin === "supplied-digest"));
      results.push(enough.pairs.map(pair => [pair.root.digest.identity, pair.effect.name]));
    }
    assert.deepEqual(results[0], results[1], "exact history and conservative candidate matching agree");
    const ordinaryFlows = flows.map(({ source, ...flow }) => {
      const { merkleDigest: _digest, ...ordinary } = source;
      return { ...flow, source: ordinary };
    });
    const noSupplied = { ...common, writes: [{ ...write, after: { ...after, flows: ordinaryFlows } }] };
    const minimumShort = merkleEffectPairs(program, noSupplied, new Set(), flow => flow.source.id, 6);
    assert.equal(minimumShort.status, "matching");
    const minimumEnough = merkleEffectPairs(program, noSupplied, new Set(), flow => flow.source.id, 7);
    assert.equal(minimumEnough.status, "complete");
    assert.equal(minimumEnough.work, 7, "retain one conservative candidate reservation when none are supplied");
    if (minimumEnough.status === "complete") assert.deepEqual(minimumEnough.pairs, []);
  });
});

test("dense owned effects share equality decoding without changing complete pairs or allowances", t => {
  withFiles({ "main.compact": "export ledger accepted: Field; export circuit accept(value: Field): [] { accepted = disclose(value); }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const ledger = [...program.symbols.values()].find(symbol => symbol.name === "accepted")!;
    const location = program.rootSource.ast.span;
    const input = (id: string): AbstractValue => ({ type: "Field", identity: id, ledger: new Set(), flows: [{
      source: { id, kind: "entry-parameter", name: id, location }, form: "raw", trace: [],
    }] });
    const a = input("effect"), b = input("proof-input");
    const equal = (left: AbstractValue, right: AbstractValue): SuccessfulPredicate => ({
      value: { type: "Boolean", flows: [], ledger: new Set(), comparison: { operator: "==", left, right } },
      truth: true, location, callPath: [], callSites: [], writesBefore: 0, operationsBefore: 0,
    });
    const predicates = [equal(a, b), ...Array.from({ length: 80 }, (_, i) => equal(input(`unrelated-${i}-a`), input(`unrelated-${i}-b`)))];
    const write: StateWrite = { ledger: ledger.id, region: [], location, before: input("old"), after: a,
      excludedBefore: [], guards: [], callPath: [] };
    const root: RuntimeOperation = { kind: "merkle-root", name: "owned-root", location, args: [b],
      result: { type: "MerkleTreeDigest", fields: { field: input("digest") }, flows: [], ledger: new Set() },
      guards: [], control: [], callPath: [], writesBefore: 0 };
    const observations = { entry: program.entries[0], writes: Array.from({ length: 40 }, () => write), operations: [root], predicates };
    const allowance = 1500;
    const matched = merkleEffectPairs(program, observations, new Set(), flow => flow.source.id, allowance);
    assert.equal(matched.status, "complete");
    assert.ok(matched.work < allowance);
    const generous = merkleEffectPairs(program, observations, new Set(), flow => flow.source.id, 100000);
    assert.deepEqual(matched, generous, "a larger allowance adds neither pairs nor work");
    if (matched.status === "complete") assert.equal(matched.pairs.length, 40);
    let rebuiltWork = 0, exhausted = false;
    for (const [index, effect] of observations.writes.entries()) {
      const rebuilt = equalityDependencies(effect.after, predicates, flow => flow.source.id, allowance - rebuiltWork,
        { writes: index, operations: observations.operations.length });
      rebuiltWork += rebuilt.work;
      if (!rebuilt.complete) { exhausted = true; break; }
      assert.deepEqual([...rebuilt.dependencies].sort(), ["effect", "proof-input"]);
    }
    assert.equal(exhausted, true, "rebuilding the same immutable predicates exhausts this unchanged allowance");
    assert.ok(rebuiltWork > allowance);
    t.diagnostic(`shared matching work=${matched.work}; repeated wrapper work before exhaustion=${rebuiltWork}; allowance=${allowance}; pairs=40`);
  });
});
