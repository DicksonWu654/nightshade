import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { sourceEffectKey, sourceHistoryFacts, querySourceHistory, type SourceHistoryFacts } from "../src/dataflow/source-history.js";
import { querySourceEntry, sourceQueryCandidate } from "../src/dataflow/source-queries.js";
import { projectEnforcedEqualities } from "../src/dataflow/predicates.js";
import { withFiles } from "./helpers.js";

function withProgram(source: string, run: (program: Program) => void): void {
  withFiles({ "main.compact": `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    run(new Program(file));
  });
}

test("default scanning completes conditional Map updates with certified detector coverage", () => {
  withProgram(`export ledger members: Map<Uint<8>, Field>;
  witness authorized(): Boolean;
  witness flags(): Vector<12, Boolean>;
  export circuit grant(): [] {
    assert(authorized(), "authorization");
    const selected = flags();
    for (const i of 0..12) { if (disclose(selected[i])) { members.insert(i as Uint<8>, 1 as Field); } }
  }`, program => {
    const exact = new Dataflow(program).analyze();
    assert.ok(exact.diagnostics.some(issue => issue.code.endsWith("budget")));
    const scan = scanFile(program.root);
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.coverage.completedEntries, program.entries);
    const authorization = scan.findings.filter(finding => finding.detectorId === "spoofable-authorization");
    assert.equal(authorization.length, 1);
    assert.equal(authorization[0].metadata.historyCoverage, "shared-source-query-with-ordinary-witnesses");
    assert.equal(authorization[0].metadata.soleGate, "proven-in-model");
    assert.equal(scan.findings.some(finding => finding.detectorId === "impossible-assertion"), false);
  });
});

test("source scanner findings match exhaustive small histories and retain root-wide value limits", () => {
  withProgram(`export ledger members: Map<Uint<8>, Field>;
  witness authorized(): Boolean;
  witness flags(): Vector<4, Boolean>;
  circuit put(): [] {
    assert(authorized(), "authorization");
    const selected = flags();
    for (const i of 0..4) { if (disclose(selected[i])) { members.insert(i as Uint<8>, 1 as Field); } }
  }
  export circuit grant(): [] { put(); }
  export circuit grantAgain(): [] { put(); }`, program => {
    const projected = scanFile(program.root, { maxPaths: 8 }), exact = scanFile(program.root);
    assert.equal(projected.status, "complete", JSON.stringify(projected.diagnostics));
    assert.equal(exact.status, "complete", JSON.stringify(exact.diagnostics));
    const signatures = (result: typeof exact) => result.findings.map(finding => ({
      detector: finding.detectorId, location: finding.location, severity: finding.severity, confidence: finding.confidence,
      fingerprint: finding.fingerprint, effects: finding.metadata.affectedEffects, soleGate: finding.metadata.soleGate,
    }));
    assert.deepEqual(signatures(projected), signatures(exact));
    const first = querySourceEntry(new Dataflow(program, 40000, 8), program.entries[0]);
    assert.equal(first.status, "covered");
    const limited = new Dataflow(program, 40000, 8, first.values + 10).analyzeWithCorrelatedQueries([], true, true);
    assert.ok(limited.exact.diagnostics.some(issue => issue.code.endsWith("budget")));
    assert.equal(limited.sources.length + limited.exact.completedEntries.length, 1, "each entry cannot reuse the root's full value allowance");
  });
});

test("source queries certify conditional writes with real evidence and reject missing obligations", () => {
  withProgram(`export ledger cells: Map<Uint<8>, Field>;
  witness authorized(): Boolean;
  export circuit entry(flags: Vector<4, Boolean>): [] {
    assert(authorized(), "authorization");
    for (const i of 0..4) { if (disclose(flags[i])) { cells.insert(i as Uint<8>, 1 as Field); } }
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine);
      const query = querySourceEntry(flow, program.entries[0]);
      assert.equal(query.status, "covered", JSON.stringify(query));
      if (query.status !== "covered") return;
      assert.equal(query.evidence.paths.length, 2);
      assert.deepEqual(query.evidence.paths.map(path => path.writes.length), [0, 4]);
      assert.equal(query.evidence.requiredGuards.size, 1);
      assert.equal([...query.evidence.requiredGuards.values()][0].size, 1);
      assert.ok(query.steps < 40000 && query.values < 50000);
      assert.equal(querySourceEntry(new Dataflow(program, 2), program.entries[0]).status, "incomplete");
    }
  });
  withProgram(`export ledger output: Field;
  export circuit entry(a: Boolean, b: Boolean): [] {
    if (disclose(a) && !disclose(b)) { output = 1 as Field; }
  }`, program => {
    const result = querySourceEntry(new Dataflow(program), program.entries[0]);
    assert.equal(result.status, "covered", "retained Boolean structure now aligns the ordinarily observed effect");
    if (result.status === "covered") assert.ok(result.evidence.paths.some(path => path.writes.length === 1));
  });
});

test("refused source queries spend the same allowance as correlated fallback", () => {
  withProgram(`export ledger member: Field;
  export circuit entry(a: Boolean, b: Boolean): [] {
    for (const i of 0..4) { if (disclose(a)) { if (disclose(b)) {} else { member = i as Field; } } }
  }`, program => {
    const query = querySourceEntry(new Dataflow(program, 40000, 2), program.entries[0]);
    assert.equal(query.status, "incomplete");
    const allowance = query.steps + 30;
    const result = new Dataflow(program, allowance, 2).analyzeWithCorrelatedQueries([], true, true);
    assert.ok(result.exact.diagnostics.some(issue => issue.code.endsWith("budget")));
    assert.ok(result.exact.metrics.steps <= allowance + 1, `${result.exact.metrics.steps} > ${allowance} + failed charge`);
    assert.equal(result.sources.length + result.correlated.length + result.exact.completedEntries.length, 0);
  });
});

test("expanded update histories do not consume the root allowance before ordinary entries", () => {
  withProgram(`export ledger member: Field;
  witness flags(): Vector<12, Boolean>;
  export circuit expanding(): [] {
    const bits = flags();
    for (const i of 0..12) { if (disclose(bits[i])) { member = i as Field; } }
  }
  export circuit ordinary(): Field { return 1 as Field; }`, program => {
    const result = scanFile(program.root, { maxValues: 200 });
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(issue => issue.code.endsWith("budget")));
    assert.deepEqual(result.coverage.completedEntries.map(entry => program.symbols.get(entry)!.name), ["ordinary"]);
  });
});

test("source admission stops at its first failed charge across source siblings", () => {
  withProgram(`export ledger member: Field;
  export circuit entry(): [] { ${Array.from({ length: 20 }, (_, index) => `member = ${index} as Field;`).join("\n")} }`, program => {
    for (const maxSteps of [1, 4, 10]) {
      let steps = 0;
      assert.equal(sourceQueryCandidate(program, program.entries[0], 9, () => ++steps <= maxSteps), false);
      assert.equal(steps, maxSteps + 1);
      const result = scanFile(program.root, { maxSteps });
      assert.equal(result.status, "incomplete");
      assert.equal(result.metrics.steps, maxSteps + 1);
    }
  });
});

test("source query absence checks cannot hide a preimage behind a joined ledger origin", () => {
  withProgram(`export ledger digest: Bytes<32>;
  export circuit entry(flag: Boolean, secret: Field, other: Bytes<32>): Field {
    if (disclose(flag)) { digest = disclose(other); }
    assert(persistentHash<Field>(secret) == digest, "digest");
    return secret;
  }`, program => {
    const result = querySourceEntry(new Dataflow(program), program.entries[0]);
    assert.equal(result.status, "incomplete");
    if (result.status === "incomplete") assert.match(result.reason, /preimage|Preimage|projection/);
  });
});

test("source queries refuse guard counterexamples based on nonaligned joined identities", () => {
  withProgram(`export ledger owner: Field;
  export ledger member: Field;
  witness claimedOwner(): Field;
  export circuit grant(flag: Boolean): [] {
    const claimed = claimedOwner();
    if (disclose(flag)) { owner = owner; }
    if (disclose(flag)) { assert(claimed == owner, "first check"); }
    else { assert(claimed == owner, "second check"); }
    member = 1 as Field;
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const result = querySourceEntry(new Dataflow(program, 40000, 256, 50000, engine), program.entries[0]);
      assert.equal(result.status, "incomplete");
      if (result.status === "incomplete") assert.match(result.reason, /aligned conservative origin|ordinary evidence/);
    }
  });
});

test("shared source histories preserve prefix order and intersect required predicates across alternatives", () => {
  withProgram(`export ledger output: Field;
  witness authorized(): Boolean;
  witness optional(): Boolean;
  circuit check(): [] { assert(authorized(), "common authorization"); }
  export circuit entry(flag: Boolean): [] {
    output = 9 as Field; check();
    if (disclose(flag)) { assert(optional(), "arm only"); output = 1 as Field; }
    else { output = 2 as Field; }
    output = 3 as Field;
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine, false, false, "equivalent-states", false, true, "all");
      const view = flow.conservativeSourceView(program.entries[0]);
      assert.equal(view.status, "available", JSON.stringify(view.diagnostics));
      const history = view.history!;
      let work = view.work.steps, values = view.work.values;
      const query = sourceHistoryFacts(history, (w, v) => { work += w; values += v; return work <= 40000 && values <= 50000; });
      assert.equal(query.status, "available");
      if (query.status !== "available") return;
      const sources = query.facts.requiredPredicates.flatMap(predicate => predicate.value.flows.map(flow => flow.source.name));
      assert.ok(sources.includes("authorized")); assert.equal(sources.includes("optional"), false); assert.equal(sources.includes("flag"), false);
      assert.equal(query.facts.possible.writes.length, 4, "the shared prefix and suffix are each retained once");
      for (const write of query.facts.possible.writes) {
        const effect: SourceHistoryFacts["effects"][number] = query.facts.effects.find(item => item.key === sourceEffectKey("ledger-write", write))!;
        const names = effect.requiredPredicates.flatMap(predicate => predicate.value.flows.map(flow => flow.source.name));
        assert.ok(names.includes("authorized"), "later enforced checks also constrain earlier successful effects");
        assert.equal(names.includes("optional"), write.after.constant === "1", "arm-only authorization is required only for that arm's effect");
      }
      const routes = (id: number): string[][] => {
        const node = history.nodes.find(node => node.id === id)!;
        if (node.kind === "start") return [[]];
        if (node.kind === "alternatives") return [...routes(node.left), ...routes(node.right)];
        return routes(node.prefix).map(prefix => [...prefix, ...node.observations.writes.map(write => write.after.constant!)]);
      };
      assert.deepEqual(routes(history.root).sort(), flow.analyze().paths.map(path => path.writes.map(write => write.after.constant!)).sort());
      assert.deepEqual(routes(history.root).sort(), [["9", "1", "3"], ["9", "2", "3"]]);
      assert.equal(sourceHistoryFacts(history, () => false).status, "incomplete");
    }
  });
});

test("effect requirements quantify over later occurrences at the same repeated call site", () => {
  withProgram(`export ledger output: Field;
  witness authorized(): Boolean;
  circuit put(): [] { output = 1 as Field; }
  export circuit entry(flags: Vector<2,Boolean>, final: Boolean): [] {
    assert(authorized(), "prefix");
    for (const i of 0..2) { if (disclose(flags[i])) { put(); } }
    assert(final, "suffix");
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine, false, false, "equivalent-states", false, true, "all");
      const view = flow.conservativeSourceView(program.entries[0]);
      assert.equal(view.status, "available");
      const query = sourceHistoryFacts(view.history!, () => true);
      assert.equal(query.status, "available");
      if (query.status !== "available") return;
      assert.equal(query.facts.effects.length, 1, "the loop calls the same source effect site");
      const effect = query.facts.effects[0];
      const names = effect.requiredPredicates.flatMap(predicate => predicate.value.flows.map(flow => flow.source.name));
      assert.deepEqual(new Set(names), new Set(["authorized", "final"]));
      assert.ok(effect.possiblePredicates.some(predicate => predicate.value.flows.some(flow => flow.source.name === "flags")));
      const ordinary = flow.analyze(); assert.deepEqual(ordinary.diagnostics, []);
      assert.deepEqual(ordinary.paths.map(path => path.writes.length).sort(), [0, 1, 1, 2]);
    }
  });
});

test("early return prevents a later guard becoming required and joined payloads remain may-observations", () => {
  withProgram(`export ledger output: Field; export ledger copied: Field;
  witness authorized(): Boolean;
  export circuit entry(flag: Boolean, early: Boolean): [] {
    if (disclose(early)) { return; }
    assert(authorized(), "not universal");
    if (disclose(flag)) { output = 1 as Field; } else { output = 2 as Field; }
    copied = output;
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const view = new Dataflow(program, 40000, 256, 50000, engine).conservativeSourceView(program.entries[0]);
      assert.equal(view.status, "available");
      const query = sourceHistoryFacts(view.history!, () => true);
      assert.equal(query.status, "available");
      if (query.status !== "available") return;
      assert.equal(query.facts.requiredPredicates.some(predicate => predicate.value.flows.some(flow => flow.source.name === "authorized")), false);
      const copied = query.facts.possible.writes.find(write => program.symbols.get(write.ledger)!.name === "copied")!;
      assert.equal(copied.after.constant, undefined, "a joined payload is not a selected value from either history");
      assert.equal(view.history!.kind, "conservative-source-alternatives");
      assert.equal("paths" in view, false);
    }
  });
});

test("common source interpretation preserves semantic guard conjunctions without publishing successful histories", () => {
  withProgram(`export circuit entry(flag: Boolean, a: Field, b: Field, c: Field): [] {
    if (disclose(flag)) { assert(a == b, "direct"); }
    else { assert(a == c, "first"); assert(c == b, "second"); }
    assert(a != b, "contradiction");
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine);
      const before = flow.analyze(), common = flow.conservativeSourceView(program.entries[0]);
      assert.deepEqual(common.diagnostics, []); assert.equal(common.status, "available");
      assert.equal(common.mayReturn, false);
      assert.equal(common.mayReachAssertions.at(-1)!.maySucceed, false);
      assert.equal("paths" in common, false); assert.equal("completedEntries" in common, false);
      assert.deepEqual(flow.analyze(), before, "may observations stay isolated from the ordinary engine");
    }
  });
});

test("a common may-return never establishes success of a disjunctive history", () => {
  withProgram(`export ledger output: Field;
  export circuit entry(flag: Boolean): [] {
    if (disclose(flag)) { output = 1 as Field; } else { output = 2 as Field; }
    assert(output != 1 as Field, "not first"); assert(output != 2 as Field, "not second");
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine);
      const common = flow.conservativeSourceView(program.entries[0]), exact = flow.analyze();
      assert.deepEqual(common.diagnostics, []); assert.equal(common.mayReturn, true);
      assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 0);
      for (const prefer of [false, true]) assert.equal(flow.selectSourceWitness(program.entries[0], prefer).status, "rejected");
    }
  });
});

test("24 conditional Map writes have a bounded current view while exact histories stay separate", () => {
  withProgram(`export ledger cursor: Uint<64>;
  export ledger cells: Map<Uint<64>, Field>;
  export circuit entry(end: Uint<64>): [] {
    const start = cursor;
    assert(disclose(end) > start, "nonempty"); assert(disclose(end) <= 24 as Uint<64>, "bound");
    for (const i of 0..24) {
      const at = i as Uint<64>;
      if (at >= start && at < disclose(end)) { cells.insert(at, 1 as Field); }
    }
    cursor = disclose(end);
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine), entry = program.entries[0];
      const common = flow.conservativeSourceView(entry);
      assert.equal(common.status, "available", JSON.stringify(common.diagnostics));
      assert.equal(common.mayReturn, true); assert.ok(common.work.joins >= 24);
      assert.ok(common.work.steps < 40000 && common.work.values < 50000);
      assert.equal(common.current!.ledger.size, 25);
      assert.ok([...common.current!.ledger.values()].every(value => value.constant === undefined), "no cell is unconditionally written across all intervals");
      const ordinary = flow.analyze();
      assert.ok(ordinary.diagnostics.some(issue => issue.code.endsWith("budget")), "a may-view does not waive ordinary history capacity");
      const cfg = engine === "instructions" ? program.instructionCFG(entry) : program.functions.get(entry)!.cfg;
      const replay = flow.selectConditionalSource(entry, new Map(cfg.nodes.filter(node => node.kind === "branch").map(node => [node.id, true])));
      if (engine === "instructions") {
        assert.equal(replay.status, "selected", JSON.stringify(replay));
        if (replay.status === "selected") assert.equal(replay.path.writes.length, 25);
      } else {
        assert.equal(replay.status, "incomplete", "source replay has not lifted expression-local alternatives");
        if (replay.status === "incomplete") assert.ok(replay.diagnostics.some(issue => issue.code === "conditional-source-incomplete"));
      }
      for (const prefer of [false, true]) {
        const selected = flow.selectSourceWitness(entry, prefer);
        assert.equal(selected.status, "selected", JSON.stringify(selected));
        if (selected.status === "selected") {
          assert.ok(selected.path.writes.length > 1);
          assert.equal("completedEntries" in selected, false);
          assert.ok(selected.metrics.steps < 40000);
        }
      }
    }
  });
});

test("ordinary selected histories follow known conditions, nested calls, folds and expression branches", () => {
  withProgram(`export ledger cells: Map<Field,Field>;
  witness sample(): Field;
  circuit authorize(): [] { assert(true, "guard"); }
  circuit put(flag: Boolean, key: Field): Field {
    if (disclose(flag) && true) { authorize(); }
    const selected = flag ? 7 as Field : 8 as Field;
    cells.insert(disclose(key), disclose(sample()));
    return selected;
  }
  pure circuit sum(sum: Field, flag: Boolean): Field { return sum + (flag ? 1 as Field : 2 as Field); }
  export circuit entry(known: Boolean, flag: Boolean): Field {
    assert(known, "forced");
    const first = put(known, 0 as Field);
    const second = put(flag, 1 as Field);
    return first + second + fold(sum, 0 as Field, [known,flag]);
  }`, program => {
    const entry = program.entries[0], guard = [...program.functions.values()].find(fn => fn.symbol.name === "authorize")!.symbol.id;
    const put = [...program.functions.values()].find(fn => fn.symbol.name === "put")!.symbol.id;
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine, true, true, "equivalent-states", true, true, "all");
      const before = flow.analyze();
      for (const prefer of [false, true]) {
        const selected = flow.selectSourceWitness(entry, prefer);
        assert.equal(selected.status, "selected", JSON.stringify(selected));
        if (selected.status !== "selected") continue;
        const path = selected.path;
        assert.equal(path.writes.length, 2);
        assert.ok(path.writes[0].guards.includes(guard), "the asserted true input overrides false preference");
        assert.equal(path.sinks.at(-1)!.value.constant, prefer ? "16" : "18");
        assert.ok(path.writes.every(write => write.callPath.includes(put)));
        assert.equal(path.witnessCalls!.size, 2); assert.deepEqual([...path.witnessCalls!.values()], [1, 1]);
        assert.ok(path.writes.every(write => write.after.flows.some(flow => flow.source.kind === "witness")));
        assert.ok(selected.calls.some(call => call.callee === put && call.maySucceed));
        assert.ok(selected.assertions.every(reach => reach.maySucceed));
        assert.equal("completedEntries" in selected, false);
      }
      assert.deepEqual(flow.analyze(), before, "selected observations do not contaminate exhaustive results");
    }
  });
});

test("ordinary selected histories keep rejection and exhausted allowances distinct", () => {
  withProgram(`export ledger output: Field;
  circuit nested(flag: Boolean): Field { if (flag) { assert(false, "disabled"); } return 1 as Field; }
  export circuit entry(flag: Boolean): [] { output = disclose(nested(flag)); }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine);
      assert.equal(flow.selectSourceWitness(program.entries[0], true).status, "rejected");
      const selected = flow.selectSourceWitness(program.entries[0], false);
      assert.equal(selected.status, "selected");
      if (selected.status === "selected") assert.equal(selected.path.writes.length, 1);
      for (const [steps, paths, values] of [[2, 256, 50000], [40000, 0, 50000], [40000, 256, 0]]) {
        const exhausted = new Dataflow(program, steps, paths, values, engine).selectSourceWitness(program.entries[0], false);
        assert.equal(exhausted.status, "incomplete");
        if (exhausted.status === "incomplete") assert.ok(exhausted.diagnostics.length);
      }
    }
  });
});

test("current Map membership and payload joins preserve absence rejection and discard stale revisions", () => {
  withProgram(`export ledger cells: Map<Field, Field>;
  export circuit entry(flag: Boolean): [] {
    const old = cells.member(0 as Field);
    if (disclose(flag)) { cells.insert(0 as Field, 7 as Field); }
    else { cells.remove(0 as Field); }
    assert(!cells.member(0 as Field), "absent now");
    assert(old, "old snapshot may have been present");
    const payload = cells.lookup(0 as Field);
    assert(payload == 7 as Field, "unreachable");
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine);
      const common = flow.conservativeSourceView(program.entries[0]);
      assert.deepEqual(common.diagnostics, []); assert.equal(common.mayReturn, false);
      assert.equal(common.mayReachAssertions.length, 2, "missing lookup rejects before the final assertion");
      const exact = flow.analyze(); assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 0);
    }
  });
});

test("IR predecessors, early returns and nested caller guards survive common current-state joins", () => {
  withProgram(`export ledger output: Field;
  circuit authorize(): [] { assert(true, "guard"); }
  circuit choose(flag: Boolean, a: Field, b: Field): Field {
    if (disclose(flag)) { authorize(); return a; } else { return b; }
  }
  export circuit entry(flag: Boolean, a: Field, b: Field): Field {
    const selected = disclose(flag) ? a : b;
    output = disclose(choose(flag, selected, b));
    return output;
  }`, program => {
    const authorize = [...program.functions.values()].find(fn => fn.symbol.name === "authorize")!.symbol.id;
    const choose = [...program.functions.values()].find(fn => fn.symbol.name === "choose")!.symbol.id;
    for (const engine of ["instructions", "expressions"] as const) {
      const common = new Dataflow(program, 40000, 256, 50000, engine).conservativeSourceView(program.entries[0]);
      assert.deepEqual(common.diagnostics, []); assert.equal(common.mayReturn, true);
      assert.equal(common.current!.guards.includes(authorize), false);
      assert.equal(common.current!.guards.includes(choose), true);
      assert.deepEqual(new Set(common.current!.value.flows.map(flow => flow.source.name)), new Set(["flag", "a", "b"]));
    }
  });
});

test("common current-state construction and transfer exhaustion are explicitly incomplete", () => {
  withProgram(`export ledger output: Field;
  export circuit entry(flag: Boolean, a: Field, b: Field): [] {
    if (disclose(flag)) { output = disclose(a); } else { output = disclose(b); }
  }`, program => {
    for (const [steps, paths, values] of [[2, 256, 50000], [40000, 0, 50000], [40000, 1, 50000], [40000, 256, 2]]) {
      const common = new Dataflow(program, steps, paths, values).conservativeSourceView(program.entries[0]);
      assert.equal(common.status, "incomplete"); assert.ok(common.diagnostics.length); assert.equal(common.current, undefined);
    }
  });
});

test("different List structures decline the common view without altering exact interpretation", () => {
  withProgram(`export ledger values: List<Field>;
  export circuit entry(flag: Boolean): [] {
    if (disclose(flag)) { values.pushFront(1 as Field); } else { values.pushFront(2 as Field); }
  }`, program => {
    const flow = new Dataflow(program), common = flow.conservativeSourceView(program.entries[0]);
    assert.equal(common.status, "incomplete");
    assert.ok(common.diagnostics.some(diagnostic => diagnostic.code === "common-state-domain"));
    assert.deepEqual(flow.analyze().diagnostics, []);
  });
});

test("Map alias origin loss cannot certify absence from two unbound selected histories", () => {
  withProgram(`export ledger table: Map<Uint<8>,Bytes<32>>;
  export ledger digest: Bytes<32>;
  export circuit entry(a: Boolean, b: Boolean, secret: Field): Field {
    table.insert(0 as Uint<8>, disclose(persistentHash<Field>(secret)));
    table.insert(1 as Uint<8>, persistentHash<Field>(42 as Field));
    const key = disclose(a) ? (disclose(b) ? 1 as Uint<8> : 0 as Uint<8>) : 1 as Uint<8>;
    assert(table.lookup(key) == digest, "binding");
    return secret;
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine);
      const exact = flow.analyze();
      assert.deepEqual(exact.diagnostics, []);
      assert.ok(exact.paths.some(path => path.bindings.length));
      for (const first of [false, true]) {
        const selected = flow.selectSourceWitness(program.entries[0], { first, alternateWitnessLeaves: true });
        assert.equal(selected.status, "selected");
        if (selected.status === "selected") assert.equal(selected.path.bindings.length, 0);
      }
      assert.equal(querySourceEntry(flow, program.entries[0]).status, "incomplete");
    }
  });
});

test("Boolean alternative guards preserve may/must evidence and exact histories in both engines", () => {
  withProgram(`export ledger output: Field;
  witness allowed(): Boolean;
  circuit choose(flag: Boolean): Boolean { return disclose(flag) ? allowed() : true; }
  export circuit entry(flag: Boolean): [] {
    const guard = choose(flag);
    assert(!guard, "inverse"); output = 1 as Field;
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine, cached, cached);
      const exact = flow.analyze();
      assert.deepEqual(exact.diagnostics, []);
      assert.equal(exact.paths.length, 1);
      const query = querySourceEntry(flow, program.entries[0]);
      assert.equal(query.status, "covered", JSON.stringify(query));
      if (query.status !== "covered") continue;
      assert.equal([...query.evidence.requiredGuards.values()][0].size, 1, "infeasible literal-true arm cannot erase the required false-witness guard");
      assert.ok(query.evidence.paths.every(path => path.writes.length === 1));
      assert.deepEqual(flow.analyze(), exact, "query isolation preserves ordinary cache and histories");
    }
  });
});

test("joined Boolean Map lookups cannot hide a middle-route preimage check", () => {
  withProgram(`ledger checks: Map<Field, Boolean>; ledger digest: Bytes<32>;
  witness secret(): Bytes<32>;
  export circuit entry(a: Boolean, b: Boolean): Bytes<32> {
    const s = secret();
    const bound = disclose(a) ? persistentHash<Bytes<32>>(s) == digest : true;
    checks.insert(0 as Field, disclose(bound)); checks.insert(1 as Field, true);
    const key = disclose(a) ? (disclose(b) ? 1 as Field : 0 as Field) : 1 as Field;
    assert(checks.lookup(key), "stored boolean"); return disclose(s);
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine, cached, cached);
      const exact = flow.analyze();
      assert.deepEqual(exact.diagnostics, []); assert.equal(exact.paths.length, 3);
      assert.ok(exact.paths.some(path => path.bindings.length > 0));
      const query = querySourceEntry(flow, program.entries[0]);
      assert.equal(query.status, "incomplete");
      if (query.status === "incomplete") assert.match(query.reason, /projection|preimage/i);
      assert.deepEqual(flow.analyze(), exact);
    }
  });
});

test("extra ordinary replay covers empty and populated branches with short-circuit assertions", () => {
  withProgram(`ledger checks: Map<Field, Uint<8>>; export ledger output: Field;
  witness allowed(): Boolean;
  export circuit entry(a: Uint<8>, b: Uint<8>): [] {
    assert(allowed(), "authorized");
    const n = checks.member(0 as Field) ? checks.lookup(0 as Field) : 0 as Uint<8>;
    if (n != 0 as Uint<8>) { assert(n == 1 as Uint<8> || n > 2 as Uint<8>, "populated"); }
    else { assert(a == 0 as Uint<8>, "empty"); }
    assert(a < 10 as Uint<8> && b < 10 as Uint<8>, "both");
    output = 1 as Field;
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const query = querySourceEntry(new Dataflow(program, 40000, 256, 50000, engine), program.entries[0]);
      assert.equal(query.status, "covered", JSON.stringify(query));
      if (query.status !== "covered") continue;
      const lines = new Set(query.evidence.assertionReaches.map(reach => reach.location.line));
      assert.ok(lines.size >= 4);
      assert.equal([...query.evidence.requiredGuards.values()][0].size, 1);
      const budget = querySourceEntry(new Dataflow(program, query.steps - 10), program.entries[0]);
      assert.equal(budget.status, "incomplete", "additional replay cannot borrow beyond the unchanged shared allowance");
    }
  });
});

test("Boolean projection distinguishes infeasible constants, optional alternatives and exhausted DAGs", () => {
  const leaf = (id: string): import("../src/dataflow/index.js").AbstractValue => ({ flows: [], ledger: new Set(), type: "Boolean", identity: id });
  const yes = { flows: [], ledger: new Set<string>(), type: "Boolean", constant: "true", constantKind: "boolean" as const };
  const a = leaf("a"), b = leaf("b");
  const project = (value: import("../src/dataflow/index.js").AbstractValue, truth: boolean, limit = 10000) => {
    let work = 0, values = 0;
    return projectEnforcedEqualities(value, truth, equality => {
      const key = `${equality.left.identity}:${equality.right.constant}`;
      return [{ key, value: key }];
    }, (w, v) => (work += w) <= limit && (values += v) <= limit);
  };
  const maybe = { ...leaf("joined"), predicateAlternatives: [a, yes] as const };
  const optional = project(maybe, true)!;
  assert.deepEqual([...optional.possible.keys()], ["a:true"]); assert.equal(optional.required.size, 0);
  const required = project(maybe, false)!;
  assert.deepEqual([...required.required.keys()], ["a:false"]);
  const exclusive = project({ ...leaf("exclusive"), predicateAlternatives: [a, b] }, true)!;
  assert.deepEqual([...exclusive.possible.keys()].sort(), ["a:true", "b:true"]); assert.equal(exclusive.required.size, 0);
  assert.equal(project({ ...maybe, predicateStructureLost: true }, true), undefined);
  let deep: import("../src/dataflow/index.js").AbstractValue = maybe;
  for (let i = 0; i < 70; i++) deep = { ...leaf(`join:${i}`), predicateAlternatives: [deep, deep] };
  assert.equal(project(deep, true), undefined, "a depth refusal returns no partial facts");
  assert.equal(project(maybe, true, 1), undefined, "decoding and retention spend the supplied allowance");
});

test("source-history possible projections never promote optional atoms to required effect guards", () => {
  withProgram(`export ledger output: Field; witness allowed(): Boolean;
  export circuit entry(): [] { output = 1 as Field; assert(allowed(), "later guard"); output = 2 as Field; }`, program => {
    const view = new Dataflow(program).conservativeSourceView(program.entries[0]);
    const query = querySourceHistory(view.history!, () => true, () => ({
      possible: [{ key: "required", value: "required" }, { key: "optional", value: "optional" }],
      required: [{ key: "required", value: "required" }],
    }));
    assert.equal(query.status, "available");
    if (query.status !== "available") return;
    assert.equal(query.facts.effects.length, 2);
    for (const effect of query.facts.effects) {
      assert.deepEqual(effect.requiredPredicates, ["required"]);
      assert.deepEqual(effect.possiblePredicates, ["required", "optional"]);
    }
  });
});

test("scalar conversion of nested Boolean alternatives refuses lost predicate evidence", () => {
  withProgram(`export ledger output: Field; witness allowed(): Boolean;
  export circuit entry(a: Boolean): [] {
    const guard = disclose(a) ? allowed() : true;
    assert((((guard == false) as Uint<8>) + 1 as Uint<8>) == 2 as Uint<8>, "numeric");
    output = 1 as Field;
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine, cached, cached), before = flow.analyze();
      assert.deepEqual(before.diagnostics, []);
      const query = querySourceEntry(flow, program.entries[0]);
      assert.equal(query.status, "incomplete");
      if (query.status === "incomplete") assert.match(query.reason, /projection/);
      assert.deepEqual(flow.analyze(), before);
    }
  });
});

test("separate stateful expression joins are admitted without requiring a repeated loop", () => {
  withProgram(`ledger values: Map<Field, Field>; export ledger output: Field;
  witness allowed(): Boolean;
  export circuit entry(): [] {
    assert(allowed(), "authorization");
    ${Array.from({ length: 10 }, (_, i) => `const n${i} = values.member(${i} as Field) ? values.lookup(${i} as Field) : 0 as Field;`).join("\n")}
    output = ${Array.from({ length: 10 }, (_, i) => `n${i}`).join(" + ")};
  }`, program => {
    assert.equal(sourceQueryCandidate(program, program.entries[0], 9, () => true), true);
    const exact = new Dataflow(program).analyze();
    assert.ok(exact.diagnostics.some(issue => issue.code.endsWith("budget")));
    const scan = scanFile(program.root);
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.coverage.completedEntries, program.entries);
    const findings = scan.findings.filter(finding => finding.detectorId === "spoofable-authorization");
    assert.equal(findings.length, 1);
    assert.equal(findings[0].metadata.historyCoverage, "shared-source-query-with-ordinary-witnesses");
  });
});

test("read-only helper expansion can use certified source coverage without changing budgets", () => {
  withProgram(`circuit score(bits: Vector<12, Boolean>): Field {
    ${Array.from({length: 12}, (_, i) => `const c${i} = bits[${i}] ? (1 as Field) : (0 as Field);`).join("\n")}
    return ${Array.from({length: 12}, (_, i) => `c${i}`).join(" + ")};
  }
  export circuit entry(bits: Vector<12, Boolean>): Field { return disclose(score(bits)); }`, program => {
    assert.equal(sourceQueryCandidate(program, program.entries[0], 9, () => true), false);
    assert.equal(sourceQueryCandidate(program, program.entries[0], 9, () => true, true), true);
    const result = scanFile(program.root);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.coverage.completedEntries, program.entries);
    const limited = scanFile(program.root, {maxSteps: 1});
    assert.equal(limited.status, "incomplete");
    assert.ok(limited.diagnostics.some(diagnostic => diagnostic.code.endsWith("budget")));
  });
});

test("complementary witness phases discharge optional gates using actual histories", () => {
  withProgram(`export ledger output: Field; ledger bound: Field;
  witness candidate(): Field; witness optionalFlag(): Boolean; witness permitted(): Boolean;
  export circuit entry(): [] {
    assert(persistentHash<Field>(candidate()) != default<Bytes<32>>, "nonzero digest");
    if (disclose(candidate() == bound)) {
      if (disclose(optionalFlag())) { assert(permitted(), "optional authorization"); }
      output = 1 as Field;
    }
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine, cached, cached);
      const query = querySourceEntry(flow, program.entries[0]);
      assert.equal(query.status, "covered", JSON.stringify(query));
      if (query.status !== "covered") continue;
      const writes = query.evidence.paths.filter(path => path.writes.length);
      assert.ok(writes.some(path => !path.predicates?.some(predicate => predicate.value.flows.some(flow => flow.source.name === "permitted"))));
      assert.ok(writes.some(path => path.predicates?.some(predicate => predicate.value.flows.some(flow => flow.source.name === "permitted"))));
      assert.ok([...query.evidence.requiredGuards.values()].every(guards => guards.size === 1), "optional authorization must not become a required guard");
      const exhausted = querySourceEntry(new Dataflow(program, query.steps - 1, 256, query.values, engine, cached, cached), program.entries[0]);
      assert.equal(exhausted.status, "incomplete", "retry uses the same work allowance");
    }
  });
});

test("completion dedup preserves user payload fields and distinct real effect histories", () => {
  withProgram(`struct Payload { trace: Field; guards: Field; }
  export ledger output: Field;
  circuit choose(flag: Boolean): Payload {
    return flag ? Payload {trace: 1 as Field, guards: 0 as Field}
                : Payload {trace: 2 as Field, guards: 0 as Field};
  }
  export circuit returned(flag: Boolean): Payload {
    const value = choose(flag); output = 7 as Field; return disclose(value);
  }
  export circuit effects(flag: Boolean): Field {
    if (disclose(flag)) { output = 3 as Field; }
    output = 7 as Field; return 1 as Field;
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      const returned = facts.paths.filter(path => program.symbols.get(path.entry)!.name === "returned");
      assert.deepEqual(returned.map(path => path.sinks.find(sink => sink.kind === "exported-return")!.value.fields!.trace.constant).sort(), ["1", "2"]);
      const effects = facts.paths.filter(path => program.symbols.get(path.entry)!.name === "effects");
      assert.deepEqual(effects.map(path => path.writes.map(write => write.after.constant)).sort(), [["3", "7"], ["7"]]);
    }
  });
});
