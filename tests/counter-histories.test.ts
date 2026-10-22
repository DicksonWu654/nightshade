import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { extractTerminalCounterRegion } from "../src/analysis/counter-regions.js";
import { buildCounterHistoryGraph, expandCounterHistories, projectCounterHistory, type CounterHistoryGraph, type CounterHistoryProjection } from "../src/dataflow/counter-histories.js";
import { Dataflow } from "../src/dataflow/index.js";
import { Program } from "../src/semantic/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const source = (size: number, reset = true) => `pragma language_version 0.26.0; import CompactStandardLibrary; export ledger count: Counter;
export circuit entry(${Array.from({ length: size }, (_, index) => `flag${index}: Boolean`).join(",")}): [] {
${reset ? "count.resetToDefault();" : ""}
${Array.from({ length: size }, (_, index) => `if (disclose(flag${index})) count.increment(${index + 1});`).join("\n")}
}`;

function fixture(size: number, reset: boolean, compile: boolean, check: (graph: CounterHistoryGraph, program: Program) => void) {
  withFiles({ "main.compact": source(size, reset) }, directory => {
    const file = resolve(directory, "main.compact");
    if (compile) { const result = validateWithCompiler(process.env.COMPACTC_TEST!, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file);
    const extracted = extractTerminalCounterRegion(program, program.entries[0]);
    assert.equal(extracted.status, "eligible");
    if (extracted.status !== "eligible") throw new Error(JSON.stringify(extracted));
    const graph = buildCounterHistoryGraph(extracted.region);
    assert.equal(graph.status, "complete");
    if (graph.status !== "complete") throw new Error(JSON.stringify(graph));
    assert.equal(graph.work, 2 + Number(reset) * 2 + size * 4);
    check(graph.value, program);
  });
}

/** Separate arithmetic model of the owned fixture, never imported by the graph. */
function expected(assignment: readonly boolean[], reset: boolean) {
  let count: bigint | undefined = reset ? 0n : undefined;
  const rows: { before: string | undefined; after: string | undefined }[] = reset ? [{ before: undefined, after: "0" }] : [];
  assignment.forEach((taken, index) => {
    if (!taken) return;
    const before = count;
    if (count !== undefined) count += BigInt(index + 1);
    rows.push({ before: before?.toString(), after: count?.toString() });
  });
  return { rows, final: count?.toString() };
}

function projectedNumbers(value: CounterHistoryProjection) {
  const values = new Map<number, bigint | undefined>();
  for (const version of value.versions) {
    if (version.kind === "incoming") values.set(version.id, undefined);
    else {
      assert.ok(values.has(version.before!), "predecessors must precede their selected successors");
      const before = values.get(version.before!);
      values.set(version.id, version.kind === "reset" ? 0n : before === undefined ? undefined : before + version.amount!);
    }
  }
  return { rows: value.operations.map(operation => ({ before: values.get(operation.before)?.toString(), after: values.get(operation.after)?.toString() })), final: values.get(value.finalVersion)?.toString() };
}

for (const size of [1, 2, 3, 4, 5, 6, 7, 8]) test(`compiler-grounded ${size}-choice histories preserve complete ordered write tuples in all four exact modes`, qualified, () => {
  fixture(size, true, true, (graph, program) => {
    const expanded = expandCounterHistories(graph, 256, 1000000);
    assert.equal(expanded.status, "complete");
    if (expanded.status !== "complete") throw new Error(JSON.stringify(expanded));
    assert.equal(expanded.value.length, 2 ** size);
    for (const projection of expanded.value) assert.deepEqual(projectedNumbers(projection), expected(projection.decisions, true));
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.paths.length, expanded.value.length);
      const seen = new Set<string>();
      for (const path of facts.paths) {
        const assignment = path.path.filter(step => step.kind === "branch").map(step => {
          assert.match(step.label, /^condition may be (true|false)$/);
          return step.label === "condition may be true";
        });
        assert.equal(assignment.length, size);
        assert.equal(seen.has(JSON.stringify(assignment)), false);
        seen.add(JSON.stringify(assignment));
        const selected = projectCounterHistory(graph, assignment);
        assert.equal(selected.status, "complete");
        if (selected.status !== "complete") throw new Error(JSON.stringify(selected));
        assert.deepEqual(path.writes.map(write => ({ before: write.before.constant, after: write.after.constant })), expected(assignment, true).rows);
        assert.deepEqual(path.writes.map(write => write.location), selected.value.operations.map(operation => operation.location));
        assert.deepEqual(projectedNumbers(selected.value).rows, path.writes.map(write => ({ before: write.before.constant, after: write.after.constant })));
      }
    }
  });
});

test("unknown incoming Counter remains unknown while choices retain distinct effect histories", qualified, () => {
  fixture(4, false, true, (graph, program) => {
    const expansion = expandCounterHistories(graph);
    assert.equal(expansion.status, "complete");
    if (expansion.status !== "complete") throw new Error(JSON.stringify(expansion));
    for (const selected of expansion.value) assert.deepEqual(projectedNumbers(selected), expected(selected.decisions, false));
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.equal(facts.paths.length, 16);
    assert.ok(facts.paths.every(path => path.writes.every(write => write.before.constant === undefined && write.after.constant === undefined)));
  });
});

test("ten choices share a small graph; all 1024 assignments require an explicitly larger expansion budget", qualified, () => {
  fixture(10, true, true, graph => {
    assert.equal(graph.representedAssignments, 1024n);
    assert.equal(graph.versions.length + graph.histories.length, 44);
    const bounded = expandCounterHistories(graph);
    assert.equal(bounded.status, "incomplete");
    if (bounded.status === "incomplete") assert.equal(bounded.diagnostics[0].code, "correlated-expansion-budget");
    const expanded = expandCounterHistories(graph, 1024, 1000000);
    assert.equal(expanded.status, "complete");
    if (expanded.status !== "complete") throw new Error(JSON.stringify(expanded));
    for (const selected of expanded.value) assert.deepEqual(projectedNumbers(selected), expected(selected.decisions, true));
    // Mutually exclusive histories cannot mix predecessor/successor versions.
    const left = projectCounterHistory(graph, [true, false, ...Array(8).fill(false)]);
    const right = projectCounterHistory(graph, [false, true, ...Array(8).fill(false)]);
    assert.equal(left.status, "complete"); assert.equal(right.status, "complete");
    if (left.status === "complete" && right.status === "complete") {
      assert.equal(projectedNumbers(left.value).final, "1");
      assert.equal(projectedNumbers(right.value).final, "2");
      assert.notEqual(left.value.finalVersion, right.value.finalVersion);
    }
  });
});

test("graph, projection and aggregate expansion budgets have explicit independent incomplete outcomes", () => {
  fixture(4, true, false, (graph, program) => {
    const region = extractTerminalCounterRegion(program, program.entries[0]);
    assert.ok(region.status === "eligible");
    const count = graph.versions.length + graph.histories.length;
    assert.equal(buildCounterHistoryGraph(region.region, count).status, "complete");
    const limited = buildCounterHistoryGraph(region.region, count - 1);
    assert.equal(limited.status, "incomplete");
    if (limited.status === "incomplete") assert.equal(limited.diagnostics[0].code, "correlated-graph-budget");
    const selected = projectCounterHistory(graph, [true, false, true, false]);
    assert.equal(selected.status, "complete");
    assert.equal(projectCounterHistory(graph, [true, false, true, false], selected.work).status, "complete");
    const stopped = projectCounterHistory(graph, [true, false, true, false], selected.work - 1);
    assert.equal(stopped.status, "incomplete");
    if (stopped.status === "incomplete") assert.equal(stopped.diagnostics[0].code, "correlated-projection-budget");
    const expanded = expandCounterHistories(graph);
    assert.equal(expanded.status, "complete");
    assert.equal(expandCounterHistories(graph, 16, expanded.work).status, "complete");
    assert.equal(expandCounterHistories(graph, 16, expanded.work - 1).status, "incomplete");
    assert.equal(expandCounterHistories(graph, 15).status, "incomplete");
  });
});

test("graph/projection snapshots are immutable and assignments reject malformed or accessor data", () => {
  fixture(2, true, false, graph => {
    assert.throws(() => (graph.decisions as string[]).push("invented"));
    assert.throws(() => { (graph.location as { start: number }).start = -1; });
    const assignment = [true, false];
    const projected = projectCounterHistory(graph, assignment);
    assert.equal(projected.status, "complete");
    if (projected.status !== "complete") throw new Error(JSON.stringify(projected));
    assignment[0] = false;
    assert.deepEqual(projected.value.decisions, [true, false]);
    assert.throws(() => (projected.value.decisions as boolean[]).push(true));
    assert.throws(() => projectCounterHistory(graph, Array(2)));
    const getter = [true, false];
    Object.defineProperty(getter, "0", { get() { assert.fail("untrusted decision accessor must not execute"); } });
    assert.throws(() => projectCounterHistory(graph, getter));
    for (const budget of [0, -1, NaN, Infinity, 1000001]) assert.throws(() => projectCounterHistory(graph, [false, false], budget));
  });
});

test("independent tuple oracle detects deliberately decoupled history/storage choices", () => {
  fixture(2, true, false, graph => {
    // Internal fault injection, not an accepted external graph format.
    const broken = structuredClone(graph);
    const firstChoice = broken.versions.find(node => node.kind === "choice");
    assert.ok(firstChoice?.kind === "choice");
    (firstChoice as { decision: number }).decision = 1;
    const selected = projectCounterHistory(broken, [true, false]);
    assert.equal(selected.status, "complete");
    if (selected.status !== "complete") throw new Error(JSON.stringify(selected));
    assert.notDeepEqual(projectedNumbers(selected.value), expected([true, false], true));
  });
});


test("raised extraction branch budget composes with graph and projection budgets beyond 256 decisions", () => {
  withFiles({ "main.compact": source(257) }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const entry = program.entries[0];
    assert.equal(extractTerminalCounterRegion(program, entry).status, "incomplete");
    const extracted = extractTerminalCounterRegion(program, entry, { maxBranches: 257 });
    assert.equal(extracted.status, "eligible");
    if (extracted.status !== "eligible") throw new Error(JSON.stringify(extracted));
    const graph = buildCounterHistoryGraph(extracted.region);
    assert.equal(graph.status, "complete");
    if (graph.status !== "complete") throw new Error(JSON.stringify(graph));
    assert.equal(graph.work, 1032);
    assert.equal(graph.value.representedAssignments, 1n << 257n);
    const projection = projectCounterHistory(graph.value, Array(257).fill(true));
    assert.equal(projection.status, "complete");
    if (projection.status === "complete") assert.equal(projection.value.operations.length, 258);
    const limited = buildCounterHistoryGraph(extracted.region, 1031);
    assert.equal(limited.status, "incomplete");
    if (limited.status === "incomplete") assert.equal(limited.diagnostics[0].code, "correlated-graph-budget");
    assert.equal(expandCounterHistories(graph.value).status, "incomplete");
  });
});
