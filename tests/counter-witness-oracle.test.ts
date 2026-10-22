import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, type AbstractValue, type SuccessfulPath } from "../src/dataflow/index.js";
import type { Span } from "../src/model.js";
import { Program } from "../src/semantic/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
interface Fixture { size: 4 | 10; reset: boolean; returned: boolean; cast: boolean }
const amount = (index: number): bigint => index % 3 === 0 ? 0n : index % 3 === 1 ? 65535n : BigInt(index + 1);
const mutation = (input: Fixture, index: number): string => `count.increment(${amount(index)}${input.cast ? " as Uint<16>" : ""})`;
const branch = (input: Fixture, index: number): string => `if (disclose(flag${index})) { ${mutation(input, index)}; }`;
function render(input: Fixture): string {
  return `pragma language_version 0.26.0;
import CompactStandardLibrary;
export ledger count: Counter;
export circuit entry(${Array.from({ length: input.size }, (_, index) => `flag${index}: Boolean`).join(", ")}): [] {
  ${input.reset ? "count.resetToDefault();" : ""}
${Array.from({ length: input.size }, (_, index) => `  ${branch(input, index)}`).join("\n")}
  ${input.returned ? "return [];" : ""}
}
`;
}

/** ASCII renderer positions are independent of parser, CFG and observed spans. */
function site(text: string, file: string, fragment: string, startAt = 0): Span {
  const start = text.indexOf(fragment, startAt);
  assert.ok(start >= 0, fragment);
  const end = start + fragment.length;
  return { file, start, end, line: text.slice(0, start).split("\n").length, column: start - text.lastIndexOf("\n", start - 1),
    endLine: text.slice(0, end).split("\n").length, endColumn: end - text.lastIndexOf("\n", end - 1) };
}

/**
 * Fixed-fixture dependency contract, not a second implementation of transfers.
 * Expected choices, amounts and sites come only from the bounded input/renderer.
 * Semantic IDs identify declarations; no graph/projector or observed effect is
 * used to decide which operation, source, guard or trace should be present.
 */
function checkWitness(input: Fixture, decisions: readonly boolean[], path: SuccessfulPath, program: Program): void {
  assert.ok(input.size === 4 || input.size === 10);
  assert.equal(decisions.length, input.size);
  assert.ok(decisions.every(value => typeof value === "boolean"));
  const text = render(input);
  assert.equal(program.rootSource.text, text);
  const file = program.rootSource.path;
  const entry = program.entries[0];
  const root = program.activeSymbols().find(symbol => symbol.kind === "ledger")!.id;
  const at = (fragment: string): Span => site(text, file, fragment);
  const atMutation = (index: number): Span => site(text, file, mutation(input, index), text.indexOf(branch(input, index)));
  const parameter = (index: number) => {
    const location = at(`flag${index}: Boolean`);
    return { id: `${file}:${location.start}:${index}`, kind: "entry-parameter", name: `flag${index}`, location, symbol: `${entry}::parameter:flag${index}` };
  };
  const tags = (value: AbstractValue, lastDecision: number, lastWrite: number): void => {
    assert.equal(value.items, undefined);
    assert.equal(value.fields, undefined);
    assert.equal(value.flows.length, lastDecision + 1, "Control dependencies include every prior false choice as well as taken choices");
    assert.deepEqual(value.flows.map(flow => flow.source.name), Array.from({ length: lastDecision + 1 }, (_, index) => `flag${index}`));
    for (const [index, flow] of value.flows.entries()) {
      const expected = parameter(index);
      assert.deepEqual(flow.source, expected, "Source identity and declaration origin must remain stable");
      assert.equal(flow.form, "derived");
      assert.equal(flow.directPreimage, undefined);
      assert.deepEqual(flow.trace, [
        { kind: "source", label: expected.name, location: expected.location },
        { kind: "argument", label: expected.name, location: expected.location },
        { kind: "disclose", label: "explicit disclosure permission", location: at(`disclose(flag${index})`) },
        { kind: "implicit-flow", label: "private-dependent control flow", location: atMutation(lastWrite) },
      ], "Disclosure retains the source; current implicit control supplies the evidence at the write");
    }
  };
  assert.equal(path.entry, entry);
  assert.deepEqual(path.bindings, []);
  assert.deepEqual(path.path, decisions.map((selected, index) => ({ kind: "branch", label: `condition may be ${selected}`, location: at(branch(input, index)) })));
  const taken = decisions.flatMap((selected, index) => selected ? [index] : []);
  assert.equal(path.writes.length, taken.length + Number(input.reset));
  assert.equal(path.sinks.length, taken.length + Number(input.returned), "Reset has no private operation argument; increments have control sinks");
  let count: bigint | undefined;
  let previousDecision = -1;
  let previousWrite = -1;
  let contentsIdentity = `ledger:${JSON.stringify([root])}:0`;
  let allocations = 0;
  const expectedWrites = [...(input.reset ? [-1] : []), ...taken];
  expectedWrites.forEach((decision, writeIndex) => {
    const write = path.writes[writeIndex];
    const location = decision === -1 ? at("count.resetToDefault()") : atMutation(decision);
    assert.equal(write.ledger, root);
    assert.deepEqual(write.region, []);
    assert.deepEqual(write.location, location);
    assert.deepEqual(write.callPath, [entry]);
    assert.deepEqual(write.guards, [], "Branch assumptions and entry completion are not prior completed guards");
    assert.deepEqual(write.excludedBefore, []);
    assert.equal(write.before.type, "standard-type::Counter");
    assert.equal(write.after.type, "standard-type::Counter");
    assert.deepEqual(write.before.region, { root, path: [], type: "standard-type::Counter", revision: writeIndex });
    assert.equal(write.before.identity, contentsIdentity);
    assert.equal(write.after.region, undefined);
    const unchanged = decision !== -1 && amount(decision) === 0n;
    assert.equal(write.after.identity, unchanged ? contentsIdentity : undefined,
      "Zero updates retain contents identity; every write still advances its storage revision");
    if (!unchanged) contentsIdentity = `write:${allocations++}`;
    assert.deepEqual([...write.before.ledger], !input.reset || writeIndex === 0 ? [root] : []);
    assert.deepEqual([...write.after.ledger], input.reset ? [] : [root]);
    assert.equal(write.before.constant, count?.toString());
    assert.equal(write.before.constantKind, count === undefined ? undefined : "integer");
    tags(write.before, previousDecision, previousWrite);
    if (decision === -1) count = 0n;
    else if (count !== undefined) count += amount(decision);
    assert.equal(write.after.constant, count?.toString());
    assert.equal(write.after.constantKind, count === undefined ? undefined : "integer");
    tags(write.after, decision, decision);
    previousDecision = decision;
    previousWrite = decision;
  });
  taken.forEach((decision, index) => {
    const sink = path.sinks[index];
    assert.equal(sink.kind, "ledger-operation");
    assert.equal(sink.name, "count.increment");
    assert.deepEqual(sink.location, atMutation(decision));
    assert.deepEqual(sink.callPath, [entry]);
    assert.equal(sink.value.constant, undefined);
    assert.equal(sink.value.constantKind, undefined);
    assert.equal(sink.value.type, undefined);
    assert.equal(sink.value.identity, undefined);
    assert.equal(sink.value.region, undefined);
    assert.deepEqual([...sink.value.ledger], []);
    tags(sink.value, decision, decision);
  });
  if (input.returned) {
    const sink = path.sinks.at(-1)!;
    assert.equal(sink.kind, "exported-return");
    assert.equal(sink.name, "entry");
    assert.deepEqual(sink.location, at("return [];"));
    assert.deepEqual(sink.callPath, [entry]);
    assert.equal(sink.value.type, "[]");
    assert.deepEqual(sink.value.items, []);
    assert.deepEqual(sink.value.flows, [], "Empty return does not publish scalar control dependencies");
    assert.deepEqual([...sink.value.ledger], []);
    assert.equal(sink.value.fields, undefined);
    assert.equal(sink.value.constant, undefined);
    assert.equal(sink.value.identity, undefined);
    assert.equal(sink.value.region, undefined);
  }
}

function fixture(input: Fixture, check: (program: Program) => void): void {
  withFiles({ "main.compact": render(input) }, directory => {
    const file = resolve(directory, "main.compact");
    const result = validateWithCompiler(process.env.COMPACTC_TEST!, file);
    assert.equal(result.valid, true, result.error);
    check(new Program(file));
  });
}

function assignments(size: 4 | 10): boolean[][] {
  // Exhaust the small family. The ten-choice family uses fixed extremal,
  // alternating and one-hot schedules; the separate differential suite owns
  // exhaustive 1,024-assignment qualification.
  if (size === 4) return Array.from({ length: 16 }, (_, bits) => Array.from({ length: size }, (_, index) => Boolean(bits & (1 << index))));
  return [Array(size).fill(false), Array(size).fill(true),
    Array.from({ length: size }, (_, index) => index % 2 === 0), Array.from({ length: size }, (_, index) => index % 2 === 1),
    ...Array.from({ length: size }, (_, chosen) => Array.from({ length: size }, (_, index) => index === chosen))];
}

for (const size of [4, 10] as const) for (const reset of [false, true]) for (const returned of [false, true]) {
  const input: Fixture = { size, reset, returned, cast: returned };
  test(`independent selected Counter witness oracle: ${size} choices, ${reset ? "reset" : "unknown"}, ${returned ? "explicit" : "implicit"} void exit`, qualified, () => {
    fixture(input, program => {
      for (const decisions of assignments(size)) {
        const result = new Dataflow(program).selectCounterWitness(program.entries[0], decisions);
        assert.equal(result.status, "selected", result.status === "incomplete" ? JSON.stringify(result.diagnostics) : result.status);
        assert.ok(result.status === "selected");
        assert.deepEqual(result.decisions, decisions);
        assert.equal(result.metrics.paths, 1);
        assert.equal(result.metrics.sources, size);
        assert.equal(result.metrics.summaryHits, 0);
        assert.equal("completedEntries" in result, false);
        assert.equal("program" in result, false);
        checkWitness(input, decisions, result.path, program);
      }
    });
  });
}

test("independent Counter witness oracle rejects matching corrupted sites, origins, guards and histories", qualified, () => {
  const input: Fixture = { size: 4, reset: true, returned: true, cast: true };
  const decisions = [false, true, false, true];
  fixture(input, program => {
    const result = new Dataflow(program).selectCounterWitness(program.entries[0], decisions);
    assert.ok(result.status === "selected");
    checkWitness(input, decisions, result.path, program);
    const corruptions: ((path: SuccessfulPath) => void)[] = [
      path => { path.writes[1].after.flows = path.writes[1].after.flows.filter(flow => flow.source.name !== "flag0"); },
      path => { path.writes[2].before.flows = structuredClone(path.writes[2].after.flows); },
      path => { path.writes[1].guards.push(program.entries[0]); },
      path => { path.writes[1].after.flows[0].form = "raw"; },
      path => { path.writes[1].after.flows[0].trace.splice(2, 1); },
      path => { path.writes[1].after.flows[0].source.id = path.writes[1].after.flows[1].source.id; },
      path => { path.writes[1].after.flows[0].source.location.start++; },
      path => { path.writes[1].before.identity = path.writes[2].before.identity; },
      path => { path.writes[1].before.region!.revision = path.writes[1].before.region!.revision! + 1; },
      path => { path.sinks[0].kind = "ledger-write"; },
      path => { path.sinks[0].value.flows.push(structuredClone(path.writes[2].after.flows.at(-1)!)); },
      path => { path.sinks.at(-1)!.value.flows = structuredClone(path.writes[2].after.flows); },
      path => { path.writes[1].callPath.push(program.entries[0]); },
      path => { path.path[0].label = "condition may be true"; },
      path => { path.path[0].location = { ...path.path[1].location }; },
      path => { path.writes.pop(); path.sinks.splice(1, 1); },
    ];
    for (const corrupt of corruptions) {
      const changed = structuredClone(result.path);
      corrupt(changed);
      assert.throws(() => checkWitness(input, decisions, changed, program));
    }
    for (const field of ["file", "start", "end", "line", "column", "endLine", "endColumn"] as const) {
      const changed = structuredClone(result.path);
      const original = changed.writes[1].location;
      const wrong = { ...original, [field]: field === "file" ? `${original.file}.wrong` : original[field] + 1 };
      changed.writes[1].location = wrong;
      changed.sinks[0].location = { ...wrong };
      changed.writes[1].after.flows.forEach(flow => { flow.trace.at(-1)!.location = { ...wrong }; });
      changed.sinks[0].value.flows.forEach(flow => { flow.trace.at(-1)!.location = { ...wrong }; });
      assert.throws(() => checkWitness(input, decisions, changed, program), `Identical site corruption is not independent evidence: ${field}`);
    }
  });
});
