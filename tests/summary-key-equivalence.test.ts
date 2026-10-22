import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, type AbstractValue } from "../src/index.js";
import { withFiles } from "./helpers.js";

const location = { file: "summary-key.compact", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
const scalar = (label: string): AbstractValue => ({ flows: [{ source: { id: "secret", name: "secret", kind: "witness", location }, form: "raw", trace: [{ kind: "read", label, location }] }], ledger: new Set(), identity: "x" });
const entries = <T>(mapping: Map<string, T>): [string, T][] => [...mapping].sort(([a], [b]) => a.localeCompare(b));

type FakeState = {
  control: { value: AbstractValue; until: number; owner: string }[];
  known: Map<string, { kind: "integer"; value: string }>;
  truths: Map<string, boolean>;
  excluded: Map<string, Set<string>>;
  aggregateExclusions: Map<string, readonly (readonly [string, { kind: "integer"; value: string }])[]>;
  aggregateExclusionsExhausted: boolean;
  scalarEqualities?: Map<string, { left: AbstractValue; right: AbstractValue; equals: boolean }>;
  scalarEqualitiesExhausted?: boolean;
  integerDomains?: Map<string, { minimum: string; maximum: string }>;
  orderings?: Map<string, { predicate: NonNullable<AbstractValue["ordering"]>; truth: boolean }>;
  orderingsExhausted?: boolean;
  ledger: Map<string, AbstractValue>;
  ledgerVersions: Map<string, number>;
  collections: { snapshot: () => { collections: unknown[] } };
  lists: { snapshot: () => { lists: unknown[] } };
};
const state = (): FakeState => ({ control: [], known: new Map(), truths: new Map(), excluded: new Map(), aggregateExclusions: new Map(), aggregateExclusionsExhausted: false,
  ledger: new Map(), ledgerVersions: new Map(), collections: { snapshot: () => ({ collections: [] }) }, lists: { snapshot: () => ({ lists: [] }) } });

function legacySummaryKey(circuit: string, args: AbstractValue[], input: FakeState): string {
  const json = JSON.stringify({ circuit, args, control: input.control, known: entries(input.known), truths: entries(input.truths), excluded: entries(input.excluded), aggregateExclusions: entries(input.aggregateExclusions), aggregateExclusionsExhausted: input.aggregateExclusionsExhausted,
    scalarEqualities: input.scalarEqualities ? entries(input.scalarEqualities) : undefined, scalarEqualitiesExhausted: input.scalarEqualitiesExhausted,
    integerDomains: input.integerDomains ? entries(input.integerDomains) : undefined, orderings: input.orderings ? entries(input.orderings) : undefined, orderingsExhausted: input.orderingsExhausted }, (_, value) => value instanceof Set ? [...value].sort() : value);
  return createHash("sha256").update(json).digest("hex");
}

function legacyReadKey(base: string, input: FakeState): string {
  const json = JSON.stringify({ base, ledger: [...input.ledger].sort(([a], [b]) => a.localeCompare(b)), revisions: [["scalar", input.ledgerVersions.get("scalar") ?? 0]], collections: [], lists: [] }, (_, value) => value instanceof Set ? [...value].sort() : value);
  return createHash("sha256").update(json).digest("hex");
}

function assertPartitions(rows: { legacy: string; current: string }[]): void {
  for (const first of rows) for (const second of rows) {
    assert.equal(first.current === second.current, first.legacy === second.legacy,
      "summary equivalence must match the full legacy serialization");
  }
}

function makeDataflow(callback: (df: Dataflow, program: Program) => void): void {
  withFiles({ "main.compact": "import CompactStandardLibrary; export ledger scalar: Field; circuit read(): Field { return scalar; } export circuit entry(): Field { return read(); }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    callback(new Dataflow(program), program);
  });
}

test("summary keys preserve legacy equivalence partitions, including trace identity", () => {
  makeDataflow(df => {
    const args = [scalar("first")], original = state();
    const partitions: { legacy: string; current: string }[] = [];
    const capture = (values: AbstractValue[], input: FakeState) => partitions.push({
      legacy: legacySummaryKey("read", values, input), current: (df as any).summaryKey("read", values, input),
    });
    capture(args, original);
    capture(structuredClone(args), state());
    const changedTrace = state();
    args[0] = scalar("first");
    const legacy = legacySummaryKey("read", args, original);
    const key = (df as any).summaryKey("read", args, original) as string;
    assert.equal(key, (df as any).summaryKey("read", args, original));
    assert.equal(Boolean(key), Boolean(legacy));
    // Diagnostic traces are part of the value fingerprint and therefore keep
    // distinct summaries separate, just as the original JSON key did.
    const changedArgs = [scalar("second")];
    capture(changedArgs, changedTrace);
    assert.notEqual(legacySummaryKey("read", changedArgs, changedTrace), legacy);
    assert.notEqual((df as any).summaryKey("read", changedArgs, changedTrace), key);
    original.known.set("x", { kind: "integer", value: "1" });
    capture(args, original);
    assert.notEqual((df as any).summaryKey("read", args, original), key);
    original.truths.set("flag", true);
    capture(args, original);
    assert.notEqual((df as any).summaryKey("read", args, original), key);
    original.known.clear(); original.truths.clear();
    capture(args, original);
    original.control.push({ value: scalar("control-a"), until: 5, owner: "caller" });
    capture(args, original);
    original.control = [{ value: scalar("control-b"), until: 5, owner: "caller" }];
    capture(args, original);
    original.control = [];
    original.excluded.set("x", new Set(["integer:1", "integer:2"]));
    capture(args, original);
    original.excluded.set("x", new Set(["integer:2", "integer:1"]));
    capture(args, original);
    assertPartitions(partitions);
  });
});

test("scalar constraints, engine/cache modes, and returned facts retain summary behavior", () => {
  makeDataflow(df => {
    const args = [scalar("x")], input = state();
    const baseline = (df as any).summaryKey("read", args, input) as string;
    input.scalarEqualities = new Map([["eq", { left: scalar("a"), right: scalar("b"), equals: true }]]);
    assert.notEqual((df as any).summaryKey("read", args, input), baseline);
    input.orderings = new Map([["ord", { predicate: { operator: "<", left: scalar("a"), right: scalar("b"), numericType: "Uint<8>" }, truth: true }]]);
    assert.notEqual((df as any).summaryKey("read", args, input), baseline);
  });
  withFiles({ "main.compact": "import CompactStandardLibrary; export ledger scalar: Field; circuit read(): Field { return scalar; } export circuit entry(): Field { return read(); }" }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    const results = [
      new Dataflow(program, 20000, 256, 50000, "instructions", true, true).analyze(),
      new Dataflow(program, 20000, 256, 50000, "instructions", false, false).analyze(),
      new Dataflow(program, 20000, 256, 50000, "expressions", true, false).analyze(),
    ];
    for (const facts of results) {
      assert.deepEqual(facts.diagnostics, []);
      assert.ok(facts.paths.length > 0);
    }
    assert.deepEqual(results[0].paths, results[1].paths);
  });
});

test("read-summary keys include selected ledger revisions and retain legacy partitions", () => {
  makeDataflow((df, program) => {
    const fn = [...program.functions.values()].find(item => item.symbol.name === "read");
    assert.ok(fn);
    program.ensureFunction(fn.symbol.id);
    const readFn = { ...fn, readsState: new Set(["scalar"]), writesState: new Set() } as typeof fn;
    const args = [scalar("x")], input = state();
    const base = (df as any).summaryKey(fn.symbol.id, args, input) as string;
    const current = (df as any).readSummaryKey(readFn, args, input) as string;
    assert.equal(current, (df as any).readSummaryKey(readFn, args, input));
    const legacy = legacyReadKey(legacySummaryKey(fn.symbol.id, args, input), input);
    const partitions = [{ legacy, current }];
    const capture = () => partitions.push({
      legacy: legacyReadKey(legacySummaryKey(fn.symbol.id, args, input), input),
      current: (df as any).readSummaryKey(readFn, args, input),
    });
    input.ledgerVersions.set("scalar", 1);
    capture();
    assert.notEqual((df as any).readSummaryKey(readFn, args, input), current);
    assert.equal(typeof legacy, "string", "legacy read-summary oracle remains available for partition comparisons");
    assert.notEqual(base, current);
    input.ledgerVersions.set("scalar", 0);
    capture();
    input.ledger.set(JSON.stringify(["scalar"]), scalar("ledger-a"));
    capture();
    input.ledger.set(JSON.stringify(["scalar"]), scalar("ledger-b"));
    capture();
    input.ledger.clear();
    capture();
    assertPartitions(partitions);
  });
});
