import test from "node:test";
import assert from "node:assert/strict";
import { ListFacts } from "../src/dataflow/lists.js";
import { Region } from "../src/dataflow/regions.js";

interface Value { readonly id: string }
const value = (id: string): Value => Object.freeze({ id });
const first = value("first");
const second = value("second");
const emptyStructure = value("empty structure");
const unknownStructure = value("unknown structure");
const list = (root: string, path: string[] = []): Region => ({ root, path, type: "List<Field>" });

function assertConcrete(facts: ListFacts<Value>, region: Region, expected: readonly Value[], context: string): void {
  const observed = facts.view(region);
  assert.ok(observed, context);
  assert.equal(observed.length, expected.length, `${context}: length`);
  assert.equal(observed.empty, expected.length === 0, `${context}: empty`);
  assert.deepEqual(observed.head, expected[0], `${context}: head`);
}

test("bounded List sequences agree with an independent concrete array model", () => {
  const region = list("items");
  const initial = new ListFacts<Value>();
  initial.reset(region, emptyStructure);
  let visited = 0;
  const visit = (facts: ListFacts<Value>, concrete: readonly Value[], trace: string[], depth: number): void => {
    visited++;
    const label = trace.join("/") || "initial";
    assertConcrete(facts, region, concrete, label);
    assert.equal(facts.exhausted, false, label);
    if (depth === 0) return;
    for (const operation of ["reset", "push first", "push second", "pop"] as const) {
      const parent = facts.snapshot();
      const branch = facts.clone();
      let expected: readonly Value[];
      if (operation === "reset") {
        branch.reset(region, emptyStructure);
        expected = [];
      } else if (operation === "pop") {
        if (concrete.length === 0) {
          // Empty pop is an explicit unsupported outcome, not an array no-op.
          assert.equal(branch.pop(region), false, `${label}/empty pop`);
          assert.equal(branch.view(region), undefined);
          assert.equal(branch.exhausted, false);
          assert.deepEqual(facts.snapshot(), parent);
          continue;
        }
        assert.equal(branch.pop(region), true, label);
        expected = concrete.slice(1);
      } else {
        const item = operation === "push first" ? first : second;
        branch.push(region, item, value(`${label}/${operation}`), unknownStructure);
        expected = [item, ...concrete];
      }
      visit(branch, expected, [...trace, operation], depth - 1);
      assert.deepEqual(facts.snapshot(), parent, `${label}: branch isolation`);
    }
  };
  visit(initial, [], [], 5);
  assert.ok(visited > 500, "exercise composed transitions rather than isolated operations");
});

test("a known prefix over unknown entry storage preserves head but not length or tail emptiness", () => {
  const region = list("items");
  const facts = new ListFacts<Value>();
  const firstStructure = value("first push");
  const secondStructure = value("second push");
  assert.equal(facts.view(region), undefined);
  facts.push(region, first, firstStructure, unknownStructure);
  assert.deepEqual(facts.view(region), { head: first, empty: false, length: undefined, structure: firstStructure });
  facts.push(region, second, secondStructure, unknownStructure);
  assert.deepEqual(facts.view(region), { head: second, empty: false, length: undefined, structure: secondStructure });
  assert.equal(facts.pop(region), true);
  assert.deepEqual(facts.view(region), { head: first, empty: false, length: undefined, structure: firstStructure });
  assert.equal(facts.pop(region), true);
  assert.deepEqual(facts.view(region), { head: undefined, empty: undefined, length: undefined, structure: unknownStructure });
  assert.equal(facts.pop(region), false);
  assert.equal(facts.view(region), undefined);
  assert.equal(facts.exhausted, false);
});

test("unknown and empty pops forget affected facts and remain distinct from exhaustion", () => {
  const region = list("items");
  const facts = new ListFacts<Value>();
  assert.equal(facts.pop(region), false);
  facts.reset(region, emptyStructure);
  assertConcrete(facts, region, [], "reset");
  assert.equal(facts.pop(region), false);
  assert.equal(facts.view(region), undefined);
  assert.equal(facts.exhausted, false);
  facts.reset(region, emptyStructure);
  facts.push(region, first, value("after reset"), unknownStructure);
  assertConcrete(facts, region, [first], "reset recovers explicit known contents");
});

test("payload order and saved structure provenance are restored independently", () => {
  const region = list("items");
  const facts = new ListFacts<Value>();
  const structureFirst = value("after first push");
  const structureSecond = value("after second push");
  facts.reset(region, emptyStructure);
  facts.push(region, first, structureFirst, unknownStructure);
  facts.push(region, second, structureSecond, unknownStructure);
  const restored: Value[] = [];
  const poppedStructure = value("first structure plus pop context");
  assert.equal(facts.pop(region, previous => { restored.push(previous); return poppedStructure; }), true);
  assert.deepEqual(restored, [structureFirst]);
  assertConcrete(facts, region, [first], "one pop");
  assert.equal(facts.view(region)!.structure, poppedStructure);
  assert.equal(facts.pop(region, previous => { restored.push(previous); return previous; }), true);
  assert.deepEqual(restored, [structureFirst, emptyStructure]);
  assertConcrete(facts, region, [], "two pops");
  assert.equal(facts.view(region)!.structure, emptyStructure);
});

test("clones and snapshots detach containers while preserving immutable payload identity", () => {
  const region = list("items", ["key:integer:1"]);
  const facts = new ListFacts<Value>();
  facts.reset(region, emptyStructure);
  facts.push(region, first, value("push first"), unknownStructure);
  // The input Region is caller-owned and can be reused or changed afterwards.
  region.path.push("field:changed");
  const storedRegion = list("items", ["key:integer:1"]);
  assertConcrete(facts, storedRegion, [first], "caller region mutation");
  const before = facts.snapshot();
  const exposedView = facts.view(storedRegion)!;
  exposedView.head = second;
  exposedView.length = 99;
  exposedView.structure = unknownStructure;
  assert.deepEqual(facts.snapshot(), before, "returned view is not the retained container");
  const snapshot = facts.snapshot();
  snapshot.lists[0].region.path.push("field:snapshot-only");
  snapshot.lists[0].prefix[0].value = second;
  snapshot.lists[0].prefix[0].previousStructure = unknownStructure;
  snapshot.lists[0].prefix.push({ value: second, previousStructure: unknownStructure });
  snapshot.lists[0].structure = unknownStructure;
  snapshot.lists.length = 0;
  assert.deepEqual(facts.snapshot(), before);
  assert.equal(facts.view(storedRegion)!.head, first);
  const branch = facts.clone();
  branch.push(storedRegion, second, value("branch push"), unknownStructure);
  assertConcrete(branch, storedRegion, [second, first], "branch");
  assertConcrete(facts, storedRegion, [first], "parent");
  assert.equal(branch.pop(storedRegion), true);
  branch.reset(storedRegion, unknownStructure);
  assertConcrete(facts, storedRegion, [first], "branch reset");
});

test("wildcard mutations invalidate possible aliases without creating universal order facts", () => {
  const firstRegion = list("table", ["key:integer:1"]);
  const secondRegion = list("table", ["key:integer:2"]);
  const other = list("other");
  const wildcard = list("table", ["key:*"]);
  for (const operation of ["push", "reset", "pop"] as const) {
    const facts = new ListFacts<Value>();
    for (const region of [firstRegion, secondRegion, other]) {
      facts.reset(region, emptyStructure);
      facts.push(region, first, value("known push"), unknownStructure);
    }
    if (operation === "push") facts.push(wildcard, second, value("dynamic push"), unknownStructure);
    else if (operation === "reset") facts.reset(wildcard, emptyStructure);
    else assert.equal(facts.pop(wildcard), false);
    assert.equal(facts.view(wildcard), undefined, operation);
    assert.equal(facts.view(firstRegion), undefined, operation);
    assert.equal(facts.view(secondRegion), undefined, operation);
    assertConcrete(facts, other, [first], `${operation}: disjoint storage`);
    assert.equal(facts.exhausted, false);
  }
});

test("ancestor writes invalidate descendants while siblings and unrelated roots survive", () => {
  const firstRegion = list("table", ["key:integer:1", "field:items"]);
  const secondRegion = list("table", ["key:integer:2", "field:items"]);
  const other = list("other");
  const facts = new ListFacts<Value>();
  for (const region of [firstRegion, secondRegion, other]) {
    facts.reset(region, emptyStructure);
    facts.push(region, first, value("insert"), unknownStructure);
  }
  facts.invalidateWrite({ root: "table", path: ["key:integer:1"], type: "unknown" });
  assert.equal(facts.view(firstRegion), undefined);
  assertConcrete(facts, secondRegion, [first], "sibling");
  assertConcrete(facts, other, [first], "unrelated root");
  facts.invalidateWrite({ root: "table", path: [], type: "unknown" });
  assert.equal(facts.view(secondRegion), undefined);
  assertConcrete(facts, other, [first], "unrelated root after ancestor reset");
});

test("region and shared-cell limits exhaust explicitly without leaving stale heads", () => {
  const a = list("a");
  const b = list("b");
  const c = list("c");
  const regions = new ListFacts<Value>(2);
  regions.reset(a, emptyStructure);
  regions.reset(b, emptyStructure);
  regions.reset(c, emptyStructure);
  assert.equal(regions.exhausted, true);
  assertConcrete(regions, a, [], "first retained region");
  assertConcrete(regions, b, [], "second retained region");
  assert.equal(regions.view(c), undefined);
  regions.invalidateWrite(a);
  regions.reset(c, emptyStructure);
  assertConcrete(regions, c, [], "released region slot");
  assert.equal(regions.exhausted, true, "reset must not erase the incomplete signal");

  const cells = new ListFacts<Value>(2);
  cells.reset(a, emptyStructure);
  cells.reset(b, emptyStructure);
  cells.push(a, first, value("a first"), unknownStructure);
  cells.push(b, first, value("b first"), unknownStructure);
  cells.push(a, second, value("a second"), unknownStructure);
  assert.equal(cells.exhausted, true);
  assert.equal(cells.view(a), undefined, "over-budget push cannot retain the old first head");
  assertConcrete(cells, b, [first], "disjoint cell survives");
  cells.push(a, second, value("new known prefix"), unknownStructure);
  assert.equal(cells.view(a)!.head, second);
  assert.equal(cells.view(a)!.length, undefined, "lost tail cannot become empty");
  assert.equal(cells.clone().exhausted, true);
  assert.deepEqual(cells.clone().snapshot(), cells.snapshot());
});

test("pop and invalidation release cell capacity; exhausted clones remain isolated", () => {
  const region = list("items");
  const facts = new ListFacts<Value>(1);
  facts.reset(region, emptyStructure);
  facts.push(region, first, value("first push"), unknownStructure);
  assert.equal(facts.pop(region), true);
  facts.push(region, second, value("second push"), unknownStructure);
  assertConcrete(facts, region, [second], "pop releases cell");
  assert.equal(facts.exhausted, false);
  const branch = facts.clone();
  branch.push(region, first, value("over budget"), unknownStructure);
  assert.equal(branch.exhausted, true);
  assert.equal(facts.exhausted, false);
  facts.invalidateWrite(region);
  facts.reset(region, emptyStructure);
  facts.push(region, first, value("after invalidation"), unknownStructure);
  assertConcrete(facts, region, [first], "invalidation releases cell");
  assert.equal(facts.exhausted, false);
});

test("zero and non-finite limits report exhaustion and retain no optimistic empty facts", () => {
  const region = list("items");
  for (const limit of [0, -1, NaN, Infinity]) {
    const facts = new ListFacts<Value>(limit);
    facts.reset(region, emptyStructure);
    facts.push(region, first, value("push"), unknownStructure);
    assert.equal(facts.exhausted, true, String(limit));
    assert.equal(facts.view(region), undefined, String(limit));
    assert.equal(facts.pop(region), false, String(limit));
    assert.equal(facts.clone().snapshot().exhausted, true);
  }
});

test("stable snapshots and value visitation retain hidden tail structure dependencies", () => {
  const a = list("a");
  const z = list("z");
  const facts = new ListFacts<Value>();
  const firstStructure = value("structure after first");
  const secondStructure = value("structure after second");
  facts.reset(z, unknownStructure);
  facts.reset(a, emptyStructure);
  facts.push(a, first, firstStructure, unknownStructure);
  facts.push(a, second, secondStructure, unknownStructure);
  assert.deepEqual(facts.snapshot().lists.map(entry => entry.region.root), ["a", "z"]);
  assert.deepEqual(facts.snapshot(), facts.clone().snapshot());
  const retained = new Set<Value>();
  facts.visitValues(entry => retained.add(entry));
  assert.deepEqual(retained, new Set([unknownStructure, emptyStructure, firstStructure, secondStructure, first, second]));
  facts.reset(a, emptyStructure);
  const afterReset = new Set<Value>();
  facts.visitValues(entry => afterReset.add(entry));
  assert.deepEqual(afterReset, new Set([unknownStructure, emptyStructure]));
});

test("nonempty tail refinement enables exactly one lossy pop without inventing a payload", () => {
  const region = list("items");
  const facts = new ListFacts<Value>();
  assert.equal(facts.assumeEmpty(region, false, unknownStructure), true);
  assert.deepEqual(facts.view(region), { head: undefined, empty: false, length: undefined, structure: unknownStructure });
  assert.equal(facts.assumeEmpty(region, true, emptyStructure), false);
  const before = facts.snapshot();
  const branch = facts.clone();
  const popped = value("tail and pop control");
  assert.equal(branch.pop(region, previous => { assert.equal(previous, unknownStructure); return popped; }), true);
  assert.deepEqual(branch.view(region), { head: undefined, empty: undefined, length: undefined, structure: popped });
  assert.notDeepEqual(branch.snapshot(), before);
  assert.deepEqual(facts.snapshot(), before);
  assert.equal(branch.pop(region), false);
  assert.equal(branch.exhausted, false);
});

test("a prefix nonempty proof cannot strengthen its unknown suffix, but an earlier tail proof survives", () => {
  const region = list("items");
  for (const refinedBeforePush of [false, true]) {
    const facts = new ListFacts<Value>();
    if (refinedBeforePush) facts.assumeEmpty(region, false, unknownStructure);
    facts.push(region, first, value("pushed structure"), unknownStructure);
    assert.equal(facts.assumeEmpty(region, false, emptyStructure), true);
    assert.equal(facts.assumeEmpty(region, true, emptyStructure), false);
    assert.equal(facts.pop(region), true);
    assert.equal(facts.view(region)!.empty, refinedBeforePush ? false : undefined);
    assert.equal(facts.pop(region), refinedBeforePush);
  }
});

test("empty refinement retains structural evidence and rejects a conflicting nonempty proof", () => {
  const region = list("items");
  const facts = new ListFacts<Value>();
  assert.equal(facts.assumeEmpty(region, true, unknownStructure), true);
  assertConcrete(facts, region, [], "asserted empty");
  assert.equal(facts.view(region)!.structure, unknownStructure);
  assert.equal(facts.assumeEmpty(region, false, emptyStructure), false);
  assert.equal(facts.pop(region), false);
});

test("assumption-created regions obey alias invalidation, bounded allocation and sticky exhaustion", () => {
  const firstRegion = list("table", ["key:integer:1"]);
  const secondRegion = list("table", ["key:integer:2"]);
  const other = list("other");
  const wildcard = list("table", ["key:*"]);
  const facts = new ListFacts<Value>(2);
  assert.equal(facts.assumeEmpty(wildcard, false, unknownStructure), true);
  assert.equal(facts.assumeEmpty(wildcard, true, unknownStructure), true);
  assert.deepEqual(facts.snapshot().lists, []);
  facts.assumeEmpty(firstRegion, false, unknownStructure);
  facts.assumeEmpty(secondRegion, true, emptyStructure);
  const retained = new Set<Value>();
  facts.visitValues(item => retained.add(item));
  assert.deepEqual(retained, new Set([unknownStructure, emptyStructure]));
  facts.assumeEmpty(other, false, unknownStructure);
  assert.equal(facts.view(other), undefined);
  assert.equal(facts.exhausted, true);
  facts.invalidateWrite(firstRegion);
  assert.equal(facts.view(firstRegion), undefined);
  assert.equal(facts.view(secondRegion)!.empty, true);
  facts.assumeEmpty(firstRegion, false, unknownStructure);
  facts.invalidateWrite(wildcard);
  assert.deepEqual(facts.snapshot().lists, []);
  facts.assumeEmpty(other, false, unknownStructure);
  assert.equal(facts.clone().exhausted, true);
  const snapshot = facts.snapshot();
  snapshot.lists[0].tail = "empty";
  assert.equal(facts.view(other)!.empty, false, "snapshot mutation is detached");
});
