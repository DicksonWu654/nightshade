import test from "node:test";
import assert from "node:assert/strict";
import { CollectionFacts } from "../src/dataflow/collections.js";
import { Region } from "../src/dataflow/regions.js";

const collection = (root: string, path: string[] = []): Region => ({ root, path, type: "Map<Field, Field>" });
const keys = ["integer:0", "integer:1", "integer:2"];

test("common collection facts hold in both concrete alternatives", () => {
  const region = collection("table");
  const alternatives = Array.from({ length: 1 << keys.length }, (_, bits) => {
    const facts = new CollectionFacts(); facts.reset(region);
    const concrete = new Set(keys.filter((_, index) => bits & 1 << index));
    for (const key of concrete) facts.insert(region, key);
    return { facts, concrete };
  });
  for (const left of alternatives) for (const right of alternatives) {
    const joined = left.facts.common(right.facts);
    assert.equal(joined.exhausted, false);
    assertSound(joined, region, [left.concrete, right.concrete], "common alternatives");
    assert.deepEqual(joined.snapshot(), right.facts.common(left.facts).snapshot());
    for (const key of keys) assert.equal(joined.member(region, key),
      left.concrete.has(key) === right.concrete.has(key) ? left.concrete.has(key) : undefined);
    assert.equal(joined.size(region), left.concrete.size === right.concrete.size ? left.concrete.size : undefined);
  }
});

test("a missing collection observation contributes no emptiness or membership proof", () => {
  const region = collection("table"), empty = new CollectionFacts(), unknown = new CollectionFacts();
  empty.reset(region);
  for (const joined of [empty.common(unknown), unknown.common(empty)]) {
    assert.equal(joined.member(region, keys[0]), undefined);
    assert.equal(joined.size(region), undefined);
    assert.equal(joined.isEmpty(region), undefined);
  }
});

test("common facts retain explicit negatives across uncertain dynamic aliases", () => {
  const region = collection("table"), left = new CollectionFacts(), right = new CollectionFacts();
  for (const [facts, key] of [[left, "identity:first"], [right, "identity:second"]] as const) {
    facts.reset(region); facts.insert(region, key);
    assert.equal(facts.assumeMember(region, keys[0], false), true);
  }
  const before = [left.snapshot(), right.snapshot()];
  const joined = left.common(right);
  assert.equal(joined.exhausted, false);
  assert.equal(joined.member(region, keys[0]), false);
  assert.equal(joined.member(region, keys[1]), undefined);
  assert.equal(joined.member(region, "identity:first"), undefined);
  assert.equal(joined.member(region, "identity:second"), undefined);
  assert.equal(joined.size(region), 1);
  assert.equal(joined.isEmpty(region), false);
  joined.insert(region, "identity:first");
  assert.equal(joined.member(region, keys[0]), undefined);
  joined.reset(region);
  assert.deepEqual([left.snapshot(), right.snapshot()], before, "the original branch stores are immutable inputs to common");
});

test("an exhausted common exception set cannot expose a partial empty default", () => {
  const region = collection("table"), left = new CollectionFacts(2), right = new CollectionFacts(2);
  left.reset(region); right.reset(region);
  left.insert(region, "integer:0"); left.insert(region, "integer:1");
  right.insert(region, "integer:2"); right.insert(region, "integer:3");
  const joined = left.common(right);
  assert.equal(joined.exhausted, true);
  for (const key of ["integer:0", "integer:1", "integer:2", "integer:3", "integer:99"])
    assert.equal(joined.member(region, key), undefined);
  assert.equal(joined.size(region), undefined);
  assert.equal(joined.isEmpty(region), undefined);
  assert.equal(joined.common(new CollectionFacts()).exhausted, true);
});

type Operation = { kind: "reset" } | { kind: "insert" | "remove"; key: string | undefined };

function applyConcrete(states: Set<string>[], operation: Operation): Set<string>[] {
  if (operation.kind === "reset") return [new Set()];
  const selected = operation.key === undefined ? keys : [operation.key];
  return selected.flatMap(key => states.map(previous => {
    const next = new Set(previous);
    if (operation.kind === "insert") next.add(key);
    else next.delete(key);
    return next;
  }));
}

function applyAbstract(facts: CollectionFacts, region: Region, operation: Operation): void {
  if (operation.kind === "reset") facts.reset(region);
  else if (operation.kind === "insert") facts.insert(region, operation.key);
  else facts.remove(region, operation.key);
}

function assertSound(facts: CollectionFacts, region: Region, states: Set<string>[], label: string): void {
  for (const key of keys) {
    const member = facts.member(region, key);
    if (member !== undefined) assert.ok(states.every(state => state.has(key) === member), `${label}: ${key}`);
  }
  const size = facts.size(region);
  if (size !== undefined) assert.ok(states.every(state => state.size === size), `${label}: size`);
  const unknown = facts.member(region, undefined);
  if (unknown !== undefined) assert.ok(states.every(state => keys.every(key => state.has(key) === unknown)), `${label}: unknown member`);
}

test("short deterministic operation sequences remain sound against concrete sets", () => {
  const region = collection("table");
  const operations: Operation[] = [
    { kind: "reset" },
    { kind: "insert", key: keys[0] },
    { kind: "insert", key: undefined },
    { kind: "remove", key: keys[1] },
    { kind: "remove", key: undefined },
  ];
  const initial = Array.from({ length: 1 << keys.length }, (_, bits) => new Set(keys.filter((_, index) => bits & 1 << index)));
  const visit = (facts: CollectionFacts, states: Set<string>[], sequence: string[], depth: number): void => {
    assertSound(facts, region, states, sequence.join(" ") || "initial");
    if (depth === 0) return;
    operations.forEach((operation, index) => {
      const branch = facts.clone();
      applyAbstract(branch, region, operation);
      visit(branch, applyConcrete(states, operation), [...sequence, String(index)], depth - 1);
    });
  };
  visit(new CollectionFacts(), initial, [], 4);
});

test("stable dynamic keys remain sound for mutations and refinements in either alias direction", () => {
  const region = collection("table");
  const dynamic = ["identity:first", "identity:second"];
  const queries = [...keys, ...dynamic];
  type World = { values: Map<string, string>; members: Set<string> };
  const initial: World[] = keys.flatMap(first => keys.flatMap(second =>
    Array.from({ length: 1 << keys.length }, (_, bits) => ({
      values: new Map([[dynamic[0], first], [dynamic[1], second]]),
      members: new Set(keys.filter((_, index) => bits & 1 << index)),
    }))));
  type Action = Operation | { kind: "assume"; key: string; present: boolean };
  const actions: Action[] = [
    { kind: "reset" },
    ...[keys[0], dynamic[0], undefined].map(key => ({ kind: "insert" as const, key })),
    ...[keys[1], dynamic[1], undefined].map(key => ({ kind: "remove" as const, key })),
    ...[keys[0], dynamic[0]].flatMap(key => [false, true].map(present => ({ kind: "assume" as const, key, present }))),
  ];
  const visit = (facts: CollectionFacts, worlds: World[], label: string, depth: number): void => {
    for (const key of queries) {
      const member = facts.member(region, key);
      if (member !== undefined) assert.ok(worlds.every(world => world.members.has(world.values.get(key) ?? key) === member), `${label}: ${key}=${member}`);
    }
    const size = facts.size(region);
    if (size !== undefined) assert.ok(worlds.every(world => world.members.size === size), `${label}: size=${size}`);
    const empty = facts.isEmpty(region);
    if (empty !== undefined) assert.ok(worlds.every(world => (world.members.size === 0) === empty), `${label}: empty=${empty}`);
    if (depth === 0) return;
    for (const action of actions) {
      const next = facts.clone();
      const trail = `${label} ${JSON.stringify(action)}`;
      if (action.kind === "assume") {
        const possible = worlds.filter(world => world.members.has(world.values.get(action.key) ?? action.key) === action.present);
        const accepted = next.assumeMember(region, action.key, action.present);
        if (!accepted) assert.equal(possible.length, 0, `${trail}: feasible assumption rejected`);
        if (accepted && possible.length) visit(next, possible, trail, depth - 1);
      } else {
        applyAbstract(next, region, action);
        const possible = worlds.flatMap(world => {
          const operation = action.kind === "reset" ? action : { ...action, key: action.key === undefined ? undefined : world.values.get(action.key) ?? action.key };
          return applyConcrete([world.members], operation).map(members => ({ ...world, members }));
        });
        visit(next, possible, trail, depth - 1);
      }
    }
  };
  visit(new CollectionFacts(), initial, "initial", 4);
});

test("nested dynamic receivers weaken concrete aliases and vice versa", () => {
  const concrete = collection("table", ["key:integer:0"]);
  const dynamic = collection("table", ["key:identity:parent"]);
  for (const [first, second] of [[concrete, dynamic], [dynamic, concrete]]) {
    const facts = new CollectionFacts();
    facts.reset(first);
    facts.insert(second, keys[0]);
    assert.equal(facts.member(first, keys[0]), undefined);
    assert.equal(facts.member(second, keys[0]), true);
    facts.remove(first, keys[0]);
    assert.equal(facts.member(second, keys[0]), undefined);
    facts.reset(first);
    assert.equal(facts.size(second), undefined);
  }
});

test("unknown initial storage, repeated operations, and clone isolation", () => {
  const region = collection("table");
  const facts = new CollectionFacts();
  assert.equal(facts.member(region, keys[0]), undefined);
  assert.equal(facts.size(region), undefined);
  facts.insert(region, keys[0]);
  facts.insert(region, keys[0]);
  assert.equal(facts.member(region, keys[0]), true);
  assert.equal(facts.size(region), undefined);

  const branch = facts.clone();
  branch.reset(region);
  branch.insert(region, keys[1]);
  branch.insert(region, keys[1]);
  assert.equal(branch.size(region), 1);
  branch.remove(region, keys[1]);
  branch.remove(region, keys[1]);
  assert.equal(branch.size(region), 0);
  assert.equal(branch.member(region, undefined), false);
  assert.equal(facts.member(region, keys[0]), true);
  assert.notDeepEqual(branch.snapshot(), facts.snapshot());
});

test("unknown key operations preserve only one-sided membership facts", () => {
  const region = collection("table");
  const facts = new CollectionFacts();
  facts.reset(region);
  facts.insert(region, keys[0]);
  facts.insert(region, undefined);
  assert.equal(facts.member(region, keys[0]), true);
  assert.equal(facts.member(region, keys[1]), undefined);
  assert.equal(facts.size(region), undefined);
  facts.remove(region, keys[0]);
  assert.equal(facts.member(region, keys[0]), false);
  facts.remove(region, undefined);
  assert.equal(facts.member(region, keys[0]), false);
});

test("member assumptions refine concrete possibilities without mutation cardinality", () => {
  const region = collection("table");
  const initial = Array.from({ length: 1 << keys.length }, (_, bits) => new Set(keys.filter((_, index) => bits & 1 << index)));
  for (const present of [false, true]) {
    const facts = new CollectionFacts();
    const possible = initial.filter(state => state.has(keys[0]) === present);
    assert.equal(facts.assumeMember(region, keys[0], present), true);
    assert.equal(facts.member(region, keys[0]), present);
    assert.equal(facts.size(region), undefined);
    assertSound(facts, region, possible, `assume ${present}`);
    assert.equal(facts.assumeMember(region, keys[0], !present), false);
    assert.equal(facts.member(region, keys[0]), present);
  }

  const facts = new CollectionFacts();
  facts.reset(region);
  assert.equal(facts.assumeMember(region, undefined, true), false);
  assert.equal(facts.assumeMember(region, undefined, false), true);
  facts.insert(region, keys[0]);
  assert.equal(facts.assumeMember(region, undefined, true), true);
  assert.equal(facts.member(region, undefined), undefined);
  assert.equal(facts.size(region), 1);
});

test("empty assumptions reject contradictions and retain non-mutating refinements", () => {
  const region = collection("table");
  const facts = new CollectionFacts();
  assert.equal(facts.isEmpty(region), undefined);
  assert.equal(facts.assumeEmpty(region, false), true);
  assert.equal(facts.isEmpty(region), undefined);
  assert.equal(facts.assumeEmpty(region, true), true);
  assert.equal(facts.isEmpty(region), true);
  assert.equal(facts.size(region), 0);
  assert.equal(facts.assumeEmpty(region, false), false);
  assert.equal(facts.assumeMember(region, keys[0], true), false);

  const nonempty = new CollectionFacts();
  assert.equal(nonempty.assumeMember(region, keys[0], true), true);
  assert.equal(nonempty.isEmpty(region), false);
  assert.equal(nonempty.assumeEmpty(region, true), false);
  assert.equal(nonempty.assumeEmpty(region, false), true);
  assert.equal(nonempty.size(region), undefined);
});

test("wildcard and unknown-key assumptions do not manufacture per-region facts", () => {
  const first = collection("table", ["key:integer:1"]);
  const wildcard = collection("table", ["key:*"]);
  const facts = new CollectionFacts();
  facts.reset(first);
  assert.equal(facts.assumeMember(wildcard, keys[0], true), true);
  assert.equal(facts.assumeEmpty(wildcard, true), true);
  assert.equal(facts.isEmpty(wildcard), undefined);
  assert.equal(facts.isEmpty(first), true);

  const unknown = new CollectionFacts();
  assert.equal(unknown.assumeMember(first, undefined, true), true);
  assert.equal(unknown.isEmpty(first), undefined);
  assert.equal(unknown.member(first, keys[0]), undefined);
  assert.deepEqual(unknown.snapshot().collections, []);
});

test("entry replacement and wildcard invalidation retain ancestors and unrelated regions", () => {
  const table = collection("table");
  const first = collection("table", ["key:integer:1"]);
  const firstNested = collection("table", ["key:integer:1", "key:integer:2"]);
  const second = collection("table", ["key:integer:2"]);
  const other = collection("other");
  const facts = new CollectionFacts();
  for (const region of [table, first, firstNested, second, other]) facts.reset(region);
  facts.insert(table, "integer:1");
  facts.insert(first, "integer:2");
  facts.insert(firstNested, keys[0]);
  facts.insert(second, keys[0]);
  facts.insert(other, keys[0]);

  facts.insert(table, "integer:1");
  assert.equal(facts.member(table, "integer:1"), true);
  assert.equal(facts.size(first), undefined);
  assert.equal(facts.size(firstNested), undefined);
  assert.equal(facts.member(second, keys[0]), true);
  assert.equal(facts.member(other, keys[0]), true);

  facts.reset(first);
  facts.insert(firstNested, keys[0]);
  facts.invalidateWrite(collection("table", ["key:*"]));
  assert.equal(facts.member(table, "integer:1"), true);
  assert.equal(facts.size(first), undefined);
  assert.equal(facts.size(firstNested), undefined);
  assert.equal(facts.size(second), undefined);
  assert.equal(facts.member(other, keys[0]), true);
});

test("wildcard receivers weaken existing matches without creating universal facts", () => {
  const first = collection("table", ["key:integer:1"]);
  const second = collection("table", ["key:integer:2"]);
  const wildcard = collection("table", ["key:*"]);
  const facts = new CollectionFacts();
  facts.reset(first);
  facts.reset(second);
  facts.insert(first, keys[0]);
  facts.insert(wildcard, keys[1]);
  assert.equal(facts.member(first, keys[0]), true);
  assert.equal(facts.member(first, keys[1]), undefined);
  assert.equal(facts.member(second, keys[1]), undefined);
  assert.equal(facts.member(wildcard, keys[1]), undefined);
  assert.equal(facts.size(wildcard), undefined);
});

test("container and key budgets exhaust deterministically without stale facts", () => {
  const first = collection("first");
  const second = collection("second");
  const containers = new CollectionFacts(1);
  containers.reset(first);
  containers.reset(second);
  assert.equal(containers.exhausted, true);
  assert.equal(containers.size(first), 0);
  assert.equal(containers.size(second), undefined);

  const keysBudget = new CollectionFacts(1);
  keysBudget.reset(first);
  keysBudget.insert(first, keys[0]);
  assert.equal(keysBudget.size(first), 1);
  keysBudget.insert(first, keys[1]);
  assert.equal(keysBudget.exhausted, true);
  assert.equal(keysBudget.member(first, keys[0]), undefined);
  assert.equal(keysBudget.member(first, keys[1]), undefined);
  assert.equal(keysBudget.size(first), undefined);
  assert.deepEqual(keysBudget.clone().snapshot(), keysBudget.snapshot());

  const assumptionBudget = new CollectionFacts(1);
  assert.equal(assumptionBudget.assumeMember(first, keys[0], false), true);
  assert.equal(assumptionBudget.assumeMember(first, keys[1], false), true);
  assert.equal(assumptionBudget.exhausted, true);
  assert.equal(assumptionBudget.member(first, keys[0]), undefined);
  assert.equal(assumptionBudget.member(first, keys[1]), undefined);

  const noBudget = new CollectionFacts(0);
  assert.equal(noBudget.assumeEmpty(first, true), true);
  assert.equal(noBudget.exhausted, true);
  assert.equal(noBudget.isEmpty(first), undefined);
});

test("snapshots are stable, sorted, detached, and preserve exhaustion", () => {
  const facts = new CollectionFacts(4);
  facts.reset(collection("z"));
  facts.reset(collection("a"));
  facts.insert(collection("a"), "integer:2");
  facts.insert(collection("a"), "integer:1");
  const snapshot = facts.snapshot();
  assert.deepEqual(snapshot.collections.map(entry => entry.region.root), ["a", "z"]);
  assert.deepEqual(snapshot.collections[0].members.map(entry => entry.key), ["integer:1", "integer:2"]);
  snapshot.collections[0].region.path.push("field:changed");
  assert.deepEqual(facts.snapshot().collections[0].region.path, []);
  assert.equal(facts.exhausted, false);
});
