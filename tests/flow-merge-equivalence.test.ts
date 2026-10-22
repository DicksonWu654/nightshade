import assert from "node:assert/strict";
import test from "node:test";
import { combine, controlled, ControlDependencies } from "../src/dataflow/transfers.js";
import type { AbstractValue, Flow, PrivateSource } from "../src/dataflow/index.js";

const location = { file: "flow-merge.compact", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
const source = (id: string, name = id): PrivateSource => ({ id, name, kind: "witness", location });
const flow = (id: string, form: Flow["form"], label = id): Flow => ({ source: source(id), form, trace: [{ kind: "input", label, location }] });
const value = (extra: Partial<AbstractValue> = {}): AbstractValue => ({ flows: [], ledger: new Set(), ...extra });

test("combine is a stable flow merge with complete dependency metadata", () => {
  const firstCommit = { location, primitive: "persistentHash", input: value(), randomness: value() };
  const secondCommit = { location, primitive: "persistentCommit", input: value(), randomness: value() };
  const origins = [{ primitive: "transientHash" as const, location }, { primitive: "transientCommit" as const, location: { ...location, start: 1, end: 2 } }];
  const left = value({
    // The same source id appears in two forms, interleaved with another
    // source. A form-partitioned implementation must still preserve this
    // single global first-seen order.
    flows: [flow("a", "raw"), flow("b", "derived"), flow("a", "hash")], ledger: new Set(["left", "shared"]), commitments: [firstCommit],
    transientOrigins: [origins[0]], proofLedgerEpoch: 2, eitherPayloads: ["payload-a"],
  });
  // Same source id/form as the first flow, but a distinct source object. The
  // replacement must retain the first key's position while taking this trace.
  const replacement = { ...flow("a", "raw", "replacement"), source: source("a", "different-instance") };
  const right = value({
    flows: [replacement, flow("c", "hash")], ledger: new Set(["right", "shared"]), commitments: [firstCommit, secondCommit],
    transientOrigins: origins, proofLedgerEpoch: 7, eitherPayloads: ["payload-a", "payload-b"], eitherLogicalGate: true,
    predicateHasAlternatives: true, predicateStructureLost: true,
  });
  const leftBefore = structuredClone(left), rightBefore = structuredClone(right);
  const merged = combine([left, right]);
  assert.deepEqual(merged.flows.map(item => [item.source.id, item.form]), [["a", "raw"], ["b", "derived"], ["a", "hash"], ["c", "hash"]]);
  assert.equal(merged.flows[0].source.name, "different-instance");
  assert.deepEqual(merged.flows[0].trace, replacement.trace);
  assert.deepEqual([...merged.ledger], ["left", "shared", "right"]);
  assert.deepEqual(merged.commitments, [firstCommit, secondCommit]);
  assert.equal(merged.proofLedgerEpoch, 7);
  assert.deepEqual(merged.transientOrigins, origins);
  assert.deepEqual(merged.eitherPayloads, ["payload-a", "payload-b"]);
  assert.equal(merged.eitherLogicalGate, true);
  assert.equal(merged.predicateHasAlternatives, true);
  assert.equal(merged.predicateStructureLost, true);
  assert.deepEqual(left, leftBefore);
  assert.deepEqual(right, rightBefore);
});

test("controlled applies implicit flow recursively while retaining snapshots and metadata", () => {
  const control = value({ flows: [flow("guard", "raw", "guard")], ledger: new Set(["guard-ledger"]), proofLedgerEpoch: 4,
    eitherPayloads: ["guard-payload"], transientOriginsUnavailable: true });
  const leaf = value({ flows: [flow("secret", "raw", "secret")], ledger: new Set(["secret-ledger"]), proofLedgerEpoch: 1,
    eitherPayloads: ["secret-payload"], eitherControls: [{ branches: ["left"], payloads: ["secret-payload"] }],
    transientOrigins: [{ primitive: "transientHash", location }], });
  const input = value({ flows: [flow("root", "raw", "root")], ledger: new Set(["root-ledger"]), commitments: [],
    fields: { nested: leaf }, items: [leaf], proofLedgerEpoch: 1, eitherPayloads: ["root-payload"] });
  const result = controlled(input, [control], location);
  assert.notEqual(result, input);
  const implicit = (candidate: AbstractValue | undefined): Flow => {
    assert.ok(candidate);
    const found = candidate.flows.find(item => item.source.id === "guard");
    assert.ok(found);
    return found;
  };
  assert.equal(implicit(result).form, "derived");
  assert.equal(implicit(result).trace.at(-1)?.kind, "implicit-flow");
  assert.equal(implicit(result.fields?.nested).trace.at(-1)?.label, "private-dependent control flow");
  assert.equal(implicit(result.items?.[0]).trace.at(-1)?.kind, "implicit-flow");
  assert.deepEqual([...result.ledger], ["root-ledger"]);
  assert.equal(result.proofLedgerEpoch, 4);
  assert.deepEqual(result.eitherPayloads, ["root-payload", "guard-payload"]);
  assert.deepEqual(result.fields?.nested.eitherControls, [{ branches: ["left"], payloads: ["secret-payload"] }]);
  assert.equal(result.transientOriginsUnavailable, undefined, "control transient metadata is not copied into the current value's snapshot");
  assert.deepEqual(input.commitments, result.commitments);
});

test("controlled preserves zero-iteration behavior and force expands empty aggregates", () => {
  const empty = value({ flows: [flow("x", "raw")], items: [] });
  const control = value({ flows: [flow("guard", "raw")] });
  assert.equal(controlled(empty, [control], location), empty);
  const forced = controlled(empty, [control], location, true);
  assert.notEqual(forced, empty);
  assert.deepEqual(forced.items, []);
  assert.equal(forced.flows.find(item => item.source.id === "guard")?.trace.at(-1)?.kind, "implicit-flow");
  assert.equal(controlled(empty, [], location), empty);
});

test("control union reuse validates sibling prefixes and retains each transfer's trace location", () => {
  const cache = new ControlDependencies();
  const a = value({ flows: [flow("a", "raw")] }), b = value({ flows: [flow("b", "hash")] });
  const tail = value({ flows: [flow("tail", "derived")], proofLedgerEpoch: 7, eitherPayloads: ["tail"] });
  const input = value({ fields: { field: value({ flows: [flow("input", "raw")] }) } });
  const before = structuredClone([a, b, tail, input]);
  for (const controls of [[a, tail], [a, tail], [b, tail], [tail], [a, b, tail], [a, tail], []]) {
    for (const site of [location, { ...location, start: 1, end: 2 }]) {
      assert.deepEqual(controlled(input, controls, site, false, cache), controlled(input, controls, site));
    }
  }
  assert.deepEqual([a, b, tail, input], before);
});
