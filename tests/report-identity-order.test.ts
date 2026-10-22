import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, detectors } from "../src/index.js";
import { withFiles } from "./helpers.js";

const cases = [
  { name: "Map-debit", rule: "zero-amount-unguarded-map-debit-review",
    header: "import CompactStandardLibrary;export ledger balances:Map<Bytes<32>,Uint<64>>;",
    parameters: "domain:Bytes<32>,amount:Uint<64>",
    body: "const key=persistentHash<Bytes<32>>(domain);if(disclose(amount)==0 as Uint<64>){const prior=balances.lookup(disclose(key));balances.insert(disclose(key),disclose((prior-amount)as Uint<64>));}" },
  { name: "List", rule: "zero-transfer-retained-list-review",
    header: "import CompactStandardLibrary;export ledger records:Map<Bytes<32>,List<Bytes<32>>>;",
    parameters: "recipient:Bytes<32>,color:Bytes<32>,amount:Uint<128>,memo:Bytes<32>",
    body: "const dest=persistentHash<Bytes<32>>(recipient);sendUnshielded(disclose(color),disclose(amount),right<ContractAddress,UserAddress>(UserAddress{bytes:disclose(dest)}));records.lookup(disclose(dest)).pushFront(disclose(memo));" },
];
for (const specimen of cases) test(`${specimen.name} report identities and fingerprints ignore Program previews, entry order and subsets`, () => {
  const source = specimen.header + ["first", "second"].map(name => `export circuit ${name}(${specimen.parameters}):[]{${specimen.body}}`).join("\n");
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), rule = detectors.find(rule => rule.id === specimen.rule)!;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
      const one = (program: Program, entry: string) => {
        const flow = new Dataflow(program, 40000, 256, 50000, engine, cached, cached);
        const facts = specimen.name === "List" ? flow.analyzeZeroTransferListEntry(entry)
          : flow.analyzeZeroMapDebitEntry(entry, entry + "::parameter:amount");
        assert.deepEqual(facts.diagnostics, []);
        const findings = rule.run(facts);
        assert.deepEqual(facts.diagnostics, []);
        assert.equal(findings.length, 1);
        return findings[0];
      };
      const all = (program: Program, order = program.entries) => order.map(entry => one(program, entry))
        .sort((a, b) => a.location.start - b.location.start);
      const fresh = new Program(file), baseline = all(fresh);
      assert.deepEqual(all(fresh), baseline);
      const reused = new Program(file);
      assert.deepEqual(one(reused, reused.entries[1]), baseline[1], "reporting a subset must reproduce its complete finding");
      assert.deepEqual(all(reused), baseline, "previewing second must not change subsequent tokens or fingerprints");
      const reverse = new Program(file);
      assert.deepEqual(all(reverse, [...reverse.entries].reverse()), baseline, "reverse traversal must reproduce every finding field");
      for (const index of [0, 1]) {
        const subset = new Program(file);
        assert.deepEqual(one(subset, subset.entries[index]), baseline[index]);
      }
    }
  });
});
