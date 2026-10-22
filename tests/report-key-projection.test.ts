import assert from "node:assert/strict";
import test from "node:test";
import { Program } from "../src/index.js";
import { ReportIdentityKeys } from "../src/reporting/identity-keys.js";
import { withFiles } from "./helpers.js";
import { resolve } from "node:path";

// Constructor inventory: dataflow/index.ts (hash/collection/Merkle),
// natives.ts, immutable-key.ts and hash-recipes.ts. These are owned engine
// tokens, as distinct from the constant/field payloads checked below.
test("report key projection covers every opaque engine family and owned wrapper", () => {
  withFiles({ "main.compact": "export circuit entry(value:Field):Field{return value;}" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const create = (scan = program) => new ReportIdentityKeys(scan, scan.entries[0], scan.rootSource.ast.span);
    const families = ["native", "hash-derived", "collection-derived", "merkle-digest", "collection-query",
      "hash-choice", "hash-relation", "expression", "aggregate"];
    const runs = ["a", "b"].map(digit => {
      const scan = new Program(resolve(directory, "main.compact")), report = create(scan);
      return families.flatMap(family => {
        const raw = family + ":" + digit.repeat(64);
        // The constructor retains a canonical companion beside each raw digest.
        scan.meteringIdentity.rememberReport(raw, family + ":" + "c".repeat(64));
        return [raw, "id:" + raw, "id:" + raw + "::byte:7", "key:identity:" + raw,
          JSON.stringify([program.entries[0], ["id:" + raw]]),
          "ledger:" + JSON.stringify([program.entries[0], ["key:identity:" + raw]]) + ":2:size"]
          .map(key => report.key(key));
      });
    });
    assert.deepEqual(runs[1], runs[0]);
    const report = create(), raw = "collection-derived:" + "a".repeat(64);
    for (const key of ["constant:string:" + raw, "field:" + raw, "key:" + raw,
      JSON.stringify(["constant", "string", raw]),
      JSON.stringify(["Field", "constant", "string", raw]),
      JSON.stringify({ kind: "string", value: raw }), 'Opaque<"' + raw + '">'])
      assert.equal(report.key(key), key, "source-owned payload must remain literal");
    assert.equal(report.key(program.entries[0]), program.entries[0], "visible compiler paths stay physical");
    assert.notEqual(report.key(raw), report.key("collection-derived:" + "b".repeat(64)), "distinct raw keys stay distinct");
    assert.equal(report.key(raw), report.key(raw));
    assert.deepEqual(report.region(["key:identity:" + raw, "field:" + raw, "key:" + raw]),
      ["key:identity:" + report.key(raw), "field:" + raw, "key:" + raw]);
  });
});
