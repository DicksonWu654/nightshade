import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts, type AbstractValue } from "../src/index.js";
import { ledgerPreimage } from "../src/detectors/index.js";
import { inconsistentAccessControl } from "../src/detectors/access-control.js";
import { spoofableAuthorization } from "../src/detectors/authorization.js";
import { directPreimageSource } from "../src/dataflow/transfers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function qualify(file: string, inspect: (facts: AnalysisFacts) => void): void {
  if (process.env.COMPACTC_TEST) {
    const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(result.valid, true, result.error);
  }
  const program = new Program(file);
  let baseline: string[] | undefined;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all").analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
    inspect(facts);
    const paths = semanticPaths(facts); baseline ??= paths; assert.deepEqual(paths, baseline, `${engine}/${cached}`);
  }
}

const header = `import CompactStandardLibrary;
export ledger owner: Bytes<32>;
export ledger context: Field;
export ledger published: Field;
export ledger sequence: Counter;
witness secret(): Field;
circuit digest(key: Field): Bytes<32> {
  return persistentHash<[Field, Field, Field]>([17 as Field, context + 1, key]);
}
`;

test("public arithmetic context preserves one exact private preimage through repeated helper calls", () => {
  withFiles({ "main.compact": `${header}
export circuit publish(): [] {
  const key = secret(); const before = digest(key);
  assert(before == digest(key), "same input");
  assert(before == owner, "owner"); published = disclose(key);
}
export circuit corrected(): [] {
  const key = secret(); assert(digest(key) == owner, "owner");
  published = 0 as Field;
}
export circuit differentInvocation(): [] {
  assert(digest(secret()) == owner, "owner"); published = disclose(secret());
}` }, directory => qualify(resolve(directory, "main.compact"), facts => {
    const hits = ledgerPreimage.run(facts);
    assert.deepEqual(hits.map(hit => hit.callPath[0]), ["publish"]);
    for (const path of facts.paths) assert.equal(path.bindings.length, 1);
  }));
});

test("additional private context, transformed keys and may-alias reads cannot invent a complete preimage", () => {
  withFiles({ "main.compact": `${header}
ledger candidates: Map<Field, Field>;
export circuit secondPrivate(): [] {
  const key = secret(); const nonce = secret();
  assert(persistentHash<[Field,Field]>([nonce, key]) == owner, "two secrets");
  published = disclose(key);
}
export circuit transformed(): [] {
  const key = secret(); assert(digest(key + 1) == owner, "derived preimage"); published = disclose(key);
}
export circuit privateSelection(flag: Boolean): [] {
  const key = secret(); const salt = disclose(flag) ? context : context + 1;
  assert(persistentHash<[Field,Field]>([salt, key]) == owner, "private control"); published = disclose(key);
}
export circuit alias(index: Field): [] {
  const key = secret(); candidates.insert(0 as Field, disclose(key));
  candidates.insert(1 as Field, 9 as Field);
  assert(digest(candidates.lookup(disclose(index))) == owner, "may alias"); published = disclose(key);
}` }, directory => qualify(resolve(directory, "main.compact"), facts => {
    assert.deepEqual(ledgerPreimage.run(facts), []);
  }));
});

test("public-context preimage guards keep stored snapshots and do not trust self-written digests", () => {
  withFiles({ "main.compact": `${header}
export circuit savedContext(): [] {
  const key = secret(); const before = digest(key); context = 42 as Field;
  assert(before == owner, "original context"); published = disclose(key);
}
export circuit selfWritten(): [] {
  const key = secret(); owner = disclose(digest(key));
  assert(digest(key) == owner, "self written"); published = disclose(key);
}
export circuit changedContext(): [] {
  const key = secret(); const before = digest(key); context = 42 as Field;
  const after = digest(key); owner = disclose(after);
  assert(before == owner, "newly written owner"); published = disclose(key);
}` }, directory => qualify(resolve(directory, "main.compact"), facts => {
    assert.deepEqual(ledgerPreimage.run(facts).map(hit => hit.callPath[0]), ["savedContext"]);
  }));
});

test("real board mutations and their controls agree across instruction/reference and cache modes", () => {
  const seeds = JSON.parse(readFileSync("tests/corpus/known-bugs.json", "utf8")).cases as {
    id: string; file: string; corrected: string; lookalike: string; expectedLines: number[];
  }[];
  for (const id of ["bboard-published-preimage", "bboard-sibling-access"]) {
    const seed = seeds.find(seed => seed.id === id)!;
    const rule = id === "bboard-published-preimage" ? ledgerPreimage : inconsistentAccessControl;
    for (const [path, lines] of [[seed.file, seed.expectedLines], [seed.corrected, []], [seed.lookalike, []]] as const) {
      const file = resolve("tests/corpus", path);
      qualify(file, facts => assert.deepEqual(rule.run(facts).map(hit => hit.location.line), lines));
      const scan = scanFile(file, { detectors: [rule.id] });
      assert.equal(scan.status, "complete"); assert.deepEqual(scan.findings.map(hit => hit.location.line), lines);
    }
  }
});

test("public-context private-preimage corrections suppress witness-only candidates without weakening raw checks", () => {
  withFiles({ "main.compact": `${header}
witness allowed(): Boolean;
export circuit rawOnly(next: Field): [] { assert(allowed(), "raw gate"); published = disclose(next); }
export circuit corrected(next: Field): [] {
  assert(allowed(), "raw gate"); assert(digest(secret()) == owner, "private preimage"); published = disclose(next);
}
export circuit secondPrivate(next: Field): [] {
  assert(allowed(), "raw gate");
  assert(persistentHash<[Field,Field]>([secret(),secret()]) == owner, "outside single-source contract");
  published = disclose(next);
}` }, directory => qualify(resolve(directory, "main.compact"), facts => {
    assert.deepEqual(spoofableAuthorization.run(facts).map(hit => hit.metadata.entry).sort(), ["rawOnly", "secondPrivate"]);
  }));
});

test("public components still consume origin traversal allowance; unknown private identity stays refused", () => {
  const source = { id: "key", kind: "witness" as const, name: "key", location: { file: "owned.compact", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 } };
  const key: AbstractValue = { flows: [{ source, form: "raw", trace: [] }], ledger: new Set(), identity: source.id };
  const context: AbstractValue = { flows: [], ledger: new Set(), type: "Field" };
  const input: AbstractValue = { flows: key.flows, ledger: new Set(), items: [context, key] };
  assert.equal(directPreimageSource(input).source, source);
  assert.deepEqual(directPreimageSource(input, 1), { complete: false, work: 2 });
  assert.equal(directPreimageSource({ ...input, items: [context, { ...key, identity: "may-alias" }] }).source, undefined);
  // Inconsistent aggregate metadata must not turn a hidden private ingredient
  // into public material; traversal checks the represented leaves themselves.
  const other = { ...key, identity: "other", flows: [{ ...key.flows[0], source: { ...source, id: "other" } }] };
  assert.equal(directPreimageSource({ flows: [], ledger: new Set(), items: [key, other] }).source, undefined);
});
