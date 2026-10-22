import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { lowEntropyHashDisclosure, detectSmallDomainHash } from "../src/detectors/small-domain-hash.js";
import { eitherPayloadMismatch, detectEitherPayloads } from "../src/detectors/either-payload.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

// Exact rule observations may use the composed native scalar comparison only while
// no rule evidence, relation or storage location can observe its elided partitions.
const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const bytesOf = (value: bigint) => `[${Array.from({ length: 32 }, (_, index) => `${value >> BigInt(8 * index) & 255n} as Uint<8>`).join(",")}]`;
const header = `import CompactStandardLibrary;
export ledger digest: Bytes<32>;
export ledger stored: Field;
export ledger seen: Set<Uint<8>>;
pure circuit compareByte(acc: Boolean, left: Uint<8>, right: Uint<8>): Boolean {
  return left == right ? acc : left < right;
}
pure circuit low(value: Secp256k1Scalar): Boolean {
  const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
  return fold(compareByte, true, bytes, ${bytesOf(order / 2n)});
}
`;
type Mode = "digest" | "either";
const modes = {
  digest: { rule: lowEntropyHashDisclosure, detect: detectSmallDomainHash, flags: [false, true, false], scope: "witness" as const },
  either: { rule: eitherPayloadMismatch, detect: detectEitherPayloads, flags: [true, false, false], scope: "all" as const },
};

function withProgram(source: string, check: (program: Program, file: string) => void): void {
  withFiles({ "main.compact": header + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 3);
      assert.equal(result.valid, true, result.error);
    }
    check(new Program(file, [], directory, undefined, 3), file);
  });
}
function observe(program: Program, mode: Mode, engine: "instructions" | "expressions", cached: boolean): AnalysisFacts {
  const { flags, scope } = modes[mode];
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, scope, false, false, false, true, false, ...flags).analyze();
}

test("exact digest/Either observations compose independent low-s checks and keep unrelated findings", () => {
  withProgram(`export circuit vote(first: Secp256k1Scalar, second: Secp256k1Scalar, choice: Boolean): [] {
  assert(low(first) && low(second), "low-s");
  digest = disclose(persistentHash<Boolean>(choice));
}
export circuit pick(signature: Secp256k1Scalar, value: Either<Field, Field>): [] {
  assert(low(signature), "low-s");
  assert(value.is_left, "left");
  stored = disclose(value.right);
}`, (program, file) => {
    for (const mode of ["digest", "either"] as const) {
      let expected: string | undefined;
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        const facts = observe(program, mode, engine, cached);
        assert.deepEqual(facts.diagnostics, [], `${mode} ${engine} ${cached}`);
        assert.deepEqual(facts.completedEntries, program.entries);
        // One composed predicate per scalar, not 33 byte suffix cases per fold.
        assert.ok(facts.paths.every(path => path.path.some(step => step.label === "total little-endian comparison fold")));
        const findings = modes[mode].detect(facts);
        assert.deepEqual(findings.map(finding => finding.metadata.entry), [mode === "digest" ? "vote" : "pick"]);
        const observed = JSON.stringify(findings.map(finding => [finding.fingerprint, finding.message, finding.location]));
        expected ??= observed;
        assert.equal(observed, expected);
      }
      const scan = scanFile(file, { detectors: [modes[mode].rule.id], zkirVersion: 3 });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.equal(scan.findings.length, 1);
    }
  });
});

for (const [name, mode, before, after] of [
  ["published byte view", "digest", "", `digest = disclose(persistentHash<Vector<32, Uint<8>>>(bytes));`],
  ["arithmetic byte view", "digest", "", `digest = disclose(persistentHash<Uint<8>>((bytes[31]+1) as Uint<8>));`],
  ["published relation to a byte", "digest", "", `assert(small == bytes[31], "linked"); digest = disclose(persistentHash<Uint<8>>(small));`],
  ["earlier relation to a byte", "digest", `assert(small == bytes[31], "linked");`, `digest = disclose(persistentHash<Uint<8>>(small));`],
  ["storage key from a byte", "digest", "", `seen.insert(disclose(bytes[0])); digest = disclose(persistentHash<Uint<8>>(small));`],
  ["Either tag related to a byte", "either", "", `assert(value.is_left == (bytes[31] == 127), "linked"); stored = disclose(value.right);`],
] as const) test(`dependent ${name} leaves the exact rule observation incomplete`, () => {
  withProgram(`export circuit entry(signature: Secp256k1Scalar, small: Uint<8>, value: Either<Field, Field>): [] {
  const bytes = (signature as Bytes<32>) as Vector<32, Uint<8>>;
  ${before}
  assert(low(signature), "low-s");
  ${after}
}`, (program, file) => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observe(program, mode, engine, cached);
      // Either the compressed fold is declined (ordinary budgets) or its
      // dependency is reported; neither is a complete rule result.
      assert.ok(facts.diagnostics.some(issue => issue.code === "observation-compression-dependency" || issue.code === "analysis-budget"), JSON.stringify(facts.diagnostics));
      if (!before) assert.ok(facts.diagnostics.some(issue => issue.code === "observation-compression-dependency"), JSON.stringify(facts.diagnostics));
      assert.deepEqual(facts.completedEntries, []);
    }
    const scan = scanFile(file, { detectors: [modes[mode].rule.id], zkirVersion: 3 });
    assert.equal(scan.coverage.baselineStatus, "complete");
    const row = scan.coverage.rules!.find(row => row.detectorId === modes[mode].rule.id)!;
    // Published byte views and arithmetic byte views have only derived digest leaves: a conservative
    // absence certificate (no represented raw private leaf) completes the rule
    // without the compressed exact histories. Every other dependency stays incomplete.
    if (["published byte view", "arithmetic byte view"].includes(name)) assert.deepEqual([row.status, row.evidence, scan.status], ["complete", "conservative-absence", "complete"]);
    else assert.deepEqual([row.status, scan.status], ["incomplete", "incomplete"]);
    assert.deepEqual(scan.findings, []);
  });
});

// Digest observation may compress a total hash-order choice only when both arms
// hash the same typed leaves in another order and the selector stays unobserved.
const chain = (sink: string) => `import CompactStandardLibrary;
export ledger digest: Bytes<32>;
export ledger root: Bytes<32>;
export circuit entry(leaf: Bytes<32>, siblings: Vector<3, Bytes<32>>, bits: Vector<3, Boolean>, choice: Boolean, other: Boolean): [] {
  const d = disclose(siblings);
  const b = disclose(bits);
  const h0 = persistentHash<Vector<1, Bytes<32>>>([disclose(leaf)]);
  const h1 = b[0] ? persistentHash<Vector<2, Bytes<32>>>([d[0], h0]) : persistentHash<Vector<2, Bytes<32>>>([h0, d[0]]);
  const h2 = b[1] ? persistentHash<Vector<2, Bytes<32>>>([d[1], h1]) : persistentHash<Vector<2, Bytes<32>>>([h1, d[1]]);
  const h3 = b[2] ? persistentHash<Vector<2, Bytes<32>>>([d[2], h2]) : persistentHash<Vector<2, Bytes<32>>>([h2, d[2]]);
  root = h3;
  ${sink}
}`;
function digestFacts(program: Program, choices: boolean, engine: "instructions" | "expressions" = "instructions", cached = true): AnalysisFacts {
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "witness", false, false, false, choices, false, false, true).analyze();
}
function withDigestProgram(source: string, check: (program: Program, file: string) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    check(new Program(file), file);
  });
}
const findingKeys = (facts: AnalysisFacts) => JSON.stringify(detectSmallDomainHash(facts).map(finding => [finding.fingerprint, finding.message, finding.location, finding.metadata]).sort());

for (const [name, sink, compressed] of [
  ["permuted Merkle arms", "digest = disclose(persistentHash<Boolean>(choice));", true],
  ["distinct hash arms", "digest = disclose(disclose(other) ? persistentHash<Boolean>(choice) : persistentHash<Boolean>(other));", false],
] as const) test(`digest hash choices agree with ordinary histories: ${name}`, () => {
  withDigestProgram(chain(sink), (program, file) => {
    const oracle = digestFacts(program, false, "expressions", false);
    assert.deepEqual(oracle.diagnostics, []);
    assert.ok(oracle.paths.length >= 8);
    const expected = findingKeys(oracle);
    assert.notEqual(expected, "[]");
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = digestFacts(program, true, engine, cached);
      assert.deepEqual(facts.diagnostics, []);
      // The Merkle arms are permutations; the distinct choice keeps both histories.
      assert.equal(facts.paths.length, compressed ? 1 : 2);
      assert.equal(findingKeys(facts), expected);
    }
    const scan = scanFile(file, { detectors: [lowEntropyHashDisclosure.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
  });
});

test("a published digest of a compressed hash selector leaves the digest observation incomplete", () => {
  // Each ordinary history knows the selector, so its own digest is constant there.
  withDigestProgram(chain("digest = disclose(persistentHash<Boolean>(b[0]));"), (program, file) => {
    const oracle = digestFacts(program, false, "expressions", false);
    assert.deepEqual(oracle.diagnostics, []);
    assert.equal(findingKeys(oracle), "[]");
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = digestFacts(program, true, engine, cached);
      assert.ok(facts.diagnostics.some(issue => issue.code === "observation-compression-dependency"), JSON.stringify(facts.diagnostics));
      assert.deepEqual(facts.completedEntries, []);
    }
    const scan = scanFile(file, { detectors: [lowEntropyHashDisclosure.id] });
    assert.equal(scan.status, "incomplete");
    assert.equal(scan.coverage.baselineStatus, "complete");
    assert.deepEqual(scan.findings, []);
  });
});

// Quantity envelopes are a separate observer contract. Snapshot-safe compression
// does not establish preservation of numeric evidence.
test("snapshot scalar compression does not admit mint quantity observation", () => {
  withProgram(`export circuit guarded(signature: Secp256k1Scalar): [] {
    assert(low(signature), "low-s");
    kernel.mintUnshielded(default<Bytes<32>>, 1);
  }
  export circuit independent(): [] { kernel.mintUnshielded(default<Bytes<32>>, 1); }`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = (quantities: boolean) => new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, true, "all", false, false, false, true, false, false, false, false, true, quantities).analyze();
      const snapshots = facts(false);
      assert.deepEqual(snapshots.diagnostics, []);
      assert.deepEqual(snapshots.completedEntries, program.entries);
      assert.ok(snapshots.paths.some(path => path.path.some(step => step.label === "total little-endian comparison fold")));
      const quantities = facts(true);
      assert.ok(quantities.diagnostics.some(issue => issue.code === "analysis-budget"), JSON.stringify(quantities.diagnostics));
      assert.deepEqual(quantities.completedEntries.map(entry => program.symbols.get(entry)!.name), ["independent"]);
      assert.ok(quantities.paths.every(path => path.path.every(step => step.label !== "total little-endian comparison fold")));
    }
  });
});

for (const before of [false, true]) test(`hidden selector arithmetic retains the ordinary oracle or fails closed (${before ? "before" : "after"} compression)`, () => {
  withDigestProgram(`import CompactStandardLibrary;
export ledger root: Bytes<32>; export ledger digest: Bytes<32>;
export circuit entry(flag: Boolean, a: Bytes<32>, b: Bytes<32>, secret: Uint<8>): [] {
  ${before ? "const derived=((flag as Uint<8>)+1) as Uint<8>;" : ""}
  const chosen=flag ? persistentHash<Vector<2,Bytes<32>>>([a,b]) : persistentHash<Vector<2,Bytes<32>>>([b,a]);
  root=disclose(chosen);
  ${before ? "" : "const derived=((flag as Uint<8>)+1) as Uint<8>;"}
  assert(secret==derived,"fixed by flag");
  digest=disclose(persistentHash<Uint<8>>(secret));
}`, (program, file) => {
    const oracle = digestFacts(program, false, "expressions", false);
    assert.deepEqual(oracle.diagnostics, []);
    assert.equal(oracle.paths.length, 2);
    assert.equal(detectSmallDomainHash(oracle).length, before ? 1 : 0);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false,true]) {
      const facts=digestFacts(program,true,engine,cached);
      if (facts.diagnostics.length) {
        assert.ok(facts.diagnostics.some(issue=>issue.code==="observation-compression-dependency"));
        assert.deepEqual(facts.completedEntries, []);
      } else {
        assert.deepEqual(facts.completedEntries, program.entries);
        assert.equal(findingKeys(facts), findingKeys(oracle));
      }
    }
    const scan=scanFile(file,{detectors:[lowEntropyHashDisclosure.id]});
    assert.equal(scan.findings.length, before ? detectSmallDomainHash(oracle).length : 0);
    assert.equal(scan.coverage.baselineStatus,"complete");
    assert.equal(scan.status,before ? "complete" : "incomplete");
  });
});

test("mint snapshots cannot hide an arithmetic compressed-byte nonce", () => {
  withProgram(`export circuit entry(signature: Secp256k1Scalar): [] {
    const bytes=(signature as Bytes<32>) as Vector<32,Uint<8>>;
    assert(low(signature),"low-s");
    const nonce=persistentHash<Uint<8>>((bytes[31]+1) as Uint<8>);
    mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),shieldedBurnAddress());
  }`, (program,file) => {
    for (const engine of ["instructions","expressions"] as const) for (const cached of [false,true]) {
      const facts=new Dataflow(program,40000,256,50000,engine,cached,cached,"equivalent-states",false,true,"all",false,false,false,true,false,false,false,false,true).analyze();
      assert.deepEqual(facts.completedEntries, []);
      assert.ok(facts.diagnostics.some(issue=>issue.code==="observation-compression-dependency"),JSON.stringify(facts.diagnostics));
    }
    const scan=scanFile(file,{detectors:["duplicate-shielded-mint"],zkirVersion:3});
    assert.equal(scan.status,"incomplete");
    assert.equal(scan.coverage.baselineStatus,"complete");
    assert.deepEqual(scan.findings, []);
  });
});


for (const field of ["source", "flows", "callPath"]) test(`user field ${field} retains its compressed identity boundary`, () => {
  withDigestProgram(`import CompactStandardLibrary;
struct Envelope { ${field}: Boolean; }
export ledger root: Bytes<32>; export ledger digest: Bytes<32>;
export circuit entry(flag: Boolean, a: Bytes<32>, b: Bytes<32>): [] {
  const h=flag ? persistentHash<Vector<2,Bytes<32>>>([a,b]) : persistentHash<Vector<2,Bytes<32>>>([b,a]);
  root=disclose(h);
  digest=disclose(persistentHash<Envelope>(Envelope{${field}:flag}));
}`, (program,file) => {
    const oracle=digestFacts(program,false,"expressions",false);
    assert.deepEqual(oracle.diagnostics,[]);
    assert.equal(oracle.paths.length,2);
    assert.deepEqual(detectSmallDomainHash(oracle),[]);
    for(const engine of ["instructions","expressions"] as const) for(const cached of [false,true]) {
      const facts=digestFacts(program,true,engine,cached);
      assert.deepEqual(facts.completedEntries,[]);
      assert.ok(facts.diagnostics.some(issue=>issue.code==="observation-compression-dependency"),JSON.stringify(facts.diagnostics));
    }
    const scan=scanFile(file,{detectors:[lowEntropyHashDisclosure.id]});
    assert.equal(scan.status,"incomplete");
    assert.equal(scan.coverage.baselineStatus,"complete");
    assert.deepEqual(scan.findings,[]);
  });
});
