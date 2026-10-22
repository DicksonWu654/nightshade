import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile } from "../src/index.js";
import { nativeKeyAuthenticationReview as rule } from "../src/detectors/native-key.js";
import { spoofableAuthorization } from "../src/detectors/authorization.js";
import { qualifyCounterDetectors } from "../src/analysis/counter-certificates.js";
import { resolvePolicies } from "../src/policies.js";
import { nativeKeyObservations } from "../src/analysis/native-key.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
const header = `import CompactStandardLibrary;
export ledger owner: Bytes<32>;
export ledger credential: Bytes<32>;
export ledger value: Field;
witness secret(): Bytes<32>;
struct Credential { key: Bytes<32>; nonce: Bytes<32>; }
`;
function check(body: string, expected: number, extra = "") {
  withFiles({ "main.compact": (extra ? header.replace("import CompactStandardLibrary;", "import { persistentHash } from CompactStandardLibrary;") : header) + extra + body }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file); let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false, "all", false, false, false, false, false, false, true, false, false, false, undefined, false, true).analyze();
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []); assert.equal(findings.length, expected);
      assert.ok(findings.every(f => f.severity === "info" && f.confidence === "high"));
      oracle ??= findings; assert.deepEqual(findings, oracle, `${engine}/${cached}`);
      const exhausted = nativeKeyObservations(facts, 0); assert.equal(exhausted.observations.length, 0); assert.ok(exhausted.diagnostics.every(d => d.scope?.detectorId === rule.id));
      if (expected) assert.deepEqual(spoofableAuthorization.run(facts), []);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics)); assert.equal(result.findings.length, expected);
    }
  });
}
test("native key with independent mandatory secret proof is an intentional review match", () => {
  check(`export circuit update(): [] { const key = ownPublicKey(); assert(key.bytes == owner, "key"); assert(persistentHash<Bytes<32>>(secret()) == credential, "secret"); value = (1 as Field); }`, 1);
});
test("exact native key plus nonce stored hash credential is a review observation", () => {
  check(`export circuit update(): [] { const key = ownPublicKey(); const claim = Credential { key: key.bytes, nonce: secret() }; assert(persistentHash<Credential>(claim) == credential, "credential"); value = (1 as Field); }`, 1);
});
test("unrelated secret/key predicates and native recipient data stay quiet", () => {
  check(`export circuit update(): [] { assert(persistentHash<Bytes<32>>(secret()) == credential, "secret"); const key = ownPublicKey(); value = (1 as Field); }`, 0);
  check(`export circuit update(): [] { const key = ownPublicKey(); assert(key.bytes != owner, "different"); assert(persistentHash<Bytes<32>>(secret()) == credential, "secret"); value = (1 as Field); }`, 0);
});
test("raw native key equality without mandatory secret proof remains owned by spoofable rule", () => {
  check(`export circuit update(): [] { assert(ownPublicKey().bytes == owner, "key"); value = (1 as Field); }`, 0);
  check(`export circuit update(flag: Boolean): [] { assert(ownPublicKey().bytes == owner, "key"); if (disclose(flag)) { assert(persistentHash<Bytes<32>>(secret()) == credential, "secret"); } value = (1 as Field); }`, 0);
});
test("same-name user witness never supplies canonical native identity", () => {
  check(`export circuit update(): [] { assert(ownPublicKey() == owner, "key"); assert(persistentHash<Bytes<32>>(secret()) == credential, "secret"); value = (1 as Field); }`, 0, "witness ownPublicKey(): Bytes<32>;\n");
});
test("optional credential equality and preview-only comparison stay quiet", () => {
  check(`export circuit update(flag: Boolean): [] { if (disclose(flag)) { assert(ownPublicKey().bytes == owner, "key"); } assert(persistentHash<Bytes<32>>(secret()) == credential, "secret"); value = (1 as Field); }`, 0);
  check(`export circuit preview(): Boolean { return disclose(ownPublicKey().bytes == owner); }`, 0);
});
test("pinned Counter seeded credential triplet compiles and scans 1/0/0 in both API modes", () => {
  for (const [variant, expected] of [["positive", 1], ["corrected", 0], ["lookalike", 0]] as const) {
    const file = resolve(`tests/corpus/known-bugs/counter-native-key-credential-${variant}.compact`);
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics)); assert.equal(result.findings.length, expected);
      if (expected) assert.equal(result.findings[0].location.line, 35);
    }
  }
});

test("canonical commitment snapshots include native key and private randomness", () => {
  check(`export circuit update(): [] { const key = ownPublicKey(); assert(persistentCommit<Bytes<32>>(key.bytes, secret()) == credential, "credential"); value = (1 as Field); }`, 1);
  check(`export circuit update(): [] { const key = ownPublicKey(); assert(persistentCommit<Bytes<32>>(key.bytes, default<Bytes<32>>) == credential, "credential"); value = (1 as Field); }`, 0);
});
test("native-key commitment evidence is separate from ordinary digest observation", () => {
  const source = header + `export circuit update(): [] {
    const key = ownPublicKey();
    assert(persistentCommit<Bytes<32>>(key.bytes, secret()) == credential, "credential");
    value = (1 as Field);
  }`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const ordinary = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false, "all", false, false, false, false, false, false, true).analyze();
      assert.equal(ordinary.commitEvidence, undefined);
      assert.equal(ordinary.diagnostics.length, 0);
      assert.deepEqual(rule.run(ordinary), []);
      assert.ok(ordinary.diagnostics.some(issue => issue.code === "native-key-evidence-unavailable"));
      const selected = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false, "all", false, false, false, false, false, false, true, false, false, false, undefined, false, true).analyze();
      assert.equal(selected.commitEvidence, true);
      assert.equal(rule.run(selected).length, 1);
      assert.deepEqual(selected.diagnostics, []);
    }
  });
});
test("published nonce equality removes private credential ingredient status", () => {
  check(`export circuit update(): [] { const nonce = secret(); assert(nonce == owner, "public nonce"); const key = ownPublicKey(); const claim = Credential { key: key.bytes, nonce: nonce }; assert(persistentHash<Credential>(claim) == credential, "credential"); value = (1 as Field); }`, 0);
});

test("native key used only as canonical mint recipient stays quiet", () => {
  check(`export circuit update(): [] { const coin = mintShieldedToken(default<Bytes<32>>, 1, default<Bytes<32>>, left<ZswapCoinPublicKey, ContractAddress>(ownPublicKey())); value = (1 as Field); }`, 0);
});
test("terminal Counter absence certificate excludes all native witnesses", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary; export ledger counter: Counter; export circuit update(flag: Boolean): [] { if (disclose(flag)) { counter.increment(1); } return []; }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const result = qualifyCounterDetectors(program, program.entries[0], [rule.id], resolvePolicies(program));
    assert.equal(result.status, "eligible");
    if (result.status === "eligible") assert.equal(result.certificates[0].reason, "no-witnesses");
  });
});

test("a hash of another public native key is not a private-preimage alternate", () => {
  check(`export circuit update(): [] { const key = ownPublicKey(); assert(key.bytes == owner, "key"); assert(persistentHash<Bytes<32>>(ownPublicKey().bytes) == credential, "public key hash"); value = (1 as Field); }`, 0);
});
