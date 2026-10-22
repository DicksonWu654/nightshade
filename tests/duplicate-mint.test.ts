import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, type AbstractValue } from "../src/dataflow/index.js";
import { successfulConstants } from "../src/dataflow/successful-constants.js";
import { shieldedMintKey } from "../src/dataflow/mint-inputs.js";
import { duplicateShieldedMint as rule } from "../src/detectors/duplicate-mint.js";
import { Program } from "../src/semantic/index.js";
import { scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = "import CompactStandardLibrary;\n";
function analyze(program: Program, engine: "instructions" | "expressions", cached: boolean) {
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all", false, false, false, true, false, false, false, false, true).analyze();
}
function check(source: string, expected: string[]) {
  withFiles({ "main.compact": header + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    const program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = analyze(program, engine, cached);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(findings.map(item => item.metadata.entry).sort(), [...expected].sort());
      baseline ??= findings;
      assert.deepEqual(findings, baseline);
    }
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)), baseline);
  });
}

test("identical mints and deterministic nonce derivation, not generic commitment opening reuse", () => check(`
export circuit repeated(nonce: Bytes<32>, recipient: ZswapCoinPublicKey): [] {
  const target = left<ZswapCoinPublicKey,ContractAddress>(disclose(recipient));
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),target);
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),target);
}
export circuit sameIndex(nonce: Bytes<32>, recipient: ZswapCoinPublicKey): [] {
  const target = left<ZswapCoinPublicKey,ContractAddress>(disclose(recipient));
  mintShieldedToken(default<Bytes<32>>,1,disclose(evolveNonce(0,nonce)),target);
  mintShieldedToken(default<Bytes<32>>,1,disclose(evolveNonce(0,nonce)),target);
}
export circuit entireRecipient(nonce: Bytes<32>, recipient: Either<ZswapCoinPublicKey,ContractAddress>): [] {
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),disclose(recipient));
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),disclose(recipient));
}
export circuit distinctIndex(nonce: Bytes<32>, recipient: ZswapCoinPublicKey): [] {
  const target = left<ZswapCoinPublicKey,ContractAddress>(disclose(recipient));
  mintShieldedToken(default<Bytes<32>>,1,disclose(evolveNonce(0,nonce)),target);
  mintShieldedToken(default<Bytes<32>>,1,disclose(evolveNonce(1,nonce)),target);
}
export circuit commitments(nonce: Bytes<32>): Field {
  const a = persistentCommit<Field>(1 as Field,disclose(nonce));
  const b = persistentCommit<Field>(2 as Field,disclose(nonce));
  return degradeToTransient(a) + degradeToTransient(b);
}
`, ["entireRecipient", "repeated", "sameIndex"]));

test("amount, token domain and active recipient all participate in duplicate identity", () => check(`
export circuit differentAmount(nonce: Bytes<32>, key: ZswapCoinPublicKey): [] {
  const to = left<ZswapCoinPublicKey,ContractAddress>(disclose(key));
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),to);
  mintShieldedToken(default<Bytes<32>>,2,disclose(nonce),to);
}
export circuit differentDomain(nonce: Bytes<32>, key: ZswapCoinPublicKey): [] {
  const to = left<ZswapCoinPublicKey,ContractAddress>(disclose(key));
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),to);
  mintShieldedToken(pad(32,"other"),1,disclose(nonce),to);
}
export circuit differentRecipient(nonce: Bytes<32>): [] {
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),left<ZswapCoinPublicKey,ContractAddress>(ZswapCoinPublicKey { bytes: pad(32,"a") }));
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),left<ZswapCoinPublicKey,ContractAddress>(ZswapCoinPublicKey { bytes: pad(32,"b") }));
}
export circuit differentArm(nonce: Bytes<32>): [] {
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),left<ZswapCoinPublicKey,ContractAddress>(default<ZswapCoinPublicKey>));
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),right<ZswapCoinPublicKey,ContractAddress>(default<ContractAddress>));
}
export circuit inactiveIrrelevant(nonce: Bytes<32>, key: ZswapCoinPublicKey): [] {
  const a = Either<ZswapCoinPublicKey,ContractAddress> { is_left: true, left: disclose(key), right: default<ContractAddress> };
  const b = Either<ZswapCoinPublicKey,ContractAddress> { is_left: true, left: disclose(key), right: ContractAddress { bytes: pad(32,"inactive") } };
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),a);
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),b);
}
`, ["inactiveIrrelevant"]));

test("mint histories stay correlated and aborts do not count", () => check(`
export circuit exclusive(flag: Boolean, nonce: Bytes<32>): [] {
  if (disclose(flag)) { mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),shieldedBurnAddress()); }
  else { mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),shieldedBurnAddress()); }
}
export circuit rejected(nonce: Bytes<32>): [] {
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),shieldedBurnAddress());
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),shieldedBurnAddress());
  assert(false,"reject");
}
export circuit constrainedLate(a: Bytes<32>, b: Bytes<32>): [] {
  mintShieldedToken(default<Bytes<32>>,1,disclose(a),shieldedBurnAddress());
  mintShieldedToken(default<Bytes<32>>,1,disclose(b),shieldedBurnAddress());
  assert(a == b,"same nonce");
}
export circuit unconstrained(a: Bytes<32>, b: Bytes<32>): [] {
  mintShieldedToken(default<Bytes<32>>,1,disclose(a),shieldedBurnAddress());
  mintShieldedToken(default<Bytes<32>>,1,disclose(b),shieldedBurnAddress());
}
`, ["constrainedLate"]));

test("helper replay keeps fresh evolution operands and immutable storage snapshots", () => check(`
export ledger nonce: Bytes<32>;
circuit derived(index: Uint<128>, previous: Bytes<32>): Bytes<32> { return evolveNonce(index,previous); }
circuit mint(index: Uint<128>, previous: Bytes<32>): [] {
  mintShieldedToken(default<Bytes<32>>,1,disclose(derived(index,previous)),shieldedBurnAddress());
}
export circuit helperSame(a: Bytes<32>): [] { mint(0,a); mint(0,a); }
export circuit helperDifferent(a: Bytes<32>, b: Bytes<32>): [] { mint(0,a); mint(0,b); }
export circuit helperIndices(a: Bytes<32>): [] { mint(0,a); mint(1,a); }
export circuit saved(a: Bytes<32>): [] {
  nonce = disclose(a); const snapshot = nonce;
  mintShieldedToken(default<Bytes<32>>,1,snapshot,shieldedBurnAddress());
  nonce = pad(32,"new");
  mintShieldedToken(default<Bytes<32>>,1,snapshot,shieldedBurnAddress());
}
export circuit updated(a: Bytes<32>): [] {
  nonce = disclose(a);
  mintShieldedToken(default<Bytes<32>>,1,nonce,shieldedBurnAddress());
  nonce = pad(32,"new");
  mintShieldedToken(default<Bytes<32>>,1,nonce,shieldedBurnAddress());
}
`, ["helperSame", "saved"]));

test("application namesakes and entries without canonical mints need no evidence", () => check(`
module Fake { export circuit mintShieldedToken(): [] {} }
import Fake prefix F_;
export circuit ordinary(): [] { F_mintShieldedToken(); }
`, []));

test("key budgets and wildcard identities cannot become clean duplicate evidence", () => {
  const empty = { flows: [], ledger: new Set<string>() };
  const path = { entry: "entry", bindings: [], sinks: [], path: [], writes: [], predicates: [] };
  const nonce = { ...empty, identity: "same-wildcard", region: { root: "ledger", path: ["*"], type: "Bytes<32>" } };
  const number = { ...empty, constant: "1", constantKind: "integer" as const };
  const bytes = { ...empty, constant: "00".repeat(32), constantKind: "bytes" as const };
  const recipient = { ...empty, fields: { is_left: { ...empty, constant: "true", constantKind: "boolean" as const }, left: { ...empty, fields: { bytes } } } };
  const args = [bytes, number, nonce, recipient];
  assert.equal(shieldedMintKey(args, successfulConstants(path)).key, undefined);
  assert.equal(shieldedMintKey(args, successfulConstants(path), 0).complete, false);
  let deep: AbstractValue = bytes;
  for (let i = 0; i < 35; i++) deep = { ...empty, nonceEvolution: { index: number, nonce: deep } };
  assert.equal(shieldedMintKey([bytes, number, deep, recipient], successfulConstants(path)).complete, false);
});

test("absent mint observation is explicitly incomplete, not a clean direct consumer", () => {
  withFiles({ "main.compact": header + "export circuit twice(): [] { mintShieldedToken(default<Bytes<32>>,1,default<Bytes<32>>,shieldedBurnAddress()); mintShieldedToken(default<Bytes<32>>,1,default<Bytes<32>>,shieldedBurnAddress()); }" }, directory => {
    const program = new Program(resolve(directory,"main.compact"));
    const baseline = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(baseline), []);
    assert.equal(baseline.diagnostics[0].code,"duplicate-mint-evidence-unavailable");
    const observed = analyze(program,"instructions",true);
    const op = observed.paths[0].operations!.find(op => op.kind === "shielded-mint")!;
    const empty = { flows: [], ledger: new Set<string>() };
    let deep: AbstractValue = op.args[2];
    for (let i = 0; i < 35; i++) deep = { ...empty, nonceEvolution: { index: op.args[1], nonce: deep } };
    op.args[2] = deep;
    assert.deepEqual(rule.run(observed), []);
    assert.equal(observed.diagnostics.at(-1)!.code,"duplicate-mint-evidence-budget");
  });
});

test("higher-order callbacks preserve nonce inputs, operation order and zero iterations", () => check(`
circuit mintEach(nonce: Bytes<32>): [] {
  mintShieldedToken(default<Bytes<32>>,1,disclose(nonce),shieldedBurnAddress());
}
export circuit repeat(nonce: Bytes<32>): [] { map(mintEach,[nonce,nonce]); }
export circuit distinct(a: Bytes<32>, b: Bytes<32>): [] { map(mintEach,[a,b]); }
export circuit zero(): [] { map(mintEach,[] as Vector<0,Bytes<32>>); }
`, ["repeat"]));

test("a saved transformed nonce has exact snapshot identity without equating separate computations", () => check(`
export circuit savedHash(nonce: Bytes<32>): [] {
  const saved = persistentHash<Bytes<32>>(evolveNonce(0,nonce));
  mintShieldedToken(default<Bytes<32>>,1,disclose(saved),shieldedBurnAddress());
  mintShieldedToken(default<Bytes<32>>,1,disclose(saved),shieldedBurnAddress());
}
export circuit separateHashes(nonce: Bytes<32>): [] {
  const a = persistentHash<Vector<2,Bytes<32>>>([evolveNonce(0,nonce),pad(32,"a")]);
  const b = persistentHash<Vector<2,Bytes<32>>>([evolveNonce(0,nonce),pad(32,"b")]);
  mintShieldedToken(default<Bytes<32>>,1,disclose(a),shieldedBurnAddress());
  mintShieldedToken(default<Bytes<32>>,1,disclose(b),shieldedBurnAddress());
}
witness nextNonce(): Bytes<32>;
export circuit freshWitnesses(): [] {
  mintShieldedToken(default<Bytes<32>>,1,disclose(nextNonce()),shieldedBurnAddress());
  mintShieldedToken(default<Bytes<32>>,1,disclose(nextNonce()),shieldedBurnAddress());
}
`, ["savedHash"]));

test("fresh wildcard snapshots can be related by an explicit guard, never by their shared region", () => check(`
export ledger nonces: Map<Uint<8>,Bytes<32>>;
export circuit explicitEquality(a: Uint<8>, b: Uint<8>): [] {
  const i = ((a as Field)+1) as Uint<8>; const j = ((b as Field)+1) as Uint<8>;
  assert(nonces.member(disclose(i)),"exists"); assert(nonces.member(disclose(j)),"exists");
  const n = nonces.lookup(disclose(i)); const m = nonces.lookup(disclose(j));
  mintShieldedToken(default<Bytes<32>>,1,n,shieldedBurnAddress());
  mintShieldedToken(default<Bytes<32>>,1,m,shieldedBurnAddress()); assert(n == m,"same saved values");
}
export circuit differentReads(a: Uint<8>, b: Uint<8>): [] {
  const i = ((a as Field)+1) as Uint<8>; const j = ((b as Field)+1) as Uint<8>;
  assert(i != j,"different"); assert(nonces.member(disclose(i)),"exists"); assert(nonces.member(disclose(j)),"exists");
  const n = nonces.lookup(disclose(i)); const m = nonces.lookup(disclose(j));
  mintShieldedToken(default<Bytes<32>>,1,n,shieldedBurnAddress());
  mintShieldedToken(default<Bytes<32>>,1,m,shieldedBurnAddress());
}
`, ["explicitEquality"]));
