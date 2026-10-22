import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile } from "../src/index.js";
import { signedEffectInput } from "../src/detectors/signed-effect-input.js";
import { signedCoinInputFindings } from "../src/detectors/signed-coin-input.js";
import { SIGNED_COIN_SEND } from "../src/semantic/signed-input-targets.js";
import { signedInputTargets } from "../src/semantic/signed-input-targets.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `pragma language_version 0.26.0; import CompactStandardLibrary;
circuit signature(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): Boolean { return jubjubSchnorrVerify<1>(msg, sig, pk); }
`;
function fixture(body: string, expected: string[], zkirVersion: 2 | 3 = 2) {
  withFiles({ "main.compact": header + body }, dir => {
    const file = resolve(dir, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, zkirVersion);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file, [], undefined, undefined, zkirVersion);
    let first: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, false, "all", false, false, false, false, true, false, true, false, false, false,
        signedInputTargets(program)).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = signedEffectInput.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual([...new Set(findings.map(item => item.metadata.entry))].sort(), expected.slice().sort());
      first ??= findings; assert.deepEqual(findings, first);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const report = scanFile(file, { detectors: [signedEffectInput.id], experimentalCounterQueries, zkirVersion });
      assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
      assert.deepEqual([...new Set(report.findings.map(item => item.metadata.entry))].sort(), expected.slice().sort());
    }
  });
}
const params = "coin: QualifiedShieldedCoinInfo, sig: JubjubSchnorrSignature, pk: JubjubPoint";
const send = "return disclose(sendShielded(disclose(coin), shieldedBurnAddress(), 1));";
test("signed coin nonce positive, corrected digest and unrelated lookalike", () => fixture(`
export circuit positive(${params}): ShieldedSendResult {
  assert(signature([coin.value as Field], sig, pk), "approved amount"); ${send}
}
export circuit fixed(${params}): ShieldedSendResult {
  assert(signature([transientHash<Bytes<32>>(coin.nonce)], sig, pk), "approved input"); ${send}
}
export circuit lookalike(${params}): ShieldedSendResult {
  const unused = signature([coin.value as Field], sig, pk); ${send}
}
`, ["positive"]));
test("exact nonce binding before send cannot borrow later or sibling-field equalities", () => fixture(`
export circuit bound(${params}, approved: Bytes<32>): ShieldedSendResult {
  assert(signature([transientHash<Bytes<32>>(approved)], sig, pk), "approved");
  assert(coin.nonce == approved, "bound coin"); ${send}
}
export circuit lateBinding(${params}, approved: Bytes<32>): ShieldedSendResult {
  assert(signature([transientHash<Bytes<32>>(approved)], sig, pk), "approved");
  const sent = sendShielded(disclose(coin), shieldedBurnAddress(), 1);
  assert(coin.nonce == approved, "late equality"); return disclose(sent);
}
export circuit lateSignature(${params}): ShieldedSendResult {
  const sent = sendShielded(disclose(coin), shieldedBurnAddress(), 1);
  assert(signature([coin.value as Field], sig, pk), "late approval"); return disclose(sent);
}
export circuit otherField(${params}): ShieldedSendResult {
  assert(signature([transientHash<Bytes<32>>(coin.color)], sig, pk), "color only"); ${send}
}
`, ["lateBinding", "otherField"]));
test("repeated helper sends, snapshot revisions and aborted histories retain exact observations", () => fixture(`
export ledger storedNonce: Bytes<32>;
circuit transmit(input: QualifiedShieldedCoinInfo): ShieldedSendResult { return sendShielded(disclose(input), shieldedBurnAddress(), 1); }
export circuit repeated(${params}, other: QualifiedShieldedCoinInfo): ShieldedSendResult {
  assert(signature([transientHash<Bytes<32>>(coin.nonce)], sig, pk), "approved first");
  const first = transmit(coin); return disclose(transmit(other));
}
export circuit aborted(${params}): ShieldedSendResult {
  assert(signature([coin.value as Field], sig, pk), "approved amount");
  const sent = transmit(coin); assert(false, "disabled"); return disclose(sent);
}
`, ["repeated"]));

test("canonical ECDSA approved digest distinguishes coin amount from input nonce", () => fixture(`
struct Approval { operation: Field; selfAddress: ContractAddress; nonce: Uint<64>; amount: Uint<128>; }
struct BoundApproval { operation: Field; selfAddress: ContractAddress; nonce: Uint<64>; amount: Uint<128>; coin: ShieldedCoinInfo; }
export ledger approvalNonce: Uint<64>;
export circuit positive(coin: QualifiedShieldedCoinInfo, sig: Secp256k1EcdsaSignature, pk: Secp256k1Point): ShieldedSendResult {
  const approval = Approval { operation: 1 as Field, selfAddress: kernel.self(), nonce: approvalNonce, amount: 1 };
  assert(secp256k1EcdsaVerify(keccak256<Approval>(approval), sig, pk), "approve burn");
  approvalNonce = (approvalNonce + 1) as Uint<64>;
  ${send}
}
export circuit fixed(coin: QualifiedShieldedCoinInfo, sig: Secp256k1EcdsaSignature, pk: Secp256k1Point): ShieldedSendResult {
  const approval = BoundApproval { operation: 1 as Field, selfAddress: kernel.self(), nonce: approvalNonce, amount: 1, coin: ShieldedCoinInfo { nonce: coin.nonce, color: coin.color, value: coin.value } };
  assert(secp256k1EcdsaVerify(keccak256<BoundApproval>(approval), sig, pk), "approve input");
  approvalNonce = (approvalNonce + 1) as Uint<64>;
  ${send}
}
`, ["positive"], 3));


test("missing ECDSA observer and missing send boundary remain explicitly incomplete", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export circuit probe(coin: QualifiedShieldedCoinInfo, sig: Secp256k1EcdsaSignature, pk: Secp256k1Point): ShieldedSendResult {
  assert(secp256k1EcdsaVerify(keccak256<Uint<128>>(coin.value), sig, pk), "approval");
  return disclose(sendShielded(disclose(coin), shieldedBurnAddress(), 1));
}` }, dir => {
    const file = resolve(dir, "main.compact"), program = new Program(file, [], undefined, undefined, 3);
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 3).valid, true);
    const flow = (targets: Set<string>) => new Dataflow(program, 40000, 256, 50000, "instructions", true, true,
      "equivalent-states", false, false, "all", false, false, false, false, true, false, true, false, false, false, targets).analyze();
    const missing = flow(new Set([SIGNED_COIN_SEND]));
    assert.equal(missing.diagnostics.length, 0);
    assert.deepEqual(signedEffectInput.run(missing), []);
    assert.ok(missing.diagnostics.some(issue => issue.code === "signed-coin-evidence-unavailable" && issue.scope?.detectorId === signedEffectInput.id));
    const boundary = flow(signedInputTargets(program));
    for (const path of boundary.paths) for (const op of path.operations ?? []) if (op.kind === "circuit-invocation" && op.name === SIGNED_COIN_SEND) delete op.operationsBefore;
    assert.deepEqual(signedCoinInputFindings(boundary), []);
    assert.ok(boundary.diagnostics.some(issue => issue.code === "signed-coin-evidence-unavailable"));
  });
});

test("owned signed-coin triplet compiles and distinguishes approved input from discarded approval", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-signed-coin-${variant}.compact`);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 3);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const report = scanFile(file, { detectors: [signedEffectInput.id], zkirVersion: 3 });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(item => item.location.line), variant === "positive" ? [36] : []);
  }
});
