import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import type { AbstractValue } from "../src/dataflow/index.js";
import { directPreimageSource } from "../src/dataflow/transfers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { spoofableAuthorization } from "../src/detectors/authorization.js";
import { semanticPaths, withFiles } from "./helpers.js";

const modes = ["instructions", "expressions"] as const;
const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8"));
function compile(file: string): void {
  if (process.env.COMPACTC_TEST) {
    const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(result.valid, true, result.error);
  }
}
function fixture(source: string, check: (program: Program) => void, filename = "main.compact"): void {
  withFiles({ [filename]: `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, filename); compile(file);
    check(new Program(file, [], directory));
  });
}
function findings(facts: AnalysisFacts) {
  const result = spoofableAuthorization.run(facts);
  assert.deepEqual(facts.diagnostics, []);
  assert.deepEqual(facts.completedEntries, facts.program.entries);
  return result;
}

test("private arithmetic with a ledger operand does not publicize an alternate authentication preimage", () => {
  fixture(`export ledger owner: Bytes<32>;
export ledger offset: Field;
export ledger stored: Field;
witness identity(): Bytes<32>;
witness key(): Field;
export circuit entry(next: Field, other: Field): [] {
  assert(identity() == owner, "raw");
  const secret = key();
  assert(secret == other + offset, "private relation");
  assert(persistentHash<Field>(secret) == owner, "secret authority");
  stored = disclose(next);
}`, program => {
    for (const engine of modes) for (const cached of [false, true])
      assert.deepEqual(findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze()), []);
  });
});

test("authorization manifest has compiler-valid native-witness positive, secret correction and negative lookalikes", () => {
  for (const row of manifest.authorization.cases) {
    const file = resolve("tests/corpus", row.file); compile(file);
    const program = new Program(file);
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.deepEqual(actual.map(finding => finding.location.line), row.lines);
      assert.ok(actual.every(finding => finding.metadata.authenticationIntent === "unknown" && finding.metadata.reviewRequired));
    }
    const scan = scanFile(file);
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.filter(finding => finding.detectorId === spoofableAuthorization.id).map(finding => finding.location.line), row.lines);
  }
});

test("selected equality polarity, Boolean helpers and opposite surviving branches", () => {
  fixture(`
export ledger owner: Bytes<32>;
export ledger stored: Field;
witness identity(): Bytes<32>;
witness choice(): Boolean;
circuit allowed(): Boolean { return identity() == owner; }
export circuit enforced(next: Field, flag: Boolean): [] {
  assert(disclose(flag) && allowed(), "combined"); stored = disclose(next);
}
export circuit negativeGuard(next: Field): [] {
  if (disclose(identity() != owner)) { assert(false, "not allowed"); }
  stored = disclose(next);
}
export circuit equalityFalse(next: Field): [] {
  assert((identity() != owner) == false, "owner"); stored = disclose(next);
}
export circuit booleanGuard(next: Field): [] {
  assert(!choice(), "selected false"); stored = disclose(next);
}
export circuit opposite(next: Field): [] {
  if (disclose(choice())) { const selected = true; } else { const selected = false; }
  stored = disclose(next);
}
export circuit differentAuthentication(next: Field, flag: Boolean): [] {
  if (disclose(flag)) { assert(allowed(), "raw"); }
  else { assert(persistentHash<Bytes<32>>(identity()) == owner, "preimage"); }
  stored = disclose(next);
}
export circuit rejected(next: Field): [] {
  assert(allowed(), "raw"); stored = disclose(next); assert(false, "disabled");
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.deepEqual(actual.map(finding => finding.metadata.entry).sort(), ["booleanGuard", "enforced", "equalityFalse", "negativeGuard"]);
      baseline ??= actual;
      assert.deepEqual(actual, baseline, JSON.stringify({ engine, cached }));
    }
  });
});

test("nested mutation replay uses current invocation sites and preserves immutable guard storage", () => {
  fixture(`
export ledger owner: Bytes<32>;
export ledger stored: Field;
witness identity(): Bytes<32>;
circuit mutate(next: Field): [] { stored = disclose(next); }
circuit wrapper(next: Field): [] { mutate(next); }
export circuit entry(next: Field): [] {
  const old = owner;
  assert(identity() == old, "old snapshot");
  wrapper(next);
  wrapper(next);
  owner = default<Bytes<32>>;
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      const actual = findings(facts);
      assert.equal(actual.length, 1);
      assert.equal(new Set(actual.map(finding => finding.fingerprint)).size, 1);
      assert.deepEqual((actual[0].metadata.affectedEffects as unknown[] | undefined)?.length, 2);
      if (cached) assert.ok(facts.metrics.statefulSummaryHits > 0);
      const predicate = facts.paths[0].predicates![0];
      assert.equal(predicate.value.comparison!.right.region!.revision, 0);
      assert.deepEqual(facts.paths[0].writes.map(write => write.callSites?.map(site => site.line)), [[8, 11, 7], [8, 12, 7], [8]]);
      baseline ??= { actual, predicates: facts.paths[0].predicates, writes: facts.paths[0].writes };
      assert.deepEqual({ actual, predicates: facts.paths[0].predicates, writes: facts.paths[0].writes }, baseline, JSON.stringify({ engine, cached }));
    }
  });
});

test("distinct witness calls cannot make a second input equal the checked first input", () => {
  fixture(`
export ledger owner: Bytes<32>;
export ledger stored: Field;
witness identity(): Bytes<32>;
circuit input(): Bytes<32> { return identity(); }
export circuit entry(next: Field): [] {
  const first = input();
  const second = input();
  assert(first == owner, "owner");
  assert(second != first, "different input is feasible");
  stored = disclose(next);
}`, program => {
    for (const engine of modes) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.equal(findings(facts).length, 1);
      assert.equal(facts.paths.length, 1);
      const predicates = facts.paths[0].predicates!;
      const first = predicates[0].value.comparison!.left.flows[0].source;
      const second = predicates[1].value.comparison!.left.flows[0].source;
      assert.notEqual(first.id, second.id);
      assert.notEqual(first.invocation!.site, second.invocation!.site);
    }
  });
});

test("branch summary replay retains caller Boolean guards and distinct effect invocation sites", () => {
  fixture(`
export ledger stored: Field;
witness allowed(): Boolean;
circuit mutate(flag: Boolean, next: Field): [] {
  if (disclose(flag)) { stored = disclose(next); } else { stored = default<Field>; }
}
export circuit entry(next: Field, a: Uint<8>, b: Uint<8>): [] {
  const flag = (a + 1) < (b + 1); const auth = allowed(); assert(auth, "allowed");
  mutate(flag, next); mutate(flag, next);
  assert(auth, "retained caller identity");
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      const actual = findings(facts);
      assert.equal(actual.length, 1);
      assert.equal(new Set(actual.map(finding => finding.fingerprint)).size, 1);
      assert.deepEqual((actual[0].metadata.affectedEffects as unknown[] | undefined)?.length, 2);
      if (cached) assert.ok(facts.metrics.statefulSummaryHits > 0);
      baseline ??= actual;
      assert.deepEqual(actual, baseline);
    }
  });
});

test("native caller equality also protects modeled transaction writes with actual call-site evidence", () => {
  fixture(`
export ledger owner: ZswapCoinPublicKey;
export circuit transfer(color: Bytes<32>, recipient: Either<ContractAddress,UserAddress>): [] {
  assert(ownPublicKey() == owner, "owner");
  sendUnshielded(disclose(color), 1, disclose(recipient));
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.ok(actual.length > 0);
      assert.ok(actual.every(finding => finding.message.includes("kernel-write") && finding.metadata.guardPosition === "before-effect"));
      assert.ok(actual.every(finding => finding.severity === "high" && finding.confidence === "high" && finding.metadata.comparedValue === "ledger-public"));
      baseline ??= actual;
      assert.deepEqual(actual, baseline);
    }
  });
});

test("canonical receipt-only guards are omitted from authorization findings", () => {
  fixture(`
export ledger owner: ZswapCoinPublicKey;
witness payoutAddress(): Either<ZswapCoinPublicKey,ContractAddress>;
witness signature_valid(): Boolean;
export circuit claimPayout(input: QualifiedShieldedCoinInfo): [] {
  sendShielded(disclose(input),disclose(payoutAddress()),1);
}
export circuit authorizeOwner(note: Bytes<32>): [] {
  assert(ownPublicKey() == owner,"owner");
  kernel.claimZswapCoinReceive(disclose(note));
}
export circuit grantSignedReceipt(note: Bytes<32>): [] {
  assert(signature_valid(),"signature");
  kernel.claimZswapCoinReceive(disclose(note));
}
export circuit corrected(input: QualifiedShieldedCoinInfo): [] {
  sendShielded(disclose(input),left<ZswapCoinPublicKey,ContractAddress>(default<ZswapCoinPublicKey>),1);
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const facts = new Dataflow(program,40000,256,50000,engine,cached,cached).analyze();
      const actual = findings(facts);
      assert.equal(actual.length,0);
      baseline ??= actual; assert.deepEqual(actual,baseline);
      const payout = facts.paths.filter(path => program.symbols.get(path.entry)?.name === "claimPayout");
      assert.ok(payout.some(path => path.operations!.some(operation => operation.name === "claimZswapCoinSpend")),"Outgoing spend histories remain observed");
    }
  });
});

test("payment receipt with balance writes labels role heuristics separately from outgoing Kernel effects", () => {
  fixture(`
export ledger servicePrice: Uint<128>;
export ledger merchantBalance: Uint<128>;
export ledger recorded: Boolean;
witness creditCoin(): ShieldedCoinInfo;
export circuit pay(): [] {
  const coin = creditCoin();
  assert(coin.value == servicePrice,"wrong amount");
  receiveShielded(disclose(coin));
  merchantBalance = (merchantBalance + servicePrice) as Uint<128>;
}
export circuit cash(): [] {
  const coin = creditCoin();
  assert(coin.value == servicePrice,"wrong amount");
  receiveShielded(disclose(coin));
  sendUnshielded(default<Bytes<32>>,disclose(coin.value),right<ContractAddress,UserAddress>(default<UserAddress>));
}
export circuit record(): [] {
  const coin = creditCoin();
  assert(coin.value == servicePrice,"wrong amount");
  receiveShielded(disclose(coin));
  recorded = true;
}
export circuit lookalike(coin: ShieldedCoinInfo): [] {
  assert(coin.value == servicePrice,"wrong amount");
  receiveShielded(disclose(coin));
  merchantBalance = (merchantBalance + servicePrice) as Uint<128>;
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false,true]) {
      const actual = findings(new Dataflow(program,40000,256,50000,engine,cached,cached).analyze());
      assert.equal(actual.length,3);
      const pay = actual.find(item => item.metadata.entry === "pay")!;
      const cash = actual.find(item => item.metadata.entry === "cash")!;
      assert.equal(pay.severity,"high"); assert.equal(pay.confidence,"high");
      assert.equal(pay.metadata.effectRoleEvidence,"circuit-or-ledger-name-heuristic");
      assert.equal(pay.metadata.authenticationIntent,"unknown");
      assert.equal(pay.metadata.soleGate,"unproven");
      const effects = pay.metadata.affectedEffects as {kind:string;name:string}[];
      assert.ok(effects.some(effect => effect.kind === "ledger-write" && effect.name === "merchantBalance"));
      assert.deepEqual(effects.filter(effect => effect.kind === "kernel-write").map(effect => effect.name),["claimZswapCoinReceive"]);
      assert.equal(cash.metadata.effectRoleEvidence,"kernel-effect");
      assert.ok((cash.metadata.affectedEffects as {name:string}[]).some(effect => effect.name === "claimUnshieldedCoinSpend"));
      assert.equal(actual.find(item => item.metadata.entry === "record")!.metadata.effectRoleEvidence,"unclassified","Receipt operation names cannot supply a circuit/ledger role heuristic");
      baseline ??= actual; assert.deepEqual(actual,baseline);
    }
  });
});

test("receipt groups with real writes, spends, calls or namesake mutations retain authorization grading", () => {
  fixture(`
export ledger owner: ZswapCoinPublicKey;
export ledger authority: Field;
witness signature_valid(): Boolean;
circuit claimZswapCoinReceive(): [] { authority = 1 as Field; }
export circuit mixedWrite(note: Bytes<32>): [] {
  assert(ownPublicKey() == owner,"owner");
  kernel.claimZswapCoinReceive(disclose(note)); authority = 1 as Field;
}
export circuit mixedSpend(note: Bytes<32>): [] {
  assert(signature_valid(),"signature");
  kernel.claimZswapCoinReceive(disclose(note)); kernel.claimZswapCoinSpend(disclose(note));
}
export circuit mixedCall(note: Bytes<32>): [] {
  assert(signature_valid(),"signature");
  kernel.claimZswapCoinReceive(disclose(note));
  kernel.claimContractCall(default<Bytes<32>>,default<Bytes<32>>,0 as Field);
}
export circuit namesake(note: Bytes<32>): [] {
  assert(signature_valid(),"signature"); claimZswapCoinReceive();
}
export circuit conditionalWrite(note: Bytes<32>,flag: Boolean): [] {
  assert(ownPublicKey() == owner,"owner"); kernel.claimZswapCoinReceive(disclose(note));
  if (disclose(flag)) { authority = 1 as Field; }
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false,true]) {
      const actual = findings(new Dataflow(program,40000,256,50000,engine,cached,cached).analyze());
      assert.equal(actual.length,5);
      for (const item of actual) {
        assert.ok(["high","critical"].includes(item.severity));
        assert.equal(item.confidence,"high");
        assert.notEqual(item.metadata.effectRoleEvidence,"receipt-coordination");
      }
      assert.equal(actual.find(item => item.metadata.entry === "mixedWrite")!.metadata.authorizationKind,"public-key-equality");
      assert.ok((actual.find(item => item.metadata.entry === "namesake")!.metadata.affectedEffects as {kind:string}[]).every(effect => effect.kind === "ledger-write"));
      baseline ??= actual; assert.deepEqual(actual,baseline);
    }
  });
});

test("checkpoint receipt prefixes retain immutable proof guards and grouped writes retain authorization grading", () => {
  fixture(`
witness approved(): Boolean;
export ledger authority: Field;
export circuit checkpointReceipt(note: Bytes<32>,flag: Boolean): [] {
  assert(approved(),"receipt validation"); kernel.claimZswapCoinReceive(disclose(note));
  kernel.checkpoint(); if (disclose(flag)) { authority = 1 as Field; }
}
export circuit separateLaterGuard(note: Bytes<32>): [] {
  kernel.claimZswapCoinReceive(disclose(note)); kernel.checkpoint();
  assert(approved(),"fallible approval"); authority = 1 as Field;
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false,true]) {
      const facts = new Dataflow(program,40000,256,50000,engine,cached,cached).analyze();
      const actual = findings(facts);
      assert.equal(actual.length,2);
      const separate = actual.find(item => item.metadata.entry === "separateLaterGuard")!;
      const effects = separate.metadata.affectedEffects as {kind:string;name:string}[];
      assert.ok(effects.some(effect => effect.kind === "ledger-write" && effect.name === "authority"));
      assert.ok(effects.some(effect => effect.kind === "kernel-write" && effect.name === "claimZswapCoinReceive"));
      assert.ok(actual.every(item => item.severity === "high" && item.confidence === "high"));
      assert.ok(actual.every(item => item.metadata.soleGate === "unproven"),"Kernel coordination checks prevent a sole raw-witness gate certificate");
      assert.ok(actual.every(item => item.metadata.effectRoleEvidence !== "receipt-coordination"));
      const prefix = facts.paths.find(path => program.symbols.get(path.entry)?.name === "separateLaterGuard" && !path.writes.length)!;
      const full = facts.paths.find(path => path.entry === prefix.entry && path.writes.length)!;
      assert.ok(prefix.operations!.some(operation => operation.name === "claimZswapCoinReceive"));
      assert.deepEqual(prefix.predicates,full.predicates,"Immutable witness constraints apply to the whole proof, including the receipt prefix");
      assert.ok(prefix.path.some(step => step.label === "assertion required by the full proof across kernel checkpoint"));
      baseline ??= actual; assert.deepEqual(actual,baseline);
    }
  });
});

test("ledger-public authorization is high/high while constant checks retain review grading", () => {
  fixture(`
export ledger owner: ZswapCoinPublicKey;
export ledger stored: Field;
witness allowed(): Boolean;
circuit requireOwner(): [] { assert(owner.bytes == ownPublicKey().bytes, "owner"); }
export circuit ledgerGuard(next: Field): [] { requireOwner(); stored = disclose(next); }
export circuit literalGuard(next: Field): [] { assert(allowed(), "input validation"); stored = disclose(next); }
export circuit corrected(next: Field, secret: Bytes<32>): [] {
  assert(owner.bytes == persistentHash<Bytes<32>>(secret), "secret"); stored = disclose(next);
}
`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.deepEqual(actual.map(finding => [finding.metadata.entry, finding.severity, finding.confidence, finding.metadata.comparedValue]),
        [["ledgerGuard", "high", "high", "ledger-public"], ["literalGuard", "low", "low", "public-constant"]]);
      assert.equal(actual.find(finding => finding.metadata.entry === "ledgerGuard")?.metadata.authorizationKind, "public-key-equality");
      assert.equal(actual.find(finding => finding.metadata.entry === "literalGuard")?.metadata.authorizationKind, "witness-validation");
      assert.ok(actual.every(finding => finding.metadata.pathFeasibility === "not-proven"));
      baseline ??= actual; assert.deepEqual(actual, baseline);
    }
  });
});

test("witness-only privileged gates are high/high while validation lookalikes stay informational", () => {
  fixture(`
export ledger total: Counter;
export ledger note: Field;
witness approved(): Boolean;
export circuit mint(): [] {
  assert(approved(), "approval");
  total.increment(1);
}
export circuit validate(next: Field): [] {
  assert(approved(), "input validation");
  note = disclose(next);
}`, program => {
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.deepEqual(actual.map(item => [item.metadata.entry, item.metadata.authorizationKind, item.severity, item.confidence]), [
        ["mint", "witness-only-authorization", "high", "high"],
        ["validate", "witness-validation", "low", "low"],
      ]);
      assert.equal(actual.find(item => item.metadata.entry === "mint")?.metadata.priority, "high");
      assert.equal(actual.find(item => item.metadata.entry === "validate")?.metadata.priority, "informational");
    }
  });
});

test("ecosystem authority setters classify direct signature witnesses as privileged gates", () => {
  fixture(`
export ledger livingDividendAddress: Field;
witness multisig_signature_valid(): Boolean;
export circuit setLivingDividendAddress(next: Field): [] {
  assert(multisig_signature_valid(), "multisig signature invalid");
  livingDividendAddress = disclose(next);
}
`, program => {
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.equal(actual.length, 1);
      assert.equal(actual[0].metadata.authorizationKind, "witness-only-authorization");
      assert.equal(actual[0].metadata.rootCause, "raw-witness-checks-are-the-only-modeled-gates");
      assert.equal(actual[0].metadata.effectRoleEvidence, "circuit-or-ledger-name-heuristic");
      assert.equal(actual[0].severity, "critical");
      assert.equal(actual[0].confidence, "high");
    }
  });
});

test("authorization role grading uses declaration names and kinds rather than source paths", () => {
  for (const [filename, entry, severity] of [["transfer.compact", "validate", "low"], ["constructor.compact", "mint", "critical"]]) {
    fixture(`ledger value: Field; witness valid(): Boolean;
export circuit ${entry}(next: Field): [] { assert(valid(), "check"); value = disclose(next); }`, program => {
      for (const engine of modes) for (const cached of [false, true]) {
        const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
        assert.equal(actual.length, 1);
        assert.equal(actual[0].severity, severity);
      }
    }, filename);
  }
});

test("Boolean signature attestation raises review priority without certifying privilege or sole-gate intent", () => {
  fixture(`
export ledger state: Field;
export ledger digest: Bytes<32>;
witness witness_multisigSignatureValid(): Boolean;
witness secret(): Bytes<32>;
circuit check(): [] { assert(witness_multisigSignatureValid(), "attestation"); }
circuit store(next: Field): [] { state = disclose(next); }
constructor() { check(); state = 0 as Field; }
export circuit update(next: Field): [] { check(); state = disclose(next); }
export circuit repeated(next: Field): [] { check(); check(); store(next); store(next); }
export circuit additional(next: Field, condition: Boolean): [] {
  check(); assert(condition, "additional condition"); state = disclose(next);
}
export circuit corrected(next: Field): [] {
  check(); assert(persistentHash<Bytes<32>>(secret()) == digest, "secret possession");
  state = disclose(next);
}
export circuit rejectedAttestation(next: Field): [] {
  assert(!witness_multisigSignatureValid(), "rejected attestation"); state = disclose(next);
}
`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      const actual = findings(facts);
      assert.equal(actual.filter(item => item.metadata.entry === "repeated").length, 1);
      assert.equal(actual.some(item => item.metadata.entry === "corrected"), false);
      for (const entry of ["update", "repeated", "additional"]) {
        const item = actual.find(item => item.metadata.entry === entry)!;
        assert.equal(item.severity, "high");
        assert.equal(item.confidence, "high");
        assert.equal(item.metadata.authorizationKind, "witness-only-authorization");
        assert.equal(item.metadata.priorityEvidence, "boolean-signature-witness-name-heuristic");
        assert.equal(item.metadata.effectRoleEvidence, "unclassified");
        assert.equal(item.metadata.authenticationIntent, "unknown");
        assert.equal(item.metadata.soleGate, entry === "additional" ? "unproven" : "proven-in-model");
        assert.match(item.title, /state-changing effect/);
        assert.doesNotMatch(item.title, /privileged/);
      }
      for (const item of actual.filter(item => ["constructor", "rejectedAttestation"].includes(item.metadata.entry as string))) {
        assert.equal(item.severity, "low");
        assert.equal(item.metadata.priorityEvidence, undefined);
      }
      assert.equal(actual.length, 5);
      if (cached) assert.ok(facts.metrics.statefulSummaryHits > 0);
      baseline ??= actual; assert.deepEqual(actual, baseline);
    }
  });
});

test("signature priority excludes ordinary validation, non-Boolean results and helper-name lookalikes", () => {
  fixture(`
export ledger state: Field;
witness valid(): Boolean;
witness signature_format_valid(): Boolean;
witness signatureLengthValid(): Boolean;
witness signature_shape_valid(): Boolean;
witness format_signature_valid(): Boolean;
witness shapeSignatureValid(): Boolean;
circuit signature_valid(): Boolean { return valid(); }
module Scalar { export witness signature_valid(): Field; }
module Aggregate {
  struct Result { accepted: Boolean; }
  export witness signature_valid(): Result;
}
import Scalar prefix Scalar_;
import Aggregate prefix Aggregate_;
export circuit ordinary(next: Field): [] { assert(valid(), "validation"); state = disclose(next); }
export circuit format(next: Field): [] { assert(signature_format_valid(), "format"); state = disclose(next); }
export circuit length(next: Field): [] { assert(signatureLengthValid(), "length"); state = disclose(next); }
export circuit shape(next: Field): [] { assert(signature_shape_valid(), "shape"); state = disclose(next); }
export circuit helper(next: Field): [] { assert(signature_valid(), "helper"); state = disclose(next); }
export circuit scalar(next: Field): [] { assert(Scalar_signature_valid() == (1 as Field), "scalar"); state = disclose(next); }
export circuit aggregate(next: Field): [] { assert(Aggregate_signature_valid().accepted, "field"); state = disclose(next); }
export circuit prefixedFormat(next: Field): [] { assert(format_signature_valid(), "format"); state = disclose(next); }
export circuit prefixedShape(next: Field): [] { assert(shapeSignatureValid(), "shape"); state = disclose(next); }
`, program => {
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.equal(actual.length, 9);
      assert.ok(actual.every(item => item.severity === "low" && item.metadata.authorizationKind === "witness-validation" && item.metadata.priorityEvidence === undefined));
    }
  });
});

test("signature priority follows the canonical witness declaration through import renaming", () => {
  fixture(`
export ledger state: Field;
module Attestation { export witness signature_valid(): Boolean; }
module Validation { export witness valid(): Boolean; }
import {signature_valid as valid} from Attestation prefix A_;
import {valid as signature_valid} from Validation prefix V_;
export circuit attested(next: Field): [] { assert(A_valid(), "check"); state = disclose(next); }
export circuit validated(next: Field): [] { assert(V_signature_valid(), "check"); state = disclose(next); }
`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.deepEqual(actual.map(item => [item.metadata.entry, item.severity]), [["attested", "high"], ["validated", "low"]]);
      baseline ??= actual; assert.deepEqual(actual, baseline);
    }
  });
});

test("predicate capacity exhaustion is incomplete and cannot support a universal guard finding", () => {
  fixture(`
export ledger owner: Bytes<32>;
export ledger stored: Field;
witness identity(): Bytes<32>;
export circuit entry(next: Field): [] { assert(identity() == owner, "owner"); stored = disclose(next); }
`, program => {
    for (const engine of modes) {
      let exhausted = false;
      for (let limit = 1; limit <= 30; limit++) {
        const facts = new Dataflow(program, 40000, 256, limit, engine).analyze();
        if (!facts.diagnostics.some(diagnostic => diagnostic.code === "predicate-budget")) continue;
        exhausted = true;
        assert.deepEqual(facts.completedEntries, []);
        assert.deepEqual(spoofableAuthorization.run(facts), []);
        break;
      }
      assert.ok(exhausted, engine);
    }
    const facts = new Dataflow(program).analyze();
    facts.paths[0].predicates = Array(1_000_001).fill(facts.paths[0].predicates![0]);
    assert.deepEqual(spoofableAuthorization.run(facts), []);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "predicate-analysis-budget"));
    const shared = new Dataflow(program).analyze();
    const predicate = shared.paths[0].predicates![0];
    let left = predicate.value.comparison!.left, right = predicate.value.comparison!.right;
    for (let depth = 0; depth < 14; depth++) {
      left = { flows: left.flows, ledger: new Set(), items: [left, left] };
      right = { flows: [], ledger: right.ledger, items: [right, right] };
    }
    predicate.value = { ...predicate.value, comparison: { operator: "==", left, right } };
    assert.deepEqual(spoofableAuthorization.run(shared), [], "shared aggregate expansion cannot leak partial evidence");
    assert.ok(shared.diagnostics.some(diagnostic => diagnostic.code === "predicate-analysis-budget"));
  });
});

test("aggregate dependency unions never pair unrelated witness and ledger components", () => {
  fixture(`
export ledger owner: Bytes<32>;
export ledger marker: Bytes<32>;
export ledger stored: Field;
witness identity(): Bytes<32>;
witness other(): Bytes<32>;
witness secret(): Bytes<32>;
witness suppliedDigest(): Bytes<32>;
export circuit mixedPrivateEquality(next: Field): [] {
  assert([identity(), marker] == [other(), marker], "private equality only");
  stored = disclose(next);
}
export circuit mixedUntrustedPreimage(next: Field): [] {
  assert(identity() == owner, "raw owner");
  assert([persistentHash<Bytes<32>>(secret()), marker] == [suppliedDigest(), marker], "untrusted digest");
  stored = disclose(next);
}
export circuit alignedPublicEquality(next: Field): [] {
  assert([identity(), other()] == [owner, marker], "two public comparisons");
  stored = disclose(next);
}
export circuit alignedTrustedPreimage(next: Field): [] {
  assert(identity() == owner, "raw owner");
  assert([persistentHash<Bytes<32>>(secret()), suppliedDigest()] == [marker, other()], "only first component authenticates");
  stored = disclose(next);
}`, program => {
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.deepEqual(actual.map(finding => finding.metadata.entry).sort(), ["alignedPublicEquality", "mixedUntrustedPreimage"]);
    }
  });
});

test("may-alias storage flows establish neither a raw witness identity nor a trusted preexisting anchor", () => {
  fixture(`
export ledger owner: Bytes<32>;
export ledger anchors: Map<Field, Bytes<32>>;
export ledger stored: Field;
witness identity(): Bytes<32>;
witness secret(): Bytes<32>;
export circuit ambiguousAnchor(key: Field, next: Field): [] {
  assert(identity() == owner, "raw owner");
  const supplied = secret();
  anchors.insert(7 as Field, disclose(persistentHash<Bytes<32>>(supplied)));
  assert(persistentHash<Bytes<32>>(supplied) == anchors.lookup(disclose(key)), "may be freshly written");
  stored = disclose(next);
}
export circuit retainedAnchor(next: Field): [] {
  assert(identity() == owner, "raw owner");
  const previous = owner;
  owner = default<Bytes<32>>;
  assert(persistentHash<Bytes<32>>(secret()) == previous, "preexisting snapshot");
  stored = disclose(next);
}
export circuit ambiguousRaw(key: Field, next: Field): [] {
  anchors.insert(7 as Field, disclose(identity()));
  assert(key != (7 as Field), "different key");
  assert(anchors.lookup(disclose(key)) == owner, "not the supplied value");
  stored = disclose(next);
}
export circuit ambiguousHash(key: Field, next: Field): [] {
  assert(identity() == owner, "raw owner");
  anchors.insert(7 as Field, disclose(persistentHash<Bytes<32>>(secret())));
  assert(key != (7 as Field), "different key");
  assert(anchors.lookup(disclose(key)) == owner, "not necessarily the secret hash");
  stored = disclose(next);
}
export circuit knownPreimage(next: Field): [] {
  assert(identity() == owner, "raw owner");
  const supplied = secret();
  assert(supplied == default<Bytes<32>>, "public preimage");
  assert(persistentHash<Bytes<32>>(supplied) == owner, "known preimage is not authentication");
  stored = disclose(next);
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      const actual = findings(facts);
      assert.deepEqual(actual.map(finding => finding.metadata.entry), ["ambiguousAnchor", "ambiguousHash", "knownPreimage", "knownPreimage"]);
      for (const path of facts.paths) {
        const name = program.symbols.get(path.entry)!.name;
        assert.equal(path.bindings.length, name === "retainedAnchor" ? 1 : 0, `${name}: legacy hash-binding evidence also requires definite origins`);
      }
      baseline ??= actual;
      assert.deepEqual(actual, baseline);
    }
  });
});

test("public preimages cannot supply alternate authentication regardless of statement order or a direct equality alias", () => {
  fixture(`
export ledger owner: Bytes<32>;
export ledger nativeOwner: ZswapCoinPublicKey;
export ledger publicInput: Bytes<32>;
export ledger stored: Field;
witness identity(): Bytes<32>;
witness secret(): Bytes<32>;
circuit callerAllowed(): Boolean { return ownPublicKey() == nativeOwner; }
circuit prefixed(s: Bytes<32>): Bytes<32> {
  return persistentHash<Vector<2, Bytes<32>>>([pad(32, "caller:"), s]);
}
export circuit nestedNativeCaller(next: Field, supplied: Bytes<32>): [] {
  assert(callerAllowed(), "raw native caller");
  assert(prefixed(supplied) == owner, "digest");
  assert(supplied == publicInput, "public preimage"); stored = disclose(next);
}
export circuit knownAfterHash(next: Field): [] {
  assert(identity() == owner, "raw owner");
  const s = secret(); const h = persistentHash<Bytes<32>>(s);
  assert(s == default<Bytes<32>>, "known preimage");
  assert(h == owner, "digest computed earlier"); stored = disclose(next);
}
export circuit knownAfterCheck(next: Field): [] {
  assert(identity() == owner, "raw owner");
  const s = secret(); assert(persistentHash<Bytes<32>>(s) == owner, "digest");
  stored = disclose(next);
  assert(s == default<Bytes<32>>, "known preimage on success");
}
export circuit publicLedgerPreimage(next: Field): [] {
  assert(identity() == owner, "raw owner");
  const s = secret(); assert(s == publicInput, "public preimage");
  assert(persistentHash<Bytes<32>>(s) == owner, "digest of public input"); stored = disclose(next);
}
export circuit publicParameter(next: Field, supplied: Bytes<32>): [] {
  assert(identity() == owner, "raw owner");
  const h = persistentHash<Bytes<32>>(supplied);
  assert(h == owner, "digest"); assert(supplied == publicInput, "public parameter");
  stored = disclose(next);
}
export circuit equalityAlias(next: Field, alias: Bytes<32>): [] {
  assert(identity() == owner, "raw owner");
  const s = secret(); assert(persistentHash<Bytes<32>>(s) == owner, "digest");
  assert(s == alias, "same value"); assert(alias == publicInput, "public alias");
  stored = disclose(next);
}
export circuit unrelatedPublic(next: Field): [] {
  assert(identity() == owner, "raw owner");
  const s = secret(); assert(persistentHash<Bytes<32>>(s) == owner, "digest");
  assert(secret() == publicInput, "a different source"); stored = disclose(next);
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.deepEqual([...new Set(actual.map(finding => finding.metadata.entry))].sort(), ["equalityAlias", "knownAfterCheck", "knownAfterHash", "nestedNativeCaller", "publicLedgerPreimage", "publicParameter"]);
      baseline ??= actual;
      assert.deepEqual(actual, baseline);
    }
  });
});

test("fixed-prefix private preimages suppress the election guard while public, unrelated and may-alias inputs do not", () => {
  fixture(`
export ledger owner: Bytes<32>;
export ledger publicInput: Bytes<32>;
export ledger candidates: Map<Field, Bytes<32>>;
export ledger stored: Field;
witness allowed(): Boolean;
witness secret(): Bytes<32>;
witness untrustedDigest(): Bytes<32>;
struct Salted { tag: Bytes<32>; parts: Vector<2, Bytes<32>>; }
circuit publicKey(s: Bytes<32>): Bytes<32> {
  return disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "election:pk:"), s]));
}
export circuit electionLike(next: Field): [] {
  assert(!allowed(), "no duplicate");
  assert(publicKey(secret()) == owner, "secret key"); stored = disclose(next);
}
export circuit repeatedNested(next: Field): [] {
  assert(!allowed(), "no duplicate"); const s = secret();
  const payload = Salted { tag: pad(32, "election:pk:"), parts: [s, s] };
  assert(persistentHash<Salted>(payload) == owner, "same secret twice"); stored = disclose(next);
}
export circuit rawOnly(next: Field): [] {
  assert(!allowed(), "no alternate"); stored = disclose(next);
}
export circuit publicBefore(next: Field): [] {
  assert(!allowed(), "no duplicate"); const s = secret();
  assert(s == default<Bytes<32>>, "public preimage");
  assert(publicKey(s) == owner, "known key"); stored = disclose(next);
}
export circuit publicAfter(next: Field, supplied: Bytes<32>): [] {
  assert(!allowed(), "no duplicate");
  assert(publicKey(supplied) == owner, "key"); stored = disclose(next);
  assert(supplied == publicInput, "public on successful completion");
}
export circuit differentSources(next: Field): [] {
  assert(!allowed(), "no duplicate");
  assert(persistentHash<Vector<2, Bytes<32>>>([secret(), secret()]) == owner, "outside single-source rule");
  stored = disclose(next);
}
export circuit uncertainSource(next: Field, key: Field): [] {
  assert(!allowed(), "no duplicate");
  candidates.insert(7 as Field, disclose(secret()));
  assert(key != (7 as Field), "different key");
  assert(publicKey(candidates.lookup(disclose(key))) == owner, "may-alias dependency");
  stored = disclose(next);
}
export circuit unrelatedAnchor(next: Field): [] {
  assert(!allowed(), "no duplicate");
  assert([publicKey(secret()), publicInput] == [untrustedDigest(), publicInput], "not the stored digest");
  stored = disclose(next);
}`, program => {
    let baseline: unknown;
    for (const engine of modes) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      const actual = findings(facts);
      assert.deepEqual([...new Set(actual.map(finding => finding.metadata.entry))].sort(),
        ["differentSources", "publicAfter", "publicBefore", "rawOnly", "uncertainSource", "unrelatedAnchor"]);
      for (const name of ["electionLike", "repeatedNested"]) {
        const path = facts.paths.find(path => program.symbols.get(path.entry)!.name === name)!;
        assert.equal(path.bindings.length, 1, `${name}: legacy bindings share definite aggregate origins`);
      }
      baseline ??= actual;
      assert.deepEqual(actual, baseline);
    }
    let budgetObserved = false;
    for (let limit = 1; limit < 100; limit++) {
      const facts = new Dataflow(program, limit).analyze();
      if (!facts.diagnostics.some(diagnostic => diagnostic.message.startsWith("Private preimage origin traversal"))) continue;
      budgetObserved = true;
      assert.ok(facts.completedEntries.length < program.entries.length);
      const complete = new Set(facts.completedEntries.map(entry => program.symbols.get(entry)!.name));
      assert.ok(spoofableAuthorization.run(facts).every(finding => complete.has(finding.metadata.entry as string)));
      break;
    }
    assert.ok(budgetObserved, "origin work consumes the engine allowance and remains incomplete");
  });
});

test("single-source hash origins bound compact aggregate DAGs and depth without returning partial evidence", () => {
  const source = { id: "secret", kind: "witness" as const, name: "secret", location: { file: "origin.compact", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 } };
  const leaf: AbstractValue = { identity: source.id, flows: [{ source, form: "raw", trace: [] }], ledger: new Set() };
  const constant: AbstractValue = { flows: [], ledger: new Set(), constant: "0", constantKind: "integer" };
  const pair: AbstractValue = { flows: leaf.flows, ledger: new Set(), items: [constant, leaf] };
  assert.equal(directPreimageSource(pair).source, source);
  assert.deepEqual(directPreimageSource(pair, 1), { complete: false, work: 2 });
  let shared = leaf;
  for (let depth = 0; depth < 14; depth++) shared = { flows: leaf.flows, ledger: new Set(), items: [shared, shared] };
  assert.deepEqual(directPreimageSource(shared), { complete: false, work: 4097 });
  let deep = leaf;
  for (let depth = 0; depth < 65; depth++) deep = { flows: leaf.flows, ledger: new Set(), fields: { child: deep } };
  assert.equal(directPreimageSource(deep).complete, false);
  assert.equal(directPreimageSource(deep).source, undefined);
  assert.equal(directPreimageSource({ ...pair, items: [constant, { ...leaf, identity: undefined }] }).source, undefined);
  assert.equal(directPreimageSource({ ...pair, items: [constant, { ...leaf, constant: "0", constantKind: "integer" }] }).source, undefined);
});

test("sole-gate coverage rejects omitted, aggregate, implicit and post-effect checks", () => {
  fixture(`export ledger owner: Field;
export ledger paused: Boolean;
export ledger members: Set<Field>;
export ledger values: Map<Field, Field>;
witness approved(): Boolean;
export circuit raw(next: Field): [] { assert(approved(), "gate"); owner = disclose(next); }
export circuit parameter(next: Field, secret: Field): [] { assert(approved(), "gate"); assert(secret == next, "other"); owner = disclose(next); }
export circuit publicGate(next: Field): [] { assert(approved(), "gate"); assert(!paused, "paused"); owner = disclose(next); }
export circuit checked(next: Field): [] { assert(approved(), "gate"); const small = next as Uint<8>; owner = disclose(small as Field); }
export circuit ordering(next: Uint<8>): [] { assert(approved(), "gate"); assert(next < 100, "range"); owner = disclose(next as Field); }
export circuit aggregate(secret: Uint<8>, next: Field): [] { assert([approved(), secret < 5] == [true, true], "both gates"); owner = disclose(next); }
export circuit aggregatePublic(next: Field): [] { assert([approved(), !paused] == [true, true], "both gates"); owner = disclose(next); }
export circuit membership(next: Field): [] { assert(approved(), "gate"); assert(members.member(disclose(next)), "member"); owner = disclose(next); }
export circuit lookup(next: Field): [] { assert(approved(), "gate"); owner = values.lookup(disclose(next)); }
export circuit later(next: Field, secret: Field): [] { assert(approved(), "gate"); owner = disclose(next); assert(secret == next, "later"); }
`, program => {
    for (const engine of modes) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      const actual = findings(facts);
      assert.equal(actual.length, 10);
      for (const item of actual) {
        const sole = item.metadata.entry === "raw";
        assert.equal(item.severity, sole ? "critical" : "high", String(item.metadata.entry));
        assert.equal(item.metadata.soleGate, sole ? "proven-in-model" : "unproven", String(item.metadata.entry));
      }
      assert.equal(facts.paths.filter(path => path.checkCoverage === "raw-witness-only").length, 1);
      // Third-party/custom facts without the coverage contract cannot certify it.
      for (const path of facts.paths) delete path.checkCoverage;
      assert.ok(findings(facts).every(item => item.severity !== "critical"));
    }
  });
});

test("sole-gate coverage quantifies all histories before nested replay and effect grouping", () => {
  fixture(`export ledger owner: Field;
witness approved(): Boolean;
witness choose(): Boolean;
circuit store(next: Field): [] { owner = disclose(next); }
circuit nested(next: Field): [] { store(next); store(next); }
export circuit mint(next: Field, permit: Boolean): [] {
  assert(approved(), "gate");
  if (disclose(choose())) { assert(permit, "additional permission"); }
  nested(next); nested(next);
}
export circuit grant(next: Field): [] {
  assert(approved(), "gate"); nested(next); nested(next);
}
`, program => {
    for (const engine of modes) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      const actual = findings(facts);
      assert.equal(actual.length, 2);
      assert.deepEqual(actual.map(item => [item.metadata.entry, item.severity, item.metadata.soleGate]), [
        ["mint", "high", "unproven"], ["grant", "critical", "proven-in-model"],
      ]);
      const histories = facts.paths.filter(path => program.symbols.get(path.entry)!.name === "mint");
      assert.deepEqual(histories.map(path => path.checkCoverage).sort(), ["raw-witness-only", "unclassified"]);
      assert.ok(actual.every(item => (item.metadata.affectedEffects as unknown[]).length > 0));
      if (cached) assert.ok(facts.metrics.statefulSummaryHits > 0);
    }
  });
});

test("time-named sole witnesses are not mistaken for protocol validation; real preimage checks correct the gate", () => {
  fixture(`export ledger owner: Field;
export ledger ownerHash: Bytes<32>;
witness witness_blockTimeGte(): Boolean;
witness secret(): Field;
export circuit mint(next: Field): [] { assert(witness_blockTimeGte(), "time"); owner = disclose(next); }
export circuit corrected(next: Field): [] {
  assert(witness_blockTimeGte(), "time");
  assert(persistentHash<Field>(secret()) == ownerHash, "authority");
  owner = disclose(next);
}
`, program => {
    for (const engine of modes) for (const cached of [false, true]) {
      const actual = findings(new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze());
      assert.deepEqual(actual.map(item => [item.metadata.entry, item.severity, item.confidence]), [["mint", "critical", "high"]]);
    }
  });
});

test("unsigned fold underflow remains an implicit gate with fold transfers on or off", () => {
  fixture(`export ledger owner: Uint<8>;
witness approved(): Boolean;
circuit subtract(total: Uint<8>, item: Uint<8>): Uint<8> { return total - item; }
export circuit grantAccess(total: Uint<8>, item: Uint<8>): [] {
  assert(approved(), "approval");
  owner = disclose(fold(subtract, total, [item]));
}
export circuit rejected(total: Uint<8>, item: Uint<8>): [] {
  assert(approved(), "approval");
  assert(total == 0, "seed"); assert(item == 1, "amount");
  owner = disclose(fold(subtract, total, [item]));
}
`, program => {
    for (const engine of modes) for (const cached of [false, true]) for (const optimized of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, optimized).analyze();
      const actual = findings(facts);
      assert.deepEqual(actual.map(item => [item.metadata.entry, item.severity, item.metadata.soleGate]), [["grantAccess", "high", "unproven"]]);
      assert.deepEqual(facts.paths.map(path => [program.symbols.get(path.entry)!.name, path.checkCoverage]), [["grantAccess", "unclassified"]]);
    }
  });
});

test("pure hash fold preserves branch-refined private-preimage authentication", () => {
  fixture(`export ledger owner: Field;
export ledger digest: Bytes<32>;
witness approved(): Boolean;
witness nonce(): Field;
witness secret(): Field;
pure circuit hashChoice(previous: Bytes<32>, x: Field, s: Field, zero: Field): Bytes<32> {
  return x == zero ? persistentHash<[Field,Field]>([x,s]) : persistentHash<[Field,Field]>([s,x]);
}
export circuit grantAccess(next: Field): [] {
  assert(approved(), "approval");
  const x = nonce(); const s = secret();
  const h = fold(hashChoice, default<Bytes<32>>, [x], [s], [0 as Field]);
  assert(x == (0 as Field), "select first");
  assert(h == digest, "authority");
  owner = disclose(next);
}
`, program => {
    let oracle: AnalysisFacts | undefined;
    for (const engine of modes) for (const cached of [false, true]) for (const optimized of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, optimized).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.paths.length, 1);
      assert.equal(facts.paths[0].writes.length, 1);
      assert.deepEqual(findings(facts), []);
      assert.ok(facts.paths[0].predicates?.some(predicate => predicate.value.comparison?.left.directHash?.source.name === "secret"));
      if (oracle) assert.deepEqual(semanticPaths(facts), semanticPaths(oracle));
      else oracle = facts;
    }
  });
});
