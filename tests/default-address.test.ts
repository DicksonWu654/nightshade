import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { successfulConstants } from "../src/dataflow/successful-constants.js";
import { Dataflow } from "../src/dataflow/index.js";
import { defaultRecipientOrOwner as rule } from "../src/detectors/default-address.js";
import { hasDefaultAddressEffects } from "../src/semantic/default-address-targets.js";
import { Program } from "../src/semantic/index.js";
import { scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function check(source: string, expected: string[], searchPaths: string[] = []) {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file, searchPaths);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all").analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts).sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
      assert.deepEqual(findings.map(item => item.metadata.entry).sort(), [...expected].sort());
      const repeated = findings.find(item => item.metadata.entry === "repeated");
      if (repeated) assert.equal((repeated.metadata.invocationSites as unknown[]).length, 2);
      baseline ??= findings;
      assert.deepEqual(findings, baseline);
    }
    const scan = scanFile(file, { detectors: [rule.id], searchPaths });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual([...scan.findings].sort((left, right) => left.fingerprint.localeCompare(right.fingerprint)), baseline);
    return program;
  });
}

const header = "import CompactStandardLibrary;\n";
test("default recipient uses selected address, amount and successful history, not inactive payloads", () => check(header + `
export circuit zeroUser(): [] { sendUnshielded(default<Bytes<32>>, 1, right<ContractAddress,UserAddress>(default<UserAddress>)); }
export circuit zeroContract(): [] { sendUnshielded(default<Bytes<32>>, 1, left<ContractAddress,UserAddress>(default<ContractAddress>)); }
export circuit wholeDefault(): [] { sendUnshielded(default<Bytes<32>>, 1, default<Either<ContractAddress,UserAddress>>); }
export circuit validUser(recipient: UserAddress): [] {
  assert(recipient.bytes != default<Bytes<32>>, "valid");
  sendUnshielded(default<Bytes<32>>, 1, right<ContractAddress,UserAddress>(disclose(recipient)));
}
export circuit validContract(recipient: ContractAddress): [] {
  assert(recipient.bytes != default<Bytes<32>>, "valid");
  sendUnshielded(default<Bytes<32>>, 1, left<ContractAddress,UserAddress>(disclose(recipient)));
}
export circuit zeroAmount(): [] { sendUnshielded(default<Bytes<32>>, 0, default<Either<ContractAddress,UserAddress>>); }
export circuit abortsLater(): [] { sendUnshielded(default<Bytes<32>>, 1, default<Either<ContractAddress,UserAddress>>); assert(false,"revert"); }
`, ["zeroUser", "zeroContract", "wholeDefault"]));

test("callee aliases, repeated helper sites and value-preserving snapshots retain default recipient facts", () => check(header + `
export ledger target: Either<ContractAddress,UserAddress>;
circuit helper(recipient: Either<ContractAddress,UserAddress>): [] { sendUnshielded(default<Bytes<32>>, 1, disclose(recipient)); }
export circuit nested(): [] { helper(default<Either<ContractAddress,UserAddress>>); }
export circuit repeated(): [] { helper(default<Either<ContractAddress,UserAddress>>); helper(default<Either<ContractAddress,UserAddress>>); }
export circuit snapshot(): [] {
  target = default<Either<ContractAddress,UserAddress>>;
  const saved = target;
  target = right<ContractAddress,UserAddress>(UserAddress { bytes: pad(32,"valid") });
  helper(saved);
}
export circuit updated(): [] {
  target = default<Either<ContractAddress,UserAddress>>;
  target = right<ContractAddress,UserAddress>(UserAddress { bytes: pad(32,"valid") });
  helper(target);
}
`, ["nested", "repeated", "snapshot"]));

test("branch correlation and direct kernel/native output observations stay aligned", () => check(header + `
export circuit branch(flag: Boolean): [] {
  const recipient = disclose(flag) ? default<Either<ContractAddress,UserAddress>>
    : right<ContractAddress,UserAddress>(UserAddress { bytes: pad(32,"valid") });
  sendUnshielded(default<Bytes<32>>, 1, recipient);
}
export circuit directKernel(): [] {
  kernel.claimUnshieldedCoinSpend(left<Bytes<32>,Bytes<32>>(default<Bytes<32>>), default<Either<ContractAddress,UserAddress>>, 1);
}
export circuit directNative(): [] {
  createZswapOutput(ShieldedCoinInfo { nonce: default<Bytes<32>>, color: default<Bytes<32>>, value: 1 }, default<Either<ZswapCoinPublicKey,ContractAddress>>);
}
`, ["branch", "directKernel", "directNative"]));

test("explicit shielded burns are a retained intentional match: the review rule remains opt-in", () => {
  check(header + `export circuit burn(): [] { mintShieldedToken(default<Bytes<32>>, 1, default<Bytes<32>>, shieldedBurnAddress()); }`, ["burn"]);
  assert.equal(rule.defaultEnabled, false);
});

test("application namesakes and ordinary zero ledger sentinels do not create destination findings", () => check(header + `
export ledger owner: Either<Bytes<32>,ContractAddress>;
constructor() { owner = default<Either<Bytes<32>,ContractAddress>>; }
module Fake { export circuit sendUnshielded(): [] {} }
import Fake prefix F_;
export circuit harmless(): [] { F_sendUnshielded(); owner = default<Either<Bytes<32>,ContractAddress>>; }
`, []));

const oz = process.env.OZ_COMPACT_TEST;
test("authenticated Ownable zero updates report; canonical renunciation and overwritten zero updates stay quiet", { skip: !oz }, () => check(header + `
import "access/Ownable" prefix O_;
constructor() { O_initialize(left<Bytes<32>,ContractAddress>(pad(32,"owner"))); }
export circuit accidental(): [] { O__unsafeUncheckedTransferOwnership(left<Bytes<32>,ContractAddress>(default<Bytes<32>>)); }
export circuit safe(ownerId: Bytes<32>): [] {
  assert(ownerId != default<Bytes<32>>,"owner");
  O__unsafeUncheckedTransferOwnership(left<Bytes<32>,ContractAddress>(disclose(ownerId)));
}
export circuit restored(): [] {
  O__unsafeUncheckedTransferOwnership(left<Bytes<32>,ContractAddress>(default<Bytes<32>>));
  O__unsafeUncheckedTransferOwnership(left<Bytes<32>,ContractAddress>(pad(32,"owner")));
}
export circuit renounce(): [] { O_renounceOwnership(); }
`, ["accidental"], [resolve(oz!, "contracts/src")]));

test("applicability includes direct kernel effects and cannot certify absence after exhaustion", () => {
  withFiles({ "main.compact": header + `export circuit direct(): [] {
    kernel.claimUnshieldedCoinSpend(left<Bytes<32>,Bytes<32>>(default<Bytes<32>>), default<Either<ContractAddress,UserAddress>>, 1);
  }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    assert.equal(hasDefaultAddressEffects(program, program.entries[0]), true);
    assert.equal(hasDefaultAddressEffects(program, program.entries[0], 0), true);
  });
});

test("changed Ownable dependencies cannot acquire the pinned owner's identity", { skip: !oz }, () => {
  const source = header + `import "access/Ownable" prefix O_;
export circuit accidental(): [] { O__unsafeUncheckedTransferOwnership(left<Bytes<32>,ContractAddress>(default<Bytes<32>>)); }`;
  withFiles({
    "main.compact": source,
    "access/Ownable.compact": readFileSync(resolve(oz!, "contracts/src/access/Ownable.compact"), "utf8"),
    "utils/Utils.compact": readFileSync(resolve(oz!, "contracts/src/utils/Utils.compact"), "utf8") + "\n// owned dependency variant\n",
  }, directory => {
    const file = resolve(directory, "main.compact"), paths = [directory];
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, paths);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const scan = scanFile(file, { detectors: [rule.id], searchPaths: paths });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings, []);
  });
});

test("aggregate leaf constraints and later atomic guards refine recipient and amount snapshots", () => check(header + `
export circuit addressEarly(recipient: Either<ContractAddress,UserAddress>): [] {
  assert(recipient.is_left,"left"); assert(recipient.left.bytes == default<Bytes<32>>,"zero");
  sendUnshielded(default<Bytes<32>>,1,disclose(recipient));
}
export circuit addressLate(recipient: Either<ContractAddress,UserAddress>): [] {
  sendUnshielded(default<Bytes<32>>,1,disclose(recipient));
  assert(recipient.is_left,"left"); assert(recipient.left.bytes == default<Bytes<32>>,"zero");
}
export circuit scalarAmountEarly(amount: Uint<64>): [] {
  assert(amount == 0,"zero"); sendUnshielded(default<Bytes<32>>,disclose(amount),default<Either<ContractAddress,UserAddress>>);
}
export circuit scalarAmountLate(amount: Uint<64>): [] {
  sendUnshielded(default<Bytes<32>>,disclose(amount),default<Either<ContractAddress,UserAddress>>); assert(amount == 0,"zero");
}
export circuit nativeAmountEarly(coin: ShieldedCoinInfo): [] {
  assert(coin.value == 0,"zero"); createZswapOutput(disclose(coin),default<Either<ZswapCoinPublicKey,ContractAddress>>);
}
export circuit nativeAmountLate(coin: ShieldedCoinInfo): [] {
  createZswapOutput(disclose(coin),default<Either<ZswapCoinPublicKey,ContractAddress>>); assert(coin.value == 0,"zero");
}
`, ["addressEarly", "addressLate"]));

test("later ledger revisions cannot constrain a previously saved recipient", () => check(header + `
export ledger recipient: UserAddress;
export circuit differentRevision(): [] {
  const saved = recipient;
  sendUnshielded(default<Bytes<32>>,1,right<ContractAddress,UserAddress>(saved));
  recipient = default<UserAddress>;
  assert(recipient.bytes == default<Bytes<32>>,"current zero");
}
export circuit previousZero(): [] {
  recipient = default<UserAddress>;
  const saved = recipient;
  recipient = UserAddress { bytes: pad(32,"new") };
  sendUnshielded(default<Bytes<32>>,1,right<ContractAddress,UserAddress>(saved));
  assert(recipient.bytes != default<Bytes<32>>,"current nonzero");
}
`, ["previousZero"]));

test("direct writes to authenticated exported owner storage are applicable", { skip: !oz }, () => check(header + `
import "access/Ownable" prefix O_;
constructor() { O_initialize(left<Bytes<32>,ContractAddress>(pad(32,"owner"))); }
export circuit directOwner(): [] { O__owner = default<Either<Bytes<32>,ContractAddress>>; }
`, ["directOwner"], [resolve(oz!, "contracts/src")]));

test("successful constant projection never borrows wildcard identity or another history and budgets stay incomplete", () => {
  const empty = { flows: [], ledger: new Set<string>() };
  const unknown = { ...empty, identity: "same-path-text", region: { root: "ledger", path: ["*"], type: "Uint<64>" }, type: "Uint<64>" };
  const zero = { ...empty, constantKind: "integer" as const, constant: "0", type: "Uint<64>" };
  const value = { ...empty, type: "Boolean", comparison: { operator: "==", left: unknown, right: zero } };
  const path = { entry: "entry", bindings: [], sinks: [], path: [], writes: [], predicates: [{ value, truth: true,
    location: { file: "owned", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 }, callPath: [], callSites: [], writesBefore: 0, operationsBefore: 0 }] };
  const constrained = successfulConstants(path);
  assert.equal(constrained.refine(unknown).constant, undefined);
  assert.equal(constrained.complete, true);
  const ordinary = { ...empty, identity: "entry-value", type: "Uint<64>" };
  const first = successfulConstants({ ...path, predicates: [{ ...path.predicates[0], value: { ...value, comparison: { operator: "==", left: ordinary, right: zero } } }] });
  assert.equal(first.refine(ordinary).constant, "0");
  assert.equal(successfulConstants({ ...path, predicates: [] }).refine(ordinary).constant, undefined);
  assert.equal(successfulConstants(path, 0).complete, false);
  assert.equal(successfulConstants({ ...path, predicates: undefined }).complete, false);
});

test("programs without destination effects need no extra predicate evidence", () => {
  withFiles({ "main.compact": header + "export ledger items: List<Field>; export circuit empty(): Boolean { return items.isEmpty(); }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(facts), []);
    assert.deepEqual(facts.diagnostics, []);
  });
});
