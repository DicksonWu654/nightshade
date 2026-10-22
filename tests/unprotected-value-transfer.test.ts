import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { Program, Dataflow, scanFile, type AnalysisFacts } from "../src/index.js";
import type { AbstractValue } from "../src/dataflow/index.js";
import { unprotectedValueTransfer as rule } from "../src/detectors/value-transfer.js";
import { privatePredicateCover } from "../src/dataflow/predicate-cover.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
export ledger owner: Bytes<32>;
export ledger expected: Boolean;
witness secret(): Bytes<32>;
witness flag(): Boolean;
circuit guard(): [] { assert(persistentHash<Bytes<32>>(secret()) == owner, "owner"); }
circuit transferValue(recipient: Either<ContractAddress,UserAddress>): [] { sendUnshielded(default<Bytes<32>>, 1, disclose(recipient)); }
`;
function fixture(source: string, expected: string[], inspect?: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiler = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiler.valid, true, compiler.error);
    }
    const program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all").analyze();
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(findings.map(f => f.metadata.entry).sort(), expected.slice().sort());
      baseline ??= findings; assert.deepEqual(findings, baseline, JSON.stringify({engine,cached}));
      inspect?.(facts);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, {detectors:[rule.id],experimentalCounterQueries});
      assert.equal(scan.status,"complete",JSON.stringify(scan.diagnostics));
      assert.deepEqual(scan.findings.map(f=>f.metadata.entry).sort(), expected.slice().sort());
    }
  });
}

test("transfer controls distinguish stdlib branches, irrelevant if/else, alternate and late application checks", () => {
  fixture(`${header}
export circuit unguarded(recipient: Either<ContractAddress,UserAddress>): [] { transferValue(recipient); }
export circuit corrected(recipient: Either<ContractAddress,UserAddress>): [] { guard(); transferValue(recipient); }
export circuit unrelated(recipient: Either<ContractAddress,UserAddress>, choice: Boolean): [] {
  if (disclose(choice)) { const unused = true; } else { const unused = false; }
  transferValue(recipient);
}
export circuit constrained(recipient: Either<ContractAddress,UserAddress>, choice: Boolean): [] {
  if (disclose(choice)) { transferValue(recipient); }
}
export circuit alternate(recipient: Either<ContractAddress,UserAddress>, choice: Boolean): [] {
  if (disclose(choice)) { guard(); } else { assert(flag(), "alternate"); }
  transferValue(recipient);
}
export circuit disjunction(recipient: Either<ContractAddress,UserAddress>): [] { assert(flag() || flag(), "either"); transferValue(recipient); }
export circuit late(recipient: Either<ContractAddress,UserAddress>): [] { transferValue(recipient); guard(); }
`, ["unguarded","unrelated"]);
});

test("opt-in transfer manifest positive/corrected/lookalike is compiler-valid and default quiet", () => {
  const manifest=JSON.parse(readFileSync("tests/corpus/manifest.json","utf8"));
  for(const row of manifest.valueTransfer.cases) {
    const file=resolve("tests/corpus",row.file);
    fixture(readFileSync(file,"utf8"),row.lines.length?["withdraw"]:[]);
    const scan=scanFile(file,{detectors:[rule.id]});
    assert.equal(scan.status,"complete",JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(f=>f.location.line),row.lines);
    assert.ok(!scanFile(file).findings.some(f=>f.detectorId===rule.id));
  }
});

test("all five token operations retain canonical nested invocation evidence", () => {
  fixture(`${header}
export circuit mintShielded(recipient: Either<ZswapCoinPublicKey,ContractAddress>): ShieldedCoinInfo {
  return mintShieldedToken(default<Bytes<32>>, 3, default<Bytes<32>>, disclose(recipient));
}
export circuit mintUnshielded(recipient: Either<ContractAddress,UserAddress>): Bytes<32> {
  return mintUnshieldedToken(default<Bytes<32>>, 3, disclose(recipient));
}
export circuit sendShieldedValue(coin: QualifiedShieldedCoinInfo, recipient: Either<ZswapCoinPublicKey,ContractAddress>): ShieldedSendResult {
  return sendShielded(disclose(coin), disclose(recipient), 1);
}
export circuit immediateTransfer(coin: ShieldedCoinInfo, recipient: Either<ZswapCoinPublicKey,ContractAddress>): ShieldedSendResult {
  return sendImmediateShielded(disclose(coin), disclose(recipient), 1);
}
export circuit sendUnshieldedValue(recipient: Either<ContractAddress,UserAddress>): [] { transferValue(recipient); }
`, ["mintShielded","mintUnshielded","sendShieldedValue","immediateTransfer","sendUnshieldedValue"],facts=>{
    assert.deepEqual(new Set(rule.run(facts).map(f=>f.metadata.operation)),new Set(["mintShieldedToken","mintUnshieldedToken","sendShielded","sendImmediateShielded","sendUnshielded"]));
  });
});

test("rejected paths cannot seed token operation findings and repeated calls do not count library effects as separate transfers", () => {
  fixture(`${header}
export circuit disabled(recipient: Either<ContractAddress,UserAddress>): [] { transferValue(recipient); assert(false,"disabled"); }
export circuit repeated(recipient: Either<ContractAddress,UserAddress>): [] { transferValue(recipient); transferValue(recipient); }
`, ["repeated"],facts=>{
    const chains=rule.run(facts)[0].metadata.invocationChains as unknown[];
    assert.equal(chains.length,2,"each nested caller chain remains visible");
    assert.notDeepEqual(chains[0],chains[1]);
  });
});

test("public control remains correlated with required private assertions", () => {
  fixture(`${header}
export circuit correlated(recipient: Either<ContractAddress,UserAddress>, choice: Boolean): [] {
  if (expected) { assert(choice, "expected true"); } else { assert(!choice, "expected false"); }
  transferValue(recipient);
}
export circuit partlyPublic(recipient: Either<ContractAddress,UserAddress>): [] {
  if (expected) { guard(); }
  transferValue(recipient);
}
`, ["partlyPublic"]);
});

test("independent public scalar comparisons cannot be combined into an invented unguarded context", () => {
  fixture(`${header}
export ledger state: Uint<8>;
export circuit correlated(recipient: Either<ContractAddress,UserAddress>, choice: Boolean): [] {
  if (disclose(choice)) { assert(state == 1, "public one"); }
  else { assert(state == 2, "public two"); }
  transferValue(recipient);
}`, []);
});

test("repeated witness calls in the same callback remain distinct atoms", () => {
  fixture(`${header}
witness bit(value: Field): Boolean;
export circuit agreement(recipient: Either<ContractAddress,UserAddress>): [] {
  const choices = map(bit, [0 as Field, 1 as Field]);
  if (disclose(choices[0])) { assert(choices[1], "agree"); }
  else { assert(!choices[1], "agree"); }
  transferValue(recipient);
}`, []);
});

test("canonical operation identity excludes a namesake user helper and constructors", () => {
  fixture(`import { ContractAddress, UserAddress, Either } from CompactStandardLibrary;
circuit sendUnshielded(color: Bytes<32>, amount: Uint<128>, recipient: Either<ContractAddress,UserAddress>): [] {}
export circuit namesake(recipient: Either<ContractAddress,UserAddress>): [] { sendUnshielded(default<Bytes<32>>, 1, disclose(recipient)); }
`, []);
  fixture(`${header} constructor() { transferValue(default<Either<ContractAddress,UserAddress>>); }`, []);
});

test("intentional public faucet matches only a low-confidence review without inferred privilege", () => {
  fixture(`${header}
export circuit faucet(recipient: Either<ContractAddress,UserAddress>): [] { transferValue(recipient); }
`, ["faucet"], facts => {
    const finding = rule.run(facts)[0];
    assert.equal(finding.confidence,"low"); assert.equal(finding.metadata.authenticationIntent,"unknown");
    const scan=scanFile(facts.program.root);
    assert.equal(scan.status,"complete",JSON.stringify(scan.diagnostics));
    assert.ok(!scan.coverage.detectors.includes(rule.id));
    assert.deepEqual(scan.findings.filter(f=>f.detectorId===rule.id),[]);
  });
});

test("transfer evidence scopes and query/engine budgets are explicitly incomplete", () => {
  fixture(`${header}
export circuit entry(recipient: Either<ContractAddress,UserAddress>): [] { transferValue(recipient); }
`, ["entry"], facts => {
    assert.equal(privatePredicateCover(facts.paths,1).status,"incomplete");
    const path = facts.paths[0], operation = path.operations![0];
    let value: AbstractValue = { type: "Boolean", flows: [], ledger: new Set(), identity: "selector" };
    for (let index = 0; index < 25; index++) value = { type: "Boolean", flows: [], ledger: new Set(),
      comparison: { operator: "==", left: value, right: { type: "Boolean", flows: [], ledger: new Set(), identity: `other${index}` } } };
    const nested = { ...path, predicates: [{ value, truth: true, location: operation.location, callPath: [path.entry], callSites: [], writesBefore: 0, operationsBefore: 0 }] };
    assert.equal(privatePredicateCover([nested]).status, "incomplete", "nested key expansion has its own bound before query recursion");
    const missing = new Dataflow(facts.program).analyze();
    assert.deepEqual(rule.run(missing),[]);
    assert.ok(missing.diagnostics.some(d=>d.code==="predicate-evidence-unavailable"));
    const bounded=new Dataflow(facts.program,1,256,50000,"instructions",true,true,"equivalent-states",false,true,"all").analyze();
    assert.deepEqual(rule.run(bounded),[]);assert.ok(bounded.diagnostics.length>0);
  });
});

test("path-refined recipient checks retain application correlation across transfer ordering", () => {
  let histories: string[] | undefined;
  fixture(`import CompactStandardLibrary;
circuit transferValue(recipient: Either<ContractAddress,UserAddress>): [] {
  sendUnshielded(default<Bytes<32>>, 1, disclose(recipient));
}
export circuit early(recipient: Either<ContractAddress,UserAddress>, choice: Boolean): [] {
  if (disclose(recipient.is_left)) { assert(choice, "contract choice"); }
  else { assert(!choice, "user choice"); }
  transferValue(recipient);
}
export circuit late(recipient: Either<ContractAddress,UserAddress>, choice: Boolean): [] {
  transferValue(recipient);
  if (disclose(recipient.is_left)) { assert(choice, "contract choice"); }
  else { assert(!choice, "user choice"); }
}

export circuit lateAlias(recipient: Either<ContractAddress,UserAddress>, choice: Boolean): [] {
  transferValue(recipient);
  if (disclose(recipient.is_left == true)) { assert(choice, "contract choice"); }
  else { assert(!choice, "user choice"); }
}
export circuit lateNegated(recipient: Either<ContractAddress,UserAddress>, choice: Boolean): [] {
  transferValue(recipient);
  if (disclose(!recipient.is_left)) { assert(!choice, "user choice"); }
  else { assert(choice, "contract choice"); }
}
export circuit irrelevant(recipient: Either<ContractAddress,UserAddress>): [] {
  transferValue(recipient);
  if (disclose(recipient.is_left)) { const unused = true; }
  else { const unused = false; }
}
export circuit irrelevantAlias(recipient: Either<ContractAddress,UserAddress>): [] {
  transferValue(recipient);
  if (disclose(recipient.is_left == false)) { const unused = true; }
  else { const unused = false; }
}
export circuit tautology(recipient: Either<ContractAddress,UserAddress>, choice: Boolean): [] {
  transferValue(recipient);
  assert(choice == choice, "always true");
  assert(recipient.is_left == recipient.is_left, "refined tautology");
  assert(true, "literal true");
}
`, ["irrelevant", "irrelevantAlias", "tautology"], facts => {
    const observed = semanticPaths(facts);
    histories ??= observed;
    assert.deepEqual(observed, histories, "complete histories, effects and predicate provenance agree in all four modes");
    for (const path of facts.paths.filter(path => facts.program.symbols.get(path.entry)!.name === "late")) {
      assert.ok(path.predicates!.some(predicate => predicate.callPath.at(-1) === path.entry
        && predicate.value.constantKind === "boolean" && predicate.value.identity
        && predicate.value.flows.some(flow => flow.source.name === "recipient")),
      "the late application selector remains visible even after the library refined it");
    }
  });
});

test("nested Boolean comparison operands retain immutable identities after library refinement", () => {
  let histories: string[] | undefined;
  fixture(`import CompactStandardLibrary;
circuit transferValue(recipient: Either<ContractAddress,UserAddress>): [] {
  sendUnshielded(default<Bytes<32>>, 1, disclose(recipient));
}
export circuit earlyWrapped(first: Either<ContractAddress,UserAddress>, second: Either<ContractAddress,UserAddress>): [] {
  assert((first.is_left == true) == (second.is_left == true), "same recipient kind");
  transferValue(first); transferValue(second);
}
export circuit lateDirect(first: Either<ContractAddress,UserAddress>, second: Either<ContractAddress,UserAddress>): [] {
  transferValue(first); transferValue(second);
  assert(first.is_left == second.is_left, "same recipient kind");
}
export circuit lateWrapped(first: Either<ContractAddress,UserAddress>, second: Either<ContractAddress,UserAddress>): [] {
  transferValue(first); transferValue(second);
  assert((first.is_left == true) == (second.is_left == true), "same recipient kind");
}
export circuit lateNegated(first: Either<ContractAddress,UserAddress>, second: Either<ContractAddress,UserAddress>): [] {
  transferValue(first); transferValue(second);
  assert((!first.is_left) == (!second.is_left), "same recipient kind");
}
export circuit unrelated(first: Either<ContractAddress,UserAddress>, second: Either<ContractAddress,UserAddress>): [] {
  transferValue(first); transferValue(second);
}
export circuit tautology(first: Either<ContractAddress,UserAddress>, second: Either<ContractAddress,UserAddress>): [] {
  transferValue(first); transferValue(second);
  assert(first.is_left == (first.is_left == true), "identity alias");
  assert((first.is_left != false) == (first.is_left == true), "equivalent aliases");
}
`, ["unrelated", "tautology"], facts => {
    const observed = semanticPaths(facts);
    histories ??= observed;
    assert.deepEqual(observed, histories);
  });
});
