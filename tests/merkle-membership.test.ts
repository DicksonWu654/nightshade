import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import type { PrivateSource } from "../src/dataflow/index.js";
import { merkleMembershipNotEnforced as rule } from "../src/detectors/merkle-membership.js";
import { enforcedMerkleDigests } from "../src/dataflow/merkle-enforcement.js";
import { immutableOperandKey } from "../src/dataflow/immutable-key.js";
import { equalityDependencies } from "../src/dataflow/equality-dependencies.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
ledger tree: MerkleTree<2,Field>;
ledger history: HistoricMerkleTree<2,Field>;
ledger expected: Field;
export ledger accepted: Field;
witness suppliedPath(): MerkleTreePath<2,Field>;
witness suppliedDigest(): MerkleTreeDigest;
circuit root(proof: MerkleTreePath<2,Field>): MerkleTreeDigest { return merkleTreePathRoot<2,Field>(proof); }
`;

test("owned membership-lifecycle equality relates nullifier insertion to the observed path input", () => {
  for (const kind of ["positive", "corrected", "lookalike"]) {
    fixture(readFileSync(`tests/corpus/synthetic-regressions/state16/merkle-membership-not-enforced-case-36-${kind}.compact`, "utf8"), kind === "positive" ? ["renounce"] : [], facts => {
      if (kind !== "positive") return;
      for (const key of ["operations", "predicates"] as const) {
        const missing: AnalysisFacts = { ...facts, diagnostics: [], paths: facts.paths.map(path => ({ ...path, [key]: undefined })) };
        assert.deepEqual(rule.run(missing), []);
        assert.ok(missing.diagnostics.some(item => item.code === "predicate-analysis-budget"), key);
      }
    });
  }
});

test("complete owned membership-lifecycle byte lifecycle reports the independently reviewed root site", () => {
  for (const kind of ["positive", "corrected", "lookalike"]) {
    fixture(readFileSync(`tests/corpus/drafts/state39/membership-lifecycle-byte/membership-lifecycle-byte-${kind}.compact`, "utf8"),
      kind === "positive" ? ["renounceRole"] : [], facts => {
        assert.deepEqual(rule.run(facts).map(finding => finding.location.line), kind === "positive" ? [38] : []);
      });
  }
});

test("equality-derived Merkle dependencies require a prior exact required relation", () => {
  const prefix = `import CompactStandardLibrary;
ledger tree: MerkleTree<2,Field>;
export ledger accepted: Bytes<32>;
witness proofFor(input: Bytes<32>): MerkleTreePath<2,Bytes<32>>;
`;
  const body = `const proof = proofFor(input); const digest = merkleTreePathRootNoLeafHash<2>(proof);`;
  fixture(`${prefix}
export circuit related(input: Bytes<32>, output: Bytes<32>): [] {
 ${body} assert(output == persistentHash<Bytes<32>>(input), "required"); accepted = disclose(output);
}
export circuit unrelated(input: Bytes<32>, other: Bytes<32>, output: Bytes<32>): [] {
 ${body} assert(output == persistentHash<Bytes<32>>(other), "unrelated"); accepted = disclose(output);
}
export circuit disjunctive(input: Bytes<32>, output: Bytes<32>): [] {
 ${body} assert(true || output == persistentHash<Bytes<32>>(input), "optional"); accepted = disclose(output);
}
export circuit after(input: Bytes<32>, output: Bytes<32>): [] {
 ${body} accepted = disclose(output); assert(output == persistentHash<Bytes<32>>(input), "late");
}`, ["related"]);
});

test("equality dependency exhaustion is explicit and never returns partial evidence", () => {
  const source = { id: "input", kind: "entry-parameter" as const, name: "input", location: { file: "test", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 } };
  const value = { type: "Field", identity: source.id, flows: [{ source, form: "raw" as const, trace: [] }], ledger: new Set<string>() };
  const result = equalityDependencies(value, [], flow => flow.source.id, 0);
  assert.equal(result.complete, false);
  assert.deepEqual([...result.dependencies], []);
  assert.ok(result.work > 0);
});

test("ordinary equality-only histories with no native operations preserve original provenance", () => {
  fixture(`${header}
export circuit ordinary(a: Field, b: Field): [] {
 assert(a == b, "matches"); accepted = disclose(a);
}
export circuit proof(): [] {
 const p = suppliedPath(); const digest = root(p); accepted = disclose(p.leaf);
}`, ["proof"], facts => {
    const ordinary = facts.paths.find(path => facts.program.symbols.get(path.entry)!.name === "ordinary")!;
    assert.equal(ordinary.operations, undefined);
    assert.ok(ordinary.predicates?.every(predicate => predicate.operationsBefore === 0));
  });
});
// Branching callback evaluation may allocate witness numbers in a different
// exploration order. Rename those numbers by the full dynamic invocation, then
// rebuild digest names from exact renamed operands. Preserve every other path
// property, including provenance, predicates, revisions and ordered effects.
function alphaMerklePaths(facts: AnalysisFacts): string[] {
  return semanticPaths(facts).map(serialized => {
    const path = JSON.parse(serialized), identities = new Map<string, string>();
    const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
    const collect = (value: unknown): void => {
      if (!value || typeof value !== "object") return;
      const source = (value as { source?: PrivateSource }).source;
      if (source?.invocation) identities.set(source.id, `witness:${hash(source.invocation)}`);
      for (const child of Object.values(value)) collect(child);
    };
    collect(path);
    assert.equal(new Set(identities.values()).size, identities.size, "renaming must not merge distinct witness instances");
    const normalize = (value: unknown): unknown => {
      if (typeof value === "string") {
        let text = value;
        for (const [from, to] of [...identities].sort(([a], [b]) => b.length - a.length)) text = text.replaceAll(from, to);
        return text;
      }
      if (Array.isArray(value)) return value.map(normalize);
      return value && typeof value === "object" ? Object.fromEntries(Object.entries(value).map(([key, child]) => [key, normalize(child)])) : value;
    };
    for (const operation of path.operations ?? []) if (operation.kind === "merkle-root") {
      const operand = immutableOperandKey(normalize(operation.args[0]) as Parameters<typeof immutableOperandKey>[0]);
      assert.ok(operand.complete && operand.key);
      identities.set(operation.result.fields.field.identity, `digest:${hash([operation.name, operand.key])}`);
    }
    return JSON.stringify(normalize(path));
  }).sort();
}

function fixture(source: string, expected: string[], inspect?: (facts: AnalysisFacts) => void, historyView = semanticPaths): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    const program = new Program(file);
    let baseline: string[] | undefined, findings: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all-private", true).analyze();
      const actual = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual([...new Set(actual.map(f => f.metadata.entry))].sort(), expected.slice().sort());
      findings ??= actual; assert.deepEqual(actual, findings);
      const paths = historyView(facts); baseline ??= paths; assert.deepEqual(paths, baseline);
      inspect?.(facts);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.deepEqual([...new Set(scan.findings.map(f => f.metadata.entry))].sort(), expected.slice().sort());
    }
  });
}

test("computed roots require enforcement, not merely computation or a discarded check", () => {
  fixture(`${header}
export circuit unchecked(): [] {
  const proof = suppliedPath(); const digest = root(proof); accepted = disclose(proof.leaf);
}
export circuit ignored(): [] {
  const proof = suppliedPath(); const digest = root(proof); tree.checkRoot(disclose(digest)); accepted = disclose(proof.leaf);
}
export circuit checked(): [] {
  const proof = suppliedPath(); const digest = root(proof); assert(tree.checkRoot(disclose(digest)), "member"); accepted = disclose(proof.leaf);
}
export circuit late(): [] {
  const proof = suppliedPath(); const digest = root(proof); accepted = disclose(proof.leaf); assert(history.checkRoot(disclose(digest)), "member");
}
export circuit wrongRoot(): [] {
  const proof = suppliedPath(); const digest = root(proof); assert(tree.checkRoot(disclose(suppliedDigest())), "other"); accepted = disclose(proof.leaf);
}
export circuit rootOnly(): MerkleTreeDigest { return disclose(root(suppliedPath())); }
`, ["unchecked", "ignored", "wrongRoot"]);
});

test("exact root identities survive repeat computation and differ for separate witness invocations", () => {
  fixture(`${header}
export circuit repeated(): [] {
  const proof = suppliedPath(); const a = root(proof); const b = root(proof);
  assert(tree.checkRoot(disclose(a)), "member"); accepted = disclose(proof.leaf);
}
export circuit different(): [] {
  const first = suppliedPath(); const second = suppliedPath();
  const a = root(first); const b = root(second);
  assert(tree.checkRoot(disclose(a)), "first member"); accepted = disclose(second.leaf);
}
`, ["different"], facts => {
    for (const path of facts.paths.filter(path => path.entry.endsWith("::repeated"))) {
      const roots = path.operations!.filter(operation => operation.kind === "merkle-root");
      assert.equal(roots.length, 2);
      assert.equal(roots[0].result.fields!.field.identity, roots[1].result.fields!.field.identity);
      assert.notDeepEqual(roots[0].callSites, roots[1].callSites);
    }
  });
});

test("Boolean aliases, alternate trees and transitive equality enforce the exact trusted root", () => {
  fixture(`${header}
export circuit aliases(): [] {
  const proof = suppliedPath(); const digest = root(proof);
  assert(!(tree.checkRoot(disclose(digest)) == false), "member"); accepted = disclose(proof.leaf);
}
export circuit alternate(choice: Boolean): [] {
  const proof = suppliedPath(); const digest = root(proof);
  if (disclose(choice)) { assert(tree.checkRoot(disclose(digest)), "current"); }
  else { assert(history.checkRoot(disclose(digest)), "historic"); }
  accepted = disclose(proof.leaf);
}
export circuit transitive(): [] {
  const proof = suppliedPath(); const digest = root(proof); const alias = suppliedDigest();
  assert(digest.field == alias.field, "equal"); assert(alias.field == expected, "trusted"); accepted = disclose(proof.leaf);
}
export circuit negative(): [] {
  const proof = suppliedPath(); const digest = root(proof); assert(!tree.checkRoot(disclose(digest)), "absent"); accepted = disclose(proof.leaf);
}
`, ["negative"]);
});

test("supplied canonical digests differ from lookalike structs and self-written roots", () => {
  fixture(`${header}
struct DigestLookalike { field: Field; }
witness lookalike(): DigestLookalike;
export circuit unchecked(): [] { const digest = suppliedDigest(); accepted = disclose(digest.field); }
export circuit corrected(): [] { const digest = suppliedDigest(); assert(digest.field == expected, "trusted"); accepted = disclose(digest.field); }
export circuit parameter(digest: MerkleTreeDigest): [] { accepted = disclose(digest.field); }
export circuit namesake(): [] { accepted = disclose(lookalike().field); }
export circuit selfWritten(): [] {
  const proof = suppliedPath(); const digest = root(proof); expected = disclose(digest.field);
  assert(digest.field == expected, "self written"); accepted = disclose(proof.leaf);
}
`, ["unchecked", "parameter", "selfWritten"]);
});

test("NoLeafHash, stored snapshots and state changes retain the original proof obligation", () => {
  fixture(`${header}
export ledger acceptedBytes: Bytes<32>;
witness hashedPath(): MerkleTreePath<2,Bytes<32>>;
export circuit unchecked(): [] { const proof = hashedPath(); const digest = merkleTreePathRootNoLeafHash<2>(proof); acceptedBytes = disclose(proof.leaf); }
export circuit corrected(): [] { const proof = hashedPath(); const digest = merkleTreePathRootNoLeafHash<2>(proof); assert(tree.checkRoot(disclose(digest)), "member"); acceptedBytes = disclose(proof.leaf); }
export circuit saved(): [] {
  const before = expected; const proof = suppliedPath(); const digest = root(proof);
  expected = 0 as Field; assert(digest.field == before, "preexisting"); accepted = disclose(proof.leaf);
}
export circuit priorMembership(): [] {
  const proof = suppliedPath(); const digest = root(proof);
  assert(history.checkRoot(disclose(digest)), "historic member"); history.insert(7 as Field); accepted = disclose(proof.leaf);
}
`, ["unchecked"]);
});

test("Merkle observation and predicate budgets are explicit", () => {
  fixture(`${header} export circuit entry(): [] { const proof = suppliedPath(); const digest = root(proof); accepted = disclose(proof.leaf); }`, ["entry"], facts => {
    assert.equal(enforcedMerkleDigests(facts.paths[0], 0).complete, false);
    const operation = facts.paths[0].operations!.find(operation => operation.kind === "merkle-root")!;
    assert.equal(immutableOperandKey(operation.args[0], 1).complete, false);
    const missing = new Dataflow(facts.program).analyze();
    assert.deepEqual(rule.run(missing), []);
    assert.ok(missing.diagnostics.some(diagnostic => diagnostic.code === "predicate-evidence-unavailable"));
    const limited = scanFile(facts.program.root, { detectors: [rule.id], maxSteps: 1 });
    assert.equal(limited.status, "incomplete"); assert.ok(limited.diagnostics.length > 0);
  });
});

test("Merkle manifest positive/corrected/lookalike cases are compiler-valid", () => {
  const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8"));
  for (const row of manifest.merkleMembership.cases) {
    const file = resolve("tests/corpus", row.file);
    fixture(readFileSync(file, "utf8"), row.lines.length ? ["accept"] : []);
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.deepEqual(scan.findings.map(finding => finding.location.line), row.lines);
  }
});

test("a deep membership alias exhausts evidence explicitly and discards earlier rule findings", () => {
  const deep = "!(".repeat(66) + "tree.checkRoot(disclose(digest))" + ")".repeat(66);
  withFiles({ "main.compact": `${header}
export circuit firstUnenforced(): [] { const proof = suppliedPath(); const digest = root(proof); accepted = disclose(proof.leaf); }
export circuit deepCheck(): [] {
  const proof = suppliedPath(); const digest = root(proof); accepted = disclose(proof.leaf); assert(${deep}, "deep alias");
}` }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all-private", true).analyze();
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.equal(facts.diagnostics.length, 0);
      assert.equal(rule.run(facts).length, 0);
      assert.deepEqual(facts.diagnostics.map(diagnostic => diagnostic.code), ["predicate-analysis-budget"]);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "incomplete");
      assert.deepEqual(result.findings, []);
      assert.deepEqual(result.diagnostics.map(diagnostic => diagnostic.code), ["predicate-analysis-budget"]);
    }
  });
});

test("membership trust is frozen at the queried revision and proof dependencies include private path nodes", () => {
  fixture(`import CompactStandardLibrary;
ledger tree: MerkleTree<2,Field>;
ledger history: HistoricMerkleTree<2,Field>;
ledger expected: Field;
export ledger accepted: Field;
witness suppliedPath(): MerkleTreePath<2,Field>;
witness suppliedDigest(): MerkleTreeDigest;
struct WrappedDigest { digest: MerkleTreeDigest; }
witness wrapped(): WrappedDigest;
circuit root(proof: MerkleTreePath<2,Field>): MerkleTreeDigest { return merkleTreePathRoot<2,Field>(proof); }
export circuit beforeMutation(): [] {
  const proof = suppliedPath(); const digest = root(proof);
  assert(tree.checkRoot(disclose(digest)), "preexisting member");
  tree.insert(disclose(proof.leaf)); accepted = disclose(proof.leaf);
}
export circuit afterMutation(): [] {
  const proof = suppliedPath(); const digest = root(proof);
  tree.insert(disclose(proof.leaf));
  assert(tree.checkRoot(disclose(digest)), "post-insert member"); accepted = disclose(proof.leaf);
}
export circuit historicAfterMutation(): [] {
  const proof = suppliedPath(); const digest = root(proof);
  history.insert(disclose(proof.leaf));
  assert(history.checkRoot(disclose(digest)), "post-insert historic member"); accepted = disclose(proof.leaf);
}
export circuit resetThenMutation(): [] {
  const proof = suppliedPath(); const digest = root(proof);
  tree.resetToDefault(); tree.insert(disclose(proof.leaf));
  assert(tree.checkRoot(disclose(digest)), "self-created member"); accepted = disclose(proof.leaf);
}
export circuit fullPrivateRoot(): [] {
  const proof = suppliedPath(); const digest = root(proof); accepted = disclose(digest.field);
}
export circuit publicLeafRoot(): [] {
  const supplied = suppliedPath();
  const proof = MerkleTreePath<2,Field>{leaf: 0 as Field, path: supplied.path};
  const digest = root(proof); accepted = disclose(digest.field);
}
export circuit publicLeafChecked(): [] {
  const supplied = suppliedPath();
  const proof = MerkleTreePath<2,Field>{leaf: 0 as Field, path: supplied.path};
  const digest = root(proof); assert(tree.checkRoot(disclose(digest)), "member"); accepted = disclose(digest.field);
}
export circuit wrappedUnchecked(): [] { const supplied = wrapped(); accepted = disclose(supplied.digest.field); }
export circuit wrappedChecked(): [] { const supplied = wrapped(); assert(supplied.digest.field == expected, "trusted"); accepted = disclose(supplied.digest.field); }
export circuit directUnchecked(): [] { const supplied = suppliedDigest(); accepted = disclose(supplied.field); }
`, ["afterMutation", "historicAfterMutation", "resetThenMutation", "fullPrivateRoot", "publicLeafRoot", "wrappedUnchecked", "directUnchecked"]);
});

test("standalone nested canonical digest inputs remain applicable without unrelated Merkle calls", () => {
  fixture(`import CompactStandardLibrary;
struct WrappedDigest { digest: MerkleTreeDigest; }
witness wrapped(): WrappedDigest;
export ledger accepted: Field;
export circuit witnessEntry(): [] { accepted = disclose(wrapped().digest.field); }
export circuit parameterEntry(input: WrappedDigest): [] { accepted = disclose(input.digest.field); }
`, ["witnessEntry", "parameterEntry"]);
});

test("a required dynamic-tree query uses its own snapshot without equating other keys or revisions", () => {
  fixture(`${header}
ledger trees: Map<Field,MerkleTree<2,Field>>;
export circuit dynamicChecked(key: Field): [] {
  const proof = suppliedPath(); const digest = root(proof);
  assert(trees.lookup(disclose(key)).checkRoot(disclose(digest)), "member"); accepted = disclose(proof.leaf);
}
export circuit dynamicWrong(key: Field): [] {
  const proof = suppliedPath(); const digest = root(proof);
  assert(trees.lookup(disclose(key)).checkRoot(disclose(suppliedDigest())), "other"); accepted = disclose(proof.leaf);
}
export circuit dynamicLate(key: Field): [] {
  const proof = suppliedPath(); const digest = root(proof);
  const member = trees.lookup(disclose(key)).checkRoot(disclose(digest));
  trees.lookup(1 as Field).insert(7 as Field);
  accepted = disclose(proof.leaf); assert(member, "snapshot");
}
export circuit mayAlias(key: Field): [] {
  const proof = suppliedPath(); const digest = root(proof);
  trees.lookup(disclose(key)).insert(disclose(proof.leaf));
  assert(trees.lookup(1 as Field).checkRoot(disclose(digest)), "possibly changed"); accepted = disclose(proof.leaf);
}
export circuit distinct(): [] {
  const proof = suppliedPath(); const digest = root(proof);
  trees.lookup(2 as Field).insert(7 as Field);
  assert(trees.lookup(1 as Field).checkRoot(disclose(digest)), "unchanged"); accepted = disclose(proof.leaf);
}
`, ["dynamicWrong", "mayAlias"]);
});

test("canonical digest and root recognition survives import aliases without accepting namesakes", () => {
  fixture(`import { MerkleTreeDigest as Digest, merkleTreePathRoot as canonicalRoot, MerkleTreePath } from CompactStandardLibrary;
struct MerkleTreeDigest { field: Field; }
witness realDigest(): Digest;
witness fakeDigest(): MerkleTreeDigest;
witness proof(): MerkleTreePath<2,Field>;
export ledger accepted: Field;
circuit merkleTreePathRoot(value: MerkleTreeDigest): MerkleTreeDigest { return value; }
export circuit aliasDigest(): [] { accepted = disclose(realDigest().field); }
export circuit aliasRoot(): [] { const path = proof(); const root = canonicalRoot<2,Field>(path); accepted = disclose(root.field); }
export circuit namesake(): [] { accepted = disclose(merkleTreePathRoot(fakeDigest()).field); }
`, ["aliasDigest", "aliasRoot"]);
});

test("callback proofs and token effects retain exact dependencies and late atomic checks", () => {
  fixture(`${header}
circuit compute(ignored: Field): MerkleTreeDigest { return root(suppliedPath()); }
export circuit callbacks(): [] {
  const roots = map(compute, [0 as Field, 1 as Field]);
  assert(tree.checkRoot(disclose(roots[0])), "first"); accepted = disclose(roots[1].field);
}
export circuit callbacksChecked(): [] {
  const roots = map(compute, [0 as Field, 1 as Field]);
  assert(tree.checkRoot(disclose(roots[1])), "second"); accepted = disclose(roots[1].field);
}
export circuit transfer(recipient: Either<ContractAddress,UserAddress>): [] {
  const proof = suppliedPath(); const digest = root(proof);
  if (disclose(proof.leaf == (1 as Field))) { sendUnshielded(default<Bytes<32>>, 1, disclose(recipient)); }
}
export circuit transferChecked(recipient: Either<ContractAddress,UserAddress>): [] {
  const proof = suppliedPath(); const digest = root(proof);
  if (disclose(proof.leaf == (1 as Field))) { sendUnshielded(default<Bytes<32>>, 1, disclose(recipient)); }
  assert(tree.checkRoot(disclose(digest)), "member");
}
export circuit rejected(): [] {
  const proof = suppliedPath(); const digest = root(proof); accepted = disclose(proof.leaf); assert(false, "disabled");
}
`, ["callbacks", "transfer"], undefined, alphaMerklePaths);
});
