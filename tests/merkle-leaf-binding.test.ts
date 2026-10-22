import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { merklePathWitnessTargets, merklePureRootSummaryTarget } from "../src/semantic/merkle-targets.js";
import { merkleDigestKey } from "../src/dataflow/merkle-enforcement.js";
import { merkleLeafBindingReview as rule } from "../src/detectors/merkle-leaf-binding.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function check(file: string, expected: string[], isolated = false): void {
  if (process.env.COMPACTC_TEST) {
    const validation = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(validation.valid, true, validation.error);
  }
  const program = new Program(file);
  let baseline: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const actual = [];
    for (const entry of isolated ? program.entries : [undefined]) {
      const flow = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, false, "all", true, false, false, false,
        false, false, true, false, false, true, merklePathWitnessTargets(program).targets);
      const facts = entry === undefined ? flow.analyze() : flow.analyzeMerkleLeafBindingEntry(entry);
      actual.push(...rule.run(facts));
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, entry === undefined ? program.entries : [entry]);
    }
    assert.deepEqual([...new Set(actual.map(finding => finding.metadata.entry))].sort(), expected.slice().sort());
    baseline ??= actual; assert.deepEqual(actual, baseline);
    assert.ok(actual.every(finding => finding.metadata.reviewRequired));
    assert.ok(actual.every(finding => finding.severity === "info"));
  }
  for (const experimentalCounterQueries of isolated ? [false] : [false, true]) {
    const scan = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual([...new Set(scan.findings.map(finding => finding.metadata.entry))].sort(), expected.slice().sort());
  }
}
for (const name of ["positive", "fixed", "whitelist", "arithmetic-positive", "arithmetic-fixed"]) test(`owned leaf review: ${name}`, () => {
  check(resolve(`tests/owned-merkle-leaf-binding/${name}.compact`), name.endsWith("positive") ? ["accept"] : []);
});

test("optional binding, transitive binding, separate proofs, operand mutation and aborts", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
ledger tree: MerkleTree<2,Field>;
export ledger accepted: Field;
ledger stored: MerkleTreePath<2,Field>;
witness proof(): MerkleTreePath<2,Field>;
witness payload(): Field;
witness scalar(): Field;
circuit root(p: MerkleTreePath<2,Field>): MerkleTreeDigest { return merkleTreePathRoot<2,Field>(p); }
export circuit optional(flag: Boolean): [] {
 const p = proof(); const candidate = transientHash<Field>(payload());
 assert(tree.checkRoot(disclose(root(p))), "member");
 if(disclose(flag)) { assert(p.leaf == candidate, "bind"); }
 accepted = disclose(candidate);
}
export circuit transitive(): [] {
 const p = proof(); const candidate = transientHash<Field>(payload()); const alias = scalar();
 assert(tree.checkRoot(disclose(root(p))), "member");
 assert(p.leaf == alias, "leaf alias"); assert(alias == candidate, "candidate alias");
 accepted = disclose(candidate);
}
export circuit separate(): [] {
 const p = proof(); const other = proof(); const candidate = transientHash<Field>(payload());
 assert(tree.checkRoot(disclose(root(p))), "member");
 assert(other.leaf == candidate, "other"); accepted = disclose(candidate);
}
export circuit mutation(): [] {
 stored = disclose(proof()); const before = stored; const candidate = transientHash<Field>(payload());
 assert(tree.checkRoot(disclose(root(before))), "member");
 stored = disclose(MerkleTreePath<2,Field>{leaf: candidate, path: before.path});
 assert(stored.leaf == candidate, "later operand"); accepted = disclose(candidate);
}
export circuit constructed(): [] {
 const original = proof(); const candidate = transientHash<Field>(payload());
 const p = MerkleTreePath<2,Field>{leaf: candidate, path: original.path};
 assert(tree.checkRoot(disclose(root(p))), "member"); accepted = disclose(candidate);
}
export circuit sharedSource(): [] {
 const p = proof(); const candidate = transientHash<Field>(p.leaf);
 assert(tree.checkRoot(disclose(root(p))), "member"); accepted = disclose(candidate);
}
export circuit constantCandidate(): [] {
 const p = proof(); const candidate = transientHash<Field>(7 as Field);
 assert(tree.checkRoot(disclose(root(p))), "member"); accepted = disclose(candidate);
}
export circuit constantFixed(): [] {
 const p = proof(); const candidate = transientHash<Field>(7 as Field);
 assert(tree.checkRoot(disclose(root(p))), "member");
 assert(p.leaf == candidate, "bind constant input candidate"); accepted = disclose(candidate);
}
export circuit rejected(): [] {
 const p = proof(); const candidate = transientHash<Field>(payload());
 assert(tree.checkRoot(disclose(root(p))), "member"); accepted = disclose(candidate); assert(false, "abort");
}
export circuit unchecked(): [] {
 const p = proof(); const candidate = transientHash<Field>(payload());
 tree.checkRoot(disclose(root(p))); accepted = disclose(candidate);
}
` }, directory => check(resolve(directory, "main.compact"), ["optional", "separate", "mutation", "constantCandidate", "sharedSource"]));
});

test("missing observer evidence and exhausted equality budgets remain explicit", () => {
 const program = new Program(resolve("tests/owned-merkle-leaf-binding/positive.compact"));
 const missing = new Dataflow(program).analyze();
 assert.deepEqual(rule.run(missing), []);
 assert.ok(missing.diagnostics.some(diagnostic => diagnostic.code === "predicate-evidence-unavailable"));
 const facts = new Dataflow(program, 40000, 256, 50000, "instructions", true, true,
   "equivalent-states", false, false, "all", true, false, false, false,
   false, false, true, false, false, true).analyze();
 const predicate = facts.paths[0].predicates![0];
 for (let depth = 0; depth < 66; depth++) predicate.value = { flows: [], ledger: new Set(), negated: predicate.value };
 assert.deepEqual(rule.run(facts), []);
 assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "predicate-analysis-budget"));
});

test("path lookup arguments are not constraints; exact invocation snapshots preserve bindings", () => {
 withFiles({ "main.compact": `import CompactStandardLibrary;
ledger tree: MerkleTree<2,Field>;
export ledger count: Counter;
witness pathFor(item: Field): MerkleTreePath<2,Field>;
witness key(): Field;
export circuit unbound(): [] {
 const candidate = transientHash<Field>(key()); const p = pathFor(candidate);
 assert(tree.checkRoot(disclose(merkleTreePathRoot<2,Field>(p))), "member"); count.increment(1);
}
export circuit fixed(): [] {
 const candidate = transientHash<Field>(key()); const p = pathFor(candidate);
 assert(p.leaf == candidate, "bind");
 assert(tree.checkRoot(disclose(merkleTreePathRoot<2,Field>(p))), "member"); count.increment(1);
}
export circuit wrongInvocation(): [] {
 const candidate = transientHash<Field>(key()); const checked = pathFor(candidate); const other = pathFor(candidate);
 assert(other.leaf == candidate, "other binding");
 assert(tree.checkRoot(disclose(merkleTreePathRoot<2,Field>(checked))), "member"); count.increment(1);
}
export circuit constructed(): [] {
 const candidate = transientHash<Field>(key()); const original = pathFor(candidate);
 const p = MerkleTreePath<2,Field>{leaf: candidate, path: original.path};
 assert(tree.checkRoot(disclose(merkleTreePathRoot<2,Field>(p))), "member"); count.increment(1);
}
` }, directory => check(resolve(directory, "main.compact"), ["unbound", "wrongInvocation"]));
});

test("equality keys retain the scalar representation", () => {
  const common = { identity: "same-snapshot", flows: [], ledger: new Set<string>() };
  assert.notEqual(merkleDigestKey({ ...common, type: "Bytes<32>" }), merkleDigestKey({ ...common, type: "Field" }));
  assert.notEqual(merkleDigestKey({ ...common, identity: undefined, constant: "1", constantKind: "integer", type: "Field" }),
    merkleDigestKey({ ...common, identity: undefined, constant: "1", constantKind: "integer", type: "Uint<64>" }));
});

test("byte lookup equality requires the actual byte leaf, not conversion provenance", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
ledger tree: MerkleTree<2,Bytes<32>>;
export ledger count: Counter;
witness pathFor(item: Bytes<32>): MerkleTreePath<2,Bytes<32>>;
witness key(): Bytes<32>;
export circuit unbound(): [] {
 const item = key(); const p = pathFor(item);
 assert(tree.checkRoot(disclose(merkleTreePathRootNoLeafHash<2>(p))), "member"); count.increment(1);
}
export circuit bound(): [] {
 const item = key(); const p = pathFor(item); assert(p.leaf == item, "bind");
 assert(tree.checkRoot(disclose(merkleTreePathRootNoLeafHash<2>(p))), "member"); count.increment(1);
}
export circuit lossyComparison(): [] {
 const item = key(); const p = pathFor(item);
 assert(degradeToTransient(p.leaf) == degradeToTransient(item), "converted equality");
 assert(tree.checkRoot(disclose(merkleTreePathRootNoLeafHash<2>(p))), "member"); count.increment(1);
}
export circuit roundTrip(): [] {
 const item = key(); const restored = upgradeFromTransient(degradeToTransient(item)); const p = pathFor(restored);
 assert(tree.checkRoot(disclose(merkleTreePathRootNoLeafHash<2>(p))), "member"); count.increment(1);
}
export circuit convertedEquality(): [] {
 const item = key(); const p = pathFor(item);
 assert(p.leaf == upgradeFromTransient(degradeToTransient(item)), "converted bytes");
 assert(tree.checkRoot(disclose(merkleTreePathRootNoLeafHash<2>(p))), "member"); count.increment(1);
}
` }, directory => check(resolve(directory, "main.compact"), ["unbound", "lossyComparison", "roundTrip", "convertedEquality"], true));
});

test("pure root summary retains the final Field hash-write candidate", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
ledger expected: Field;
export ledger written: Field;
witness pathFor(item: Field): MerkleTreePath<1,Field>;
export circuit accept(item: Field): [] {
 const proof = pathFor(item); const digest = merkleTreePathRoot<1,Field>(proof);
 assert(digest.field == expected, "member"); written = disclose(digest.field);
}
` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const results = [];
    for (const summarized of [false, true]) {
      const flow = new Dataflow(program, 40000, 256, 50000, "instructions", true, true,
        "equivalent-states", false, false, "all", true, false, false, false,
        false, false, true, false, false, true, merklePathWitnessTargets(program).targets);
      const facts = flow.analyzeMerkleLeafBindingEntry(program.entries[0], summarized);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      results.push([...new Set(findings.map(item => item.metadata.evidence))].sort());
      assert.ok(facts.paths.some(path => path.operations?.some(operation => operation.kind === "merkle-root"
        && operation.result.fields?.field[summarized ? "summarizedMerkleHash" : "directDigest"])));
    }
    assert.deepEqual(results, [
      ["checked-root-without-required-leaf-candidate-equality", "checked-root-without-required-lookup-input-leaf-equality"],
      ["checked-root-without-required-leaf-candidate-equality", "checked-root-without-required-lookup-input-leaf-equality"],
    ]);
  });
});

test("pinned legacy and current ZKIR2 root helpers qualify individually", () => {
  withFiles({ "main.compact": `pragma language_version >= 0.20;
import CompactStandardLibrary;
ledger expected: Field;
export ledger accepted: Field;
witness pathFor(item: Field): MerkleTreePath<1,Field>;
export circuit accept(item: Field): [] {
 const proof = pathFor(item); const digest = merkleTreePathRoot<1,Field>(proof);
 assert(digest.field == expected, "member"); accepted = disclose(item);
}
` }, directory => {
    const file = resolve(directory, "main.compact");
    for (const version of ["0.30.0", "0.31.1", "0.34.0"] as const) {
      const compiler = version === "0.30.0" ? process.env.COMPACTC_030_TEST
        : version === "0.31.1" ? process.env.COMPACTC_031_TEST : process.env.COMPACTC_TEST;
      if (compiler) {
        const validation = validateWithCompiler(compiler, file, [], 30000, 2, version);
        assert.equal(validation.valid, true, validation.error);
      }
      const program = new Program(file, [], directory, undefined, 2, version);
      const root = [...program.functions.keys()].find(id => id.startsWith("standard-library::merkleTreePathRoot<"))!;
      assert.deepEqual(merklePureRootSummaryTarget(program, root), { depth: 1, leaf: "Field", noLeafHash: false });
      const flow = new Dataflow(program, 40000, 256, 50000, "instructions", true, true,
        "equivalent-states", false, false, "all", true, false, false, false,
        false, false, true, false, false, true, merklePathWitnessTargets(program).targets);
      const facts = flow.analyzeMerkleLeafBindingEntry(program.entries[0]);
      assert.deepEqual(facts.diagnostics, [], version);
      assert.deepEqual(facts.completedEntries, program.entries, version);
      assert.deepEqual(rule.run(facts).map(item => item.metadata.argumentIndex), [0], version);
      const ordinary = new Dataflow(program, 40000, 256, 50000, "instructions", true, true,
        "equivalent-states", false, false, "all", true, false, false, false,
        false, false, true, false, false, true, merklePathWitnessTargets(program).targets)
        .analyzeMerkleLeafBindingEntry(program.entries[0], false);
      assert.deepEqual(ordinary.diagnostics, [], version);
      assert.deepEqual(rule.run(ordinary).map(item => item.metadata.argumentIndex), [0], version);
      const keys = (observed: typeof facts) => [...new Set(observed.paths.flatMap(path => (path.operations ?? [])
        .filter(operation => operation.kind === "merkle-root").map(operation => operation.result.fields?.field.identity)))].sort();
      assert.deepEqual(keys(facts), keys(ordinary), version);
    }
    for (const version of ["0.33.0-rc.2", "0.35.0"] as const) {
      const program = new Program(file, [], directory, undefined, 2, version);
      const root = [...program.functions.keys()].find(id => id.startsWith("standard-library::merkleTreePathRoot<"))!;
      assert.equal(merklePureRootSummaryTarget(program, root), undefined, version);
    }
  });
});

test("pure root summary matches small depths and completes bounded depth 10 and 32", () => {
  for (const depth of [0, 1, 2, 10, 32]) withFiles({ "main.compact": `import CompactStandardLibrary;
ledger expected: Field;
export ledger accepted: Bytes<32>;
witness pathFor(item: Bytes<32>): MerkleTreePath<${depth},Bytes<32>>;
export circuit accept(item: Bytes<32>): [] {
 const proof = pathFor(item); const digest = merkleTreePathRootNoLeafHash<${depth}>(proof);
 assert(digest.field == expected, "member"); accepted = disclose(item);
}
` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const validation = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(validation.valid, true, validation.error);
    }
    const program = new Program(file);
    const run = (summarized: boolean) => new Dataflow(program, 40000, 256, 50000, "instructions", true, true,
      "equivalent-states", false, false, "all", true, false, false, false,
      false, false, true, false, false, true, merklePathWitnessTargets(program).targets)
      .analyzeMerkleLeafBindingEntry(program.entries[0], summarized);
    const summarized = run(true);
    assert.deepEqual(summarized.diagnostics, [], `depth ${depth}`);
    assert.deepEqual(summarized.completedEntries, program.entries, `depth ${depth}`);
    assert.deepEqual(rule.run(summarized).map(item => item.metadata.argumentIndex), [0], `depth ${depth}`);
    if (depth <= 2) {
      const ordinary = run(false);
      assert.deepEqual(ordinary.diagnostics, [], `ordinary depth ${depth}`);
      assert.deepEqual(rule.run(ordinary).map(item => item.metadata.argumentIndex), [0], `ordinary depth ${depth}`);
      const keys = (facts: typeof summarized) => [...new Set(facts.paths.flatMap(path => (path.operations ?? [])
        .filter(operation => operation.kind === "merkle-root").map(operation => operation.result.fields?.field.identity)))].sort();
      assert.deepEqual(keys(summarized), keys(ordinary), `depth ${depth}`);
    }
  });
});

test("pure root summaries retain ordinary call depth, including zero-iteration roots", () => {
  for (const [helpers, depth, complete] of [[29, 1, true], [30, 1, false], [30, 0, true]] as const) {
    const source = `import CompactStandardLibrary;
ledger expected: Field;
witness pathFor(item: Field): MerkleTreePath<${depth}, Field>;
export circuit accept(item: Field): [] { assert(disclose(h0(item)).field == expected, "member"); }
${Array.from({ length: helpers }, (_, index) => `circuit h${index}(item: Field): MerkleTreeDigest {
  return ${index + 1 < helpers ? `h${index + 1}(item)` : `merkleTreePathRoot<${depth}, Field>(pathFor(item))`};
}`).join("\n")}`;
    withFiles({ "main.compact": source }, directory => {
      const file = resolve(directory, "main.compact");
      if (process.env.COMPACTC_TEST) {
        const validation = validateWithCompiler(process.env.COMPACTC_TEST, file);
        assert.equal(validation.valid, true, validation.error);
      }
      const program = new Program(file);
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        for (const summarized of [false, true]) {
          const flow = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
            "equivalent-states", false, false, "all", true, false, false, false,
            false, false, true, false, false, true, merklePathWitnessTargets(program).targets);
          const facts = flow.analyzeMerkleLeafBindingEntry(program.entries[0], summarized);
          assert.deepEqual(facts.completedEntries, complete ? program.entries : [], `${helpers}, ${depth}, ${engine}, ${cached}, ${summarized}`);
          assert.deepEqual(facts.diagnostics.map(issue => issue.code), complete ? [] : ["call-depth"]);
        }
      }
    });
  }
});

test("pure root keys distinguish helpers, changed directions and fresh paths", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
witness pathFor(item: Bytes<32>): MerkleTreePath<1,Bytes<32>>;
witness alternate(): Bytes<32>;
export circuit inspect(item: Bytes<32>): [] {
 const proof = pathFor(item);
 const first = merkleTreePathRootNoLeafHash<1>(proof);
 const repeat = merkleTreePathRootNoLeafHash<1>(proof);
 const alternateEntry = MerkleTreePathEntry{ sibling: proof.path[0].sibling, goes_left: !proof.path[0].goes_left };
 const changed = MerkleTreePath<1,Bytes<32>>{ leaf: proof.leaf, path: [alternateEntry] };
 const changedRoot = merkleTreePathRootNoLeafHash<1>(changed);
 const fresh = merkleTreePathRootNoLeafHash<1>(pathFor(item));
 const domainHashed = merkleTreePathRoot<1,Bytes<32>>(proof);
}
` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const validation = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(validation.valid, true, validation.error);
    }
    const program = new Program(file);
    const flow = new Dataflow(program, 40000, 256, 50000, "instructions", true, true,
      "equivalent-states", false, false, "all", true, false, false, false,
      false, false, true, false, false, true, merklePathWitnessTargets(program).targets);
    const facts = flow.analyzeMerkleLeafBindingEntry(program.entries[0]);
    assert.deepEqual(facts.diagnostics, []);
    const roots = facts.paths[0].operations!.filter(operation => operation.kind === "merkle-root");
    assert.equal(roots.length, 5);
    const keys = roots.map(operation => operation.result.fields!.field.identity);
    assert.equal(keys[0], keys[1]);
    assert.ok(keys.slice(2).every(key => key !== keys[0]));
    assert.equal(new Set(keys).size, 4);
  });
});

test("root argument effects and aborts precede the pure summary", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
ledger expected: Field;
export ledger touched: Counter;
witness pathFor(item: Bytes<32>): MerkleTreePath<0,Bytes<32>>;
circuit supplied(item: Bytes<32>): MerkleTreePath<0,Bytes<32>> {
 touched.increment(1); return pathFor(item);
}
circuit rejected(item: Bytes<32>): MerkleTreePath<0,Bytes<32>> {
 assert(false, "argument abort"); return pathFor(item);
}
export circuit effect(item: Bytes<32>): [] {
 const digest = merkleTreePathRootNoLeafHash<0>(supplied(item)); assert(digest.field == expected, "member");
}
export circuit argumentAbort(item: Bytes<32>): [] {
 const digest = merkleTreePathRootNoLeafHash<0>(rejected(item)); assert(digest.field == expected, "member");
}
export circuit enclosingAbort(item: Bytes<32>): [] {
 const digest = merkleTreePathRootNoLeafHash<0>(supplied(item)); assert(false, "enclosing abort");
}
` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const validation = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(validation.valid, true, validation.error);
    }
    const program = new Program(file);
    for (const entry of program.entries) for (const summarized of [false, true]) {
      const flow = new Dataflow(program, 40000, 256, 50000, "instructions", true, true,
        "equivalent-states", false, false, "all", true, false, false, false,
        false, false, true, false, false, true, merklePathWitnessTargets(program).targets);
      const facts = flow.analyzeMerkleLeafBindingEntry(entry, summarized);
      assert.deepEqual(facts.diagnostics, []);
      const name = program.symbols.get(entry)!.name;
      if (name === "effect") {
        assert.deepEqual(facts.completedEntries, [entry]);
        assert.equal(facts.paths.length, 1);
        assert.equal(facts.paths[0].writes.filter(write => program.symbols.get(write.ledger)?.name === "touched").length, 1);
      } else assert.deepEqual(facts.paths, [], name);
    }
  });
});

test("root summary rejects namesakes, unsupported leaf types and low allowances", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
ledger expected: Field;
witness bytePath(): MerkleTreePath<0,Bytes<32>>;
witness integerPath(): MerkleTreePath<0,Uint<64>>;
circuit merkleTreePathRootNoLeafHash(path: MerkleTreePath<0,Bytes<32>>): MerkleTreeDigest {
 return default<MerkleTreeDigest>;
}
export circuit entry(): [] {
 const proof = bytePath(); const digest = merkleTreePathRoot<0,Bytes<32>>(proof);
 assert(digest.field == expected, "member");
 const other = merkleTreePathRoot<0,Uint<64>>(integerPath());
 const namesake = merkleTreePathRootNoLeafHash(proof);
}
` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const canonicalByte = [...program.functions.keys()].find(id => id.startsWith("standard-library::merkleTreePathRoot<0,Bytes<32>"))!;
    const canonicalInteger = [...program.functions.keys()].find(id => id.startsWith("standard-library::merkleTreePathRoot<0,Uint<64>"))!;
    const namesake = [...program.functions.keys()].find(id => id.endsWith("::merkleTreePathRootNoLeafHash"))!;
    assert.deepEqual(merklePureRootSummaryTarget(program, canonicalByte), { depth: 0, leaf: "Bytes<32>", noLeafHash: false });
    assert.equal(merklePureRootSummaryTarget(program, canonicalInteger), undefined);
    assert.equal(merklePureRootSummaryTarget(program, namesake), undefined);
    for (const [steps, values, code] of [[1, 50, "analysis-budget"], [40000, 1, "value-budget"]] as const) {
      const flow = new Dataflow(program, steps, 1, values, "instructions", true, true,
        "equivalent-states", false, false, "all", true, false, false, false,
        false, false, true, false, false, true, merklePathWitnessTargets(program).targets);
      const facts = flow.analyzeMerkleLeafBindingEntry(program.entries[0]);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === code));
      assert.deepEqual(facts.completedEntries, []);
    }
  });
  withFiles({ "main.compact": `import CompactStandardLibrary;
witness proof(): MerkleTreePath<0,Opaque<"string">>;
export circuit entry(): MerkleTreeDigest { return merkleTreePathRoot<0,Opaque<"string">>(proof()); }
` }, directory => assert.throws(() => new Program(resolve(directory, "main.compact")),
    error => (error as { diagnostic?: { code?: string } }).diagnostic?.code === "unsupported-opaque-intrinsic"));
});

test("combined Counter fallback preserves existing historical encryption invocation targets", () => {
  const report = scanFile(resolve("tests/corpus/known-bugs/library-public-encryption-secret-positive.compact"), {
    compilerVersion: "0.31.1", experimentalCounterQueries: true,
    detectors: [rule.id, "publicly-derivable-encryption-secret"],
  });
  assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
  assert.equal(report.findings.filter(finding => finding.detectorId === "publicly-derivable-encryption-secret").length, 1);
});
