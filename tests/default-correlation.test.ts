import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

const account = "Either<Bytes<32>, ContractAddress>";
const helpers = `
pure circuit canonicalize(value: ${account}): ${account} {
  return value.is_left
    ? ${account}{is_left: true, left: value.left, right: default<ContractAddress>}
    : ${account}{is_left: false, left: default<Bytes<32>>, right: value.right};
}
pure circuit tag(value: ${account}): Boolean {
  if (value.is_left) { return true; }
  return false;
}
pure circuit isZero(value: ${account}): Boolean {
  if (value.is_left) { return value.left == default<Bytes<32>>; }
  return value.right == default<ContractAddress>;
}`;

function compare(source: string, check: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let expected: AnalysisFacts | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      check(facts);
      if (expected) assert.deepEqual(semanticPaths(facts), semanticPaths(expected));
      else expected = facts;
    }
  });
}

const returns = (facts: AnalysisFacts): (string | undefined)[] => facts.paths.flatMap(path =>
  path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value.constant)).sort();

for (const first of ["canonicalize", "tag"] as const) test(`NFT owner snapshot retains its tag after ${first} (619/895)`, () => {
  const expression = first === "canonicalize" ? "canonicalize(owner).is_left == tag(owner)" : "tag(owner) == canonicalize(owner).is_left";
  compare(`${helpers}
export ledger owners: Map<Field, ${account}>;
export circuit entry(key: Field): Boolean {
  const owner = owners.lookup(disclose(key));
  return ${expression};
}`, facts => assert.deepEqual(returns(facts), ["true", "true"]));
});

test("NFT recipient nonzero aggregate cannot become zero (817 minimum)", () => {
  compare(`export circuit entry(to: ContractAddress): Boolean {
  assert(to != default<ContractAddress>, "recipient must be nonzero");
  if (to == default<ContractAddress>) { return false; }
  return true;
}`, facts => assert.deepEqual(returns(facts), ["true"]));
});

test("NFT recipient stays nonzero through Either canonicalization (817)", () => {
  compare(`${helpers}
export circuit entry(to: ${account}): Boolean {
  assert(!isZero(to), "recipient must be nonzero");
  const canonical = canonicalize(to);
  if (!isZero(canonical)) { return true; }
  return false;
}`, facts => assert.deepEqual(returns(facts), ["true", "true"]));
});

test("aggregate disequality excludes the whole value, not each field", () => {
  compare(`struct Pair { first: Field; second: Field; }
export circuit entry(value: Pair): Boolean {
  assert(value != default<Pair>, "not all zero");
  assert(value.first == (0 as Field), "first may still be zero");
  return true;
}`, facts => assert.deepEqual(returns(facts), ["true"]));
});

test("an excluded ContractAddress default cannot be rebuilt by constraining its bytes", () => {
  compare(`export circuit entry(to: ContractAddress): Boolean {
  assert(to != default<ContractAddress>, "nonzero address");
  assert(to.bytes == default<Bytes<32>>, "zero bytes");
  return true;
}`, facts => {
    assert.deepEqual(returns(facts), []);
    assert.equal(facts.failedAssertions.length, 1);
    assert.equal(facts.failedAssertions[0].message, '"zero bytes"');
  });
});

test("an aggregate exclusion survives constraints on each field", () => {
  compare(`struct Pair { first: Field; second: Field; }
export circuit entry(value: Pair): Boolean {
  assert(value != default<Pair>, "not all zero");
  assert(value.first == (0 as Field), "first may be zero");
  assert(value.second == (0 as Field), "both cannot be zero");
  return true;
}`, facts => {
    assert.deepEqual(returns(facts), []);
    assert.equal(facts.failedAssertions.length, 1);
    assert.equal(facts.failedAssertions[0].message, '"both cannot be zero"');
  });
});

test("aggregate exclusions retain the correlation of saved projections after their parent dies", () => {
  compare(`struct Pair { first: Field; second: Field; }
export circuit entry(value: Pair): Boolean {
  assert(value != default<Pair>, "not all zero");
  const first = value.first;
  const second = value.second;
  assert(first == (0 as Field), "first may be zero");
  if (second == (0 as Field)) { return false; }
  return true;
}`, facts => assert.deepEqual(returns(facts), ["true"]));
});

test("aggregate exclusions constrain retained snapshots after the ledger value changes", () => {
  compare(`struct Pair { first: Field; second: Field; }
export ledger values: Map<Field, Pair>;
export circuit entry(): Boolean {
  const value = values.lookup(0 as Field);
  assert(value != default<Pair>, "not all zero");
  const first = value.first;
  const second = value.second;
  assert(first == (0 as Field), "first may be zero");
  values.insert(0 as Field, default<Pair>);
  if (second == (0 as Field)) { return false; }
  return true;
}`, facts => assert.deepEqual(returns(facts), ["true"]));
});

test("excluding one dynamic aggregate snapshot does not exclude another read's default", () => {
  compare(`struct Pair { first: Field; second: Field; }
export ledger values: Map<Field, Pair>;
export circuit entry(firstKey: Field, secondKey: Field): Boolean {
  const first = values.lookup(disclose(firstKey));
  const second = values.lookup(disclose(secondKey));
  assert(first != default<Pair>, "first is nonzero");
  assert(second == default<Pair>, "second may be zero");
  return true;
}`, facts => assert.deepEqual(returns(facts), ["true"]));
});

test("excluded vector defaults cannot be rebuilt by constraining their items", () => {
  compare(`export circuit entry(value: Vector<2, Field>): Boolean {
  assert(value != default<Vector<2, Field>>, "not all zero");
  assert(value[0] == (0 as Field), "first may be zero");
  assert(value[1] == (0 as Field), "both cannot be zero");
  return true;
}`, facts => assert.deepEqual(returns(facts), []));
});

test("aggregate exclusion retention exhaustion is explicitly incomplete in every execution mode", () => {
  const assertions = Array.from({ length: 5 }, (_, index) =>
    `assert(value != [${index} as Field, ...default<Vector<255, Field>>], "excluded value ${index}");`).join("\n");
  withFiles({ "main.compact": `export circuit entry(value: Vector<256, Field>): Field {
${assertions}
return value[0];
}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.completedEntries, []);
      assert.deepEqual(facts.diagnostics.map(diagnostic => diagnostic.code), ["constraint-budget"]);
      assert.deepEqual(facts.failedAssertions, []);
    }
  });
});

test("aggregate equality refines corresponding fields", () => {
  compare(`struct Pair { first: Field; second: Field; }
export circuit entry(value: Pair): Boolean {
  assert(value == default<Pair>, "all zero");
  if (value.first != (0 as Field)) { return false; }
  return value.second == (0 as Field);
}`, facts => assert.deepEqual(returns(facts), ["true"]));
});

test("different dynamic reads remain independent while saved fields stay stable", () => {
  compare(`${helpers}
export ledger owners: Map<Field, ${account}>;
export circuit entry(first: Field, second: Field): Boolean {
  const leftOwner = owners.lookup(disclose(first));
  const rightOwner = owners.lookup(disclose(second));
  assert(leftOwner.is_left != rightOwner.is_left, "different entries may have different tags");
  return tag(leftOwner) == canonicalize(leftOwner).is_left;
}`, facts => assert.deepEqual(returns(facts), ["true", "true"]));
});

test("a retained owner keeps its field constraints after the ledger entry changes", () => {
  compare(`${helpers}
export ledger owners: Map<Field, ${account}>;
export circuit entry(): Boolean {
  const owner = owners.lookup(0 as Field);
  const originalTag = tag(owner);
  owners.insert(0 as Field, left<Bytes<32>, ContractAddress>(default<Bytes<32>>));
  return originalTag == tag(owner);
}`, facts => assert.deepEqual(returns(facts), ["true", "true"]));
});
