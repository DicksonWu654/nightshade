import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";
import { HashRecipes } from "../src/dataflow/hash-recipes.js";
import { assumeScalar, type ScalarConstraints } from "../src/dataflow/transfers.js";
import { commonScalarConstraints } from "../src/dataflow/common-constraints.js";

const constraintState = (hashRecipes: HashRecipes): ScalarConstraints => ({ hashRecipes, known: new Map(), truths: new Map(),
  excluded: new Map(), aggregateExclusions: new Map(), aggregateExclusionLeaves: 0, aggregateExclusionsExhausted: false, scalarEqualities: new Map() });
const scalar = (identity: string, type = "Field") => ({ flows: [], ledger: new Set<string>(), identity, type });

test("shared selector normalization remains isolated through alias propagation and new choices", () => {
  for (const share of [false, true]) {
    const recipes = new HashRecipes(() => true, () => assert.fail("depth"), share);
    const first = recipes.choose("flag", "a", "b")!, second = recipes.choose("flag", "c", "d")!;
    const make = () => {
      const state = constraintState(recipes);
      state.scalarEqualities!.set("flag-alias", { left: scalar("flag", "Boolean"), right: scalar("alias", "Boolean"), equals: true });
      state.scalarEqualities!.set("first-e", { left: scalar(first), right: scalar("e"), equals: true });
      state.known.set("alias", { kind: "boolean", value: "true" });
      state.excluded.set(second, new Set(["integer:0"]));
      return state;
    };
    const left = make(), right = make();
    assert.equal(commonScalarConstraints(left, right, () => true).status, "available");
    assert.equal(left.known.has("flag"), false); assert.equal(right.known.has("flag"), false);
    const sibling = constraintState(recipes);
    assert.equal(recipes.refine(scalar(second), sibling).identity, second);
    assert.equal(assumeScalar(scalar("flag", "Boolean"), false, sibling), true);
    assert.equal(recipes.refine(scalar(second), sibling).identity, "d");
    const earlier = constraintState(recipes);
    earlier.known.set("later", { kind: "boolean", value: "true" });
    assert.equal(recipes.refine(scalar(first), earlier).identity, first);
    const later = recipes.choose("later", first, "other")!;
    assert.equal(recipes.refine(scalar(later), earlier).identity, first, "new selectors refresh existing state handles");
    earlier.known.delete("later"); recipes.invalidate(earlier, "later");
    assert.equal(recipes.refine(scalar(later), earlier).identity, later, "forgetting a selector cannot reuse a selected substitution");
  }
});

test("indexed recipe liveness agrees with the graph walk for nested hashes, bytes, casts and comparisons", () => {
  const recipes = new HashRecipes(() => true, () => assert.fail("depth"));
  const roots: string[] = [], all = new Set<string>(["unrelated"]);
  let previous = "seed";
  for (let index = 0; index < 24; index++) {
    const selected = recipes.choose(`flag${index}`, previous, `other${index}`)!;
    const byte = recipes.byte(selected, index)!;
    const cast = recipes.cast(selected, "owned-cast")!;
    previous = recipes.hash([scalar(selected), scalar(byte), scalar(cast)], ["owned-domain"], "hash")!;
    roots.push(previous);
    for (const identity of [selected, byte, cast, previous, `flag${index}`, `other${index}`]) all.add(identity);
  }
  const compared = recipes.hash([{ ...scalar("predicate", "Boolean"), comparison: { operator: "==", left: scalar(previous), right: scalar("peer") } }], [], "hash")!;
  roots.push(compared); all.add(compared); all.add("peer"); all.add("seed");
  for (const root of roots) {
    const walked = new Set<string>(), indexed = new Set<string>();
    recipes.dependencies(root, identity => walked.add(identity));
    recipes.retainDependencies([root], all, identity => indexed.add(identity));
    assert.deepEqual(indexed, new Set([...all].filter(identity => walked.has(identity))));
  }
});

test("recipe index and context allocations refuse exhausted work and value allowances", () => {
  for (const dimension of ["work", "values"] as const) {
    let work = 0, values = 0;
    const recipes = new HashRecipes((w, v) => { work += w; values += v; return dimension === "work" ? work <= 20 : values <= 20; }, () => {});
    let previous = "seed";
    for (let index = 0; index < 24 && !recipes.exhausted; index++) previous = recipes.choose(`flag${index}`, previous, `other${index}`) ?? previous;
    assert.equal(recipes.exhausted, true, dimension);
    assert.equal(recipes.choose("again", "a", "b"), undefined, "a later query cannot clear refusal");
  }
});

test("shared recipe contexts preserve full compiler-valid caller histories in both engines", () => {
  withProgram(`export ledger output: Map<Field,Bytes<32>>;
  circuit authorize(): [] { assert(true, "guard"); }
  pure circuit wrap(value: Bytes<32>): Bytes<32> { return persistentHash<Bytes<32>>(value); }
  export circuit entry(flag: Boolean, alias: Boolean, key: Field, a: Field, b: Field): [] {
    const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
    const wrapped = wrap(chosen);
    assert(flag == alias, "alias");
    if (disclose(alias)) {
      authorize(); assert(wrapped == wrap(${hash("a", "b")}), "selected true");
      output.insert(disclose(key), disclose(wrapped));
    } else {
      assert(wrapped == wrap(${hash("b", "a")}), "selected false");
      output.insert(disclose(key), disclose(chosen));
    }
    assert(output.member(disclose(key)), "present");
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const summaries of [false, true]) {
      const observations: Omit<AnalysisFacts, "metrics">[] = [];
      for (const optimized of [false, true]) {
        const flow = new Dataflow(program, 40000, 256, 50000, engine, summaries, summaries, "equivalent-states", true, true, "all", false, true);
        const hook = flow as unknown as { newHashRecipes(): HashRecipes };
        const create = hook.newHashRecipes.bind(flow);
        hook.newHashRecipes = () => {
          const recipes = create();
          (recipes as unknown as { shareContexts: boolean }).shareContexts = optimized;
          if (!optimized) recipes.retainDependencies = (roots, candidates, visit) => {
            const walked = new Set<string>(), seen = new Set<string>();
            for (const root of roots) recipes.dependencies(root, value => walked.add(value), seen);
            for (const candidate of candidates) if (walked.has(candidate)) visit(candidate);
          };
          return recipes;
        };
        const { metrics: _, ...facts } = flow.analyze();
        assert.deepEqual(facts.diagnostics, []); assert.equal(facts.paths.length, 2);
        observations.push(facts);
      }
      assert.deepEqual(observations[1], observations[0], `${engine}, summaries=${summaries}`);
    }
  });
});

const hash = (a: string, b: string): string => `persistentHash<[Field,Field]>([${a},${b}])`;
function withProgram(source: string, check: (program: Program) => void, zkirVersion: 2 | 3 = 2): void {
  withFiles({ "main.compact": `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, zkirVersion);
      assert.equal(compiled.valid, true, compiled.error);
    }
    check(new Program(file, [], directory, undefined, zkirVersion));
  });
}
function run(program: Program, check: (facts: AnalysisFacts) => void, options: { paths?: number; choices?: boolean; steps?: number; values?: number } = {}): void {
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const analysis = new Dataflow(program, options.steps ?? 40000, options.paths ?? 256, options.values ?? 50000,
      engine, cached, cached, "equivalent-states", true, true, "all", false, false, false, options.choices ?? true);
    const facts = analysis.analyze();
    check(facts);
    assert.deepEqual(analysis.analyze(), facts, "recipe definitions reset between runs");
  }
}
const complete = (facts: AnalysisFacts): void => {
  assert.deepEqual(facts.diagnostics, []);
  assert.deepEqual(facts.completedEntries, facts.program.entries);
};

test("hash choices retain scalar, nested and aggregate contradictions in both guard orders", () => {
  const entries: string[] = [];
  for (const aggregate of [false, true]) for (const selectorFirst of [false, true]) {
    const mismatch = aggregate ? "assert([selected, 0 as Field] != [expected, 0 as Field], \"mismatch\");" : "assert(selected != expected, \"mismatch\");";
    entries.push(`export circuit entry_${aggregate}_${selectorFirst}(flag: Boolean, a: Field, b: Field): [] {
      const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
      const selected = persistentHash<Bytes<32>>(chosen);
      const expected = persistentHash<Bytes<32>>(${hash("a", "b")});
      ${selectorFirst ? 'assert(flag, "select");' : ""}
      ${mismatch}
      ${selectorFirst ? "" : 'assert(flag, "select");'}
    }`);
  }
  withProgram(entries.join("\n"), program => {
    for (const choices of [false, true]) run(program, facts => { complete(facts); assert.equal(facts.paths.length, 0); }, { choices });
  });
});

test("earlier constant constraints and aggregate exclusions follow a selected hash arm", () => {
  withProgram(`export circuit constantFirst(flag: Boolean, a: Field, b: Field): [] {
    const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
    assert(chosen == default<Bytes<32>>, "constant"); assert(flag, "select");
    assert(${hash("a", "b")} != default<Bytes<32>>, "contradiction");
  }
  export circuit excludedFirst(flag: Boolean, a: Field, b: Field): [] {
    const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
    assert([chosen, 0 as Field] != [default<Bytes<32>>, 0 as Field], "excluded");
    assert(flag, "select"); assert(${hash("a", "b")} == default<Bytes<32>>, "contradiction");
  }`, program => {
    for (const choices of [false, true]) run(program, facts => { complete(facts); assert.equal(facts.paths.length, 0); }, { choices });
  });
});

test("sibling selectors, calls and real effect histories do not share constraint caches", () => {
  withProgram(`export ledger result: Bytes<32>;
  pure circuit choose(flag: Boolean, a: Field, b: Field): Bytes<32> {
    return flag ? ${hash("a", "b")} : ${hash("b", "a")};
  }
  pure circuit wrap(h: Bytes<32>): Bytes<32> { return persistentHash<Bytes<32>>(h); }
  circuit authorize(): [] { assert(true, "guard"); }
  export circuit entry(flag: Boolean, a: Field, b: Field): [] {
    const selected = choose(flag,a,b);
    const nested = wrap(selected);
    if (disclose(flag)) {
      authorize(); assert(nested == wrap(${hash("a", "b")}), "same");
      result = disclose(nested);
    } else {
      assert(nested == wrap(${hash("b", "a")}), "same");
      result = disclose(nested);
    }
  }`, program => run(program, facts => {
    complete(facts); assert.equal(facts.paths.length, 2);
    assert.ok(facts.paths.every(path => path.writes.length === 1));
    const authorize = [...program.functions.values()].find(fn => fn.symbol.name === "authorize")!.symbol.id;
    assert.equal(facts.paths.filter(path => path.writes[0].guards.includes(authorize)).length, 1);
    assert.ok(facts.paths.every(path => path.writes[0].after.flows.some(flow => flow.source.name === "flag")));
  }));
});

test("a 24-level hash chain completes without enumerating selectors or merging writes", () => {
  withProgram(`export ledger scratch: Bytes<32>;
  export circuit entry(bits: Vector<24,Boolean>, siblings: Vector<24,Bytes<32>>, leaf: Bytes<32>): Bytes<32> {
    scratch = disclose(leaf);
    for (const i of 0..24) {
      const bit = bits[i]; const sib = siblings[i]; const previous = scratch;
      scratch = disclose(bit ? persistentHash<[Bytes<32>,Bytes<32>]>([sib,previous]) : persistentHash<[Bytes<32>,Bytes<32>]>([previous,sib]));
    }
    return scratch;
  }`, program => {
    run(program, facts => {
      complete(facts); assert.equal(facts.paths.length, 1); assert.equal(facts.paths[0].writes.length, 25);
      const result = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
      assert.deepEqual(new Set(result.flows.map(flow => flow.source.name)), new Set(["bits", "siblings", "leaf"]));
      assert.ok(result.identity!.length < 128);
      assert.ok(facts.paths[0].path.some(step => step.kind === "summary"));
    }, { paths: 1 });
    run(program, facts => assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget")), { paths: 1, choices: false });
    run(program, facts => {
      assert.equal(facts.completedEntries.length, 0);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code.endsWith("budget")));
    }, { values: 60 });
  });
});

test("branch-sensitive preimages retain ordinary interpretation", () => {
  withProgram(`export ledger digest: Bytes<32>; export ledger output: Field;
  witness nonce(): Field; witness secret(): Field;
  export circuit entry(): [] {
    const x = nonce(); const s = secret();
    const h = x == (0 as Field) ? ${hash("x", "s")} : ${hash("s", "x")};
    assert(x == (0 as Field), "select"); assert(h == digest, "binding");
    output = disclose(s);
  }`, program => run(program, facts => {
    complete(facts); assert.equal(facts.paths.length, 1);
    assert.ok(facts.paths[0].predicates?.some(predicate => predicate.value.comparison?.left.directHash?.source.name === "secret"));
    assert.ok(!facts.paths[0].path.some(step => step.kind === "summary"));
  }));
});

test("effectful and unequal-dependency arms remain separate histories", () => {
  withProgram(`export ledger output: Field;
  circuit changing(value: Field): Field { output = disclose(value); return value; }
  export circuit entry(flag: Boolean, a: Field, b: Field): Bytes<32> {
    return disclose(disclose(flag) ? ${hash("changing(a)", "b")} : ${hash("b", "a")});
  }`, program => run(program, facts => {
    complete(facts); assert.equal(facts.paths.length, 2);
    assert.deepEqual(facts.paths.map(path => path.writes.length).sort(), [0, 1]);
    assert.ok(facts.paths.every(path => !path.path.some(step => step.kind === "summary")));
  }));
});

test("byte projections retain selected digest identity", () => {
  withProgram(`export circuit entry(flag: Boolean, a: Field, b: Field): [] {
    const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
    const expected = ${hash("a", "b")};
    assert(chosen[0] != expected[0], "different byte"); assert(flag, "select");
  }`, program => {
    for (const choices of [false, true]) run(program, facts => { complete(facts); assert.equal(facts.paths.length, 0); }, { choices });
  });
});

test("unresolved choice collection keys remain explicitly incomplete", () => {
  withProgram(`export ledger table: Map<Bytes<32>,Field>;
  export circuit entry(flag: Boolean, a: Field, b: Field): [] {
    const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
    table.insert(disclose(chosen),1 as Field);
  }`, program => {
    run(program, facts => {
      assert.equal(facts.completedEntries.length, 0);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "unsupported-hash-choice"));
    });
    run(program, complete, { choices: false });
  });
});

for (const operation of ["ordering hash", "scalar cast"] as const) test(`${operation} retains a selected digest's derivation`, () => {
  const transform = (name: string): string => operation === "ordering hash" ? `persistentHash<Boolean>(${name}[0] < 10)` : `${name} as Secp256k1Scalar`;
  withProgram(`export circuit entry(flag: Boolean, a: Field, b: Field): [] {
    const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
    const expected = ${hash("a", "b")};
    const actual = ${transform("chosen")}; const wanted = ${transform("expected")};
    assert(actual != wanted, "mismatch"); assert(flag, "select");
  }`, program => {
    for (const choices of [false, true]) run(program, facts => { complete(facts); assert.equal(facts.paths.length, 0); }, { choices });
  }, operation === "scalar cast" ? 3 : 2);
});

for (const input of ["Bytes[...chosen]", "((chosen as Vector<32,Uint<8>>) as Bytes<32>)"]) test(`aggregate scalar cast is explicitly incomplete: ${input}`, () => {
  withProgram(`export circuit entry(flag: Boolean, a: Field, b: Field): [] {
    const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
    const expected = ${hash("a", "b")};
    const actual = ${input} as Secp256k1Scalar;
    const wanted = ${input.replaceAll("chosen", "expected")} as Secp256k1Scalar;
    assert(actual != wanted, "mismatch"); assert(flag, "select");
  }`, program => {
    run(program, facts => {
      assert.equal(facts.completedEntries.length, 0);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "unsupported-hash-choice"));
    });
    run(program, facts => { complete(facts); assert.equal(facts.paths.length, 0); }, { choices: false });
  }, 3);
});

test("retained byte bounds follow hash choices into later constraints", () => {
  withProgram(`export circuit entry(flag: Boolean, a: Field, b: Field): [] {
    const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
    const expected = ${hash("a", "b")};
    assert(chosen[0] < 10, "first bound"); assert(flag, "select");
    assert(expected[0] >= 10, "contradiction");
  }`, program => {
    for (const choices of [false, true]) run(program, facts => { complete(facts); assert.equal(facts.paths.length, 0); }, { choices });
  });
});

test("unresolved exclusions of both hash arms never become a clean successful entry", () => {
  withProgram(`export circuit entry(flag: Boolean, a: Field, b: Field): [] {
    const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
    assert(chosen != ${hash("a", "b")}, "exclude first");
    assert(chosen != ${hash("b", "a")}, "exclude second");
  }`, program => {
    run(program, facts => {
      assert.equal(facts.completedEntries.length, 0);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "unsupported-hash-choice-constraint"));
    });
    run(program, facts => { complete(facts); assert.equal(facts.paths.length, 0); }, { choices: false });
  });
});

test("choice hashes can still be checked against an opaque public ledger digest", () => {
  withProgram(`export ledger root: Bytes<32>;
  export circuit entry(flag: Boolean, a: Field, b: Field): [] {
    const chosen = flag ? ${hash("a", "b")} : ${hash("b", "a")};
    assert(chosen == root, "root");
  }`, program => run(program, facts => { complete(facts); assert.equal(facts.paths.length, 1); }));
});
