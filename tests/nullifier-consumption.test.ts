import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { nullifierCheckWithoutInsert as rule } from "../src/detectors/nullifier-consumption.js";
import { unconsumedAbsences } from "../src/dataflow/collection-consumption.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
ledger used: Set<Field>;
ledger other: Set<Field>;
ledger maps: Map<Field,Boolean>;
ledger nested: Map<Field,Set<Field>>;
export ledger accepted: Field;
witness token(): Field;
circuit consume(value: Field): [] { used.insert(disclose(value)); }
`;
function comparablePaths(facts: AnalysisFacts): string[] {
  return semanticPaths(facts).map(serialized => {
    const snapshots = new Map<string, string>();
    const writes = new Map<string, string>();
    const visit = (value: unknown): unknown => {
      if (Array.isArray(value)) return value.map(visit);
      if (!value || typeof value !== "object") return value;
      const record = value as Record<string, unknown>;
      const result = Object.fromEntries(Object.entries(record).map(([key, value]) => [key, visit(value)]));
      // Exploration order allocates snapshot/write numbers. Rename only AbstractValue
      // identity metadata, bijectively within each history; preserve field
      // suffixes, all aliases, operands, guards, effects and provenance.
      if (Array.isArray(record.flows) && Array.isArray(record.ledger) && typeof record.identity === "string") {
        const prefix = /^snapshot:\d+(?=:)/.exec(record.identity)?.[0];
        if (prefix) {
          if (!snapshots.has(prefix)) snapshots.set(prefix, `snapshot:${snapshots.size}`);
          result.identity = snapshots.get(prefix)! + record.identity.slice(prefix.length);
        }
        const write = /^write:\d+$/.exec(record.identity)?.[0];
        if (write) {
          if (!writes.has(write)) writes.set(write, `write:${writes.size}`);
          result.identity = writes.get(write)!;
        }
      }
      return result;
    };
    return JSON.stringify(visit(JSON.parse(serialized)));
  }).sort();
}
function fixture(source: string, expected: string[], inspect?: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiler = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiler.valid, true, compiler.error);
    }
    const program = new Program(file);
    let findings: unknown, paths: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all", false, true).analyze();
      const result = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual([...new Set(result.map(finding => finding.metadata.entry))].sort(), expected.slice().sort());
      findings ??= result; assert.deepEqual(result, findings);
      paths ??= comparablePaths(facts); assert.deepEqual(comparablePaths(facts), paths);
      inspect?.(facts);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.deepEqual([...new Set(result.findings.map(finding => finding.metadata.entry))].sort(), expected.slice().sort());
    }
  });
}

test("required absence connects exact keys to surviving Set and Map insertions", () => {
  fixture(`${header}
export circuit unchecked(): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); accepted = disclose(x); }
export circuit corrected(): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); consume(x); accepted = disclose(x); }
export circuit wrongKey(): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); consume(token()); accepted = disclose(x); }
export circuit wrongCollection(): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); other.insert(disclose(x)); accepted = disclose(x); }
export circuit removed(): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); consume(x); used.remove(disclose(x)); accepted = disclose(x); }
export circuit reset(): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); consume(x); used.resetToDefault(); accepted = disclose(x); }
export circuit reinserted(): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); consume(x); used.resetToDefault(); consume(x); accepted = disclose(x); }
export circuit mapCorrected(): [] { const x = token(); assert(!maps.member(disclose(x)), "fresh"); maps.insert(disclose(x), true); accepted = disclose(x); }
export circuit mapDefault(): [] { const x = token(); assert(!maps.member(disclose(x)), "fresh"); maps.insertDefault(disclose(x)); accepted = disclose(x); }
export circuit late(): [] { const x = token(); const present = used.member(disclose(x)); consume(x); accepted = disclose(x); assert(!present, "fresh"); }
export circuit readOnly(x: Field): Boolean { return !used.member(disclose(x)); }
export circuit ignored(): [] { const x = token(); used.member(disclose(x)); accepted = disclose(x); }
export circuit present(): [] { const x = token(); assert(used.member(disclose(x)), "present"); accepted = disclose(x); }
export circuit tautology(): [] { const x = token(); const p = used.member(disclose(x)); assert(p == p, "same"); accepted = disclose(x); }
export circuit rejected(): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); accepted = disclose(x); assert(false, "disabled"); }
`, ["unchecked", "wrongKey", "wrongCollection", "removed", "reset"]);
});

test("nested receiver selectors retain identity, replacement and possible alias invalidation", () => {
  fixture(`${header}
export circuit corrected(key: Field): [] { const k = disclose(key); const x = token(); assert(!nested.lookup(k).member(disclose(x)), "fresh"); nested.lookup(k).insert(disclose(x)); accepted = disclose(x); }
export circuit wrongKey(first: Field, second: Field): [] { const x = token(); assert(!nested.lookup(disclose(first)).member(disclose(x)), "fresh"); nested.lookup(disclose(second)).insert(disclose(x)); accepted = disclose(x); }
export circuit replaced(key: Field): [] { const k = disclose(key); const x = token(); assert(!nested.lookup(k).member(disclose(x)), "fresh"); nested.lookup(k).insert(disclose(x)); nested.insertDefault(k); accepted = disclose(x); }
export circuit aliasRemoval(key: Field): [] { const x = token(); assert(!nested.lookup(1 as Field).member(disclose(x)), "fresh"); nested.lookup(1 as Field).insert(disclose(x)); nested.lookup(disclose(key)).remove(disclose(x)); accepted = disclose(x); }
export circuit disjoint(): [] { const x = token(); assert(!nested.lookup(1 as Field).member(disclose(x)), "fresh"); nested.lookup(1 as Field).insert(disclose(x)); nested.insertDefault(2 as Field); accepted = disclose(x); }
export circuit outerMembership(key: Field): [] { const k = disclose(key); const x = token(); assert(!nested.member(k), "fresh collection"); nested.insertDefault(k); nested.lookup(k).insert(disclose(x)); accepted = disclose(x); }
ledger counts: Map<Field,Counter>;
export circuit counterValue(key: Field): [] { const k = disclose(key); assert(!counts.member(k), "fresh entry"); counts.insertDefault(k); counts.lookup(k).increment(1); accepted = k; }
`, ["wrongKey", "replaced", "aliasRemoval"]);
});

test("derived nullifiers, stored aliases and required equalities retain exact consumption", () => {
  fixture(`${header}
ledger hashed: Set<Bytes<32>>;
export circuit hashReuse(): [] { const x = token(); const n = persistentHash<Field>(x); assert(!hashed.member(disclose(n)), "fresh"); hashed.insert(disclose(n)); accepted = disclose(x); }
export circuit recomputed(): [] { const x = token(); assert(!hashed.member(disclose(persistentHash<Field>(x))), "fresh"); hashed.insert(disclose(persistentHash<Field>(x))); accepted = disclose(x); }
export circuit arithmetic(): [] { const x = token(); const n = x + (1 as Field); assert(!used.member(disclose(n)), "fresh"); consume(n); accepted = disclose(x); }
export circuit equality(): [] { const x = token(); const y = token(); assert(x == y, "same"); assert(!used.member(disclose(x)), "fresh"); consume(y); accepted = disclose(x); }
export circuit distinct(): [] { const x = token(); const y = token(); assert(x != y, "different"); assert(!used.member(disclose(x)), "fresh"); consume(y); accepted = disclose(x); }
export circuit changed(): [] { accepted = disclose(token()); const x = accepted; assert(!used.member(x), "fresh"); accepted = disclose(token()); used.insert(accepted); }
`, ["distinct", "changed"]);
});

test("branch alternatives and token-only effects use actual successful required absence", () => {
  fixture(`${header}
export circuit partial(choice: Boolean): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); if (disclose(choice)) { consume(x); } accepted = disclose(x); }
export circuit alternate(choice: Boolean): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); if (disclose(choice)) { consume(x); } else { used.insert(disclose(x)); } accepted = disclose(x); }
export circuit transfer(recipient: Either<ContractAddress,UserAddress>): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); sendUnshielded(default<Bytes<32>>, 1, disclose(recipient)); }
export circuit transferCorrected(recipient: Either<ContractAddress,UserAddress>): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); consume(x); sendUnshielded(default<Bytes<32>>, 1, disclose(recipient)); }
`, ["partial", "transfer"]);
});

test("absence decoding and observation exhaustion cannot produce clean or partial rule results", () => {
  fixture(`${header} export circuit unchecked(): [] { const x = token(); assert(!used.member(disclose(x)), "fresh"); accepted = disclose(x); }`, ["unchecked"], facts => {
    assert.equal(unconsumedAbsences(facts.paths[0], 0).complete, false);
    const missing = new Dataflow(facts.program).analyze();
    assert.equal(rule.run(missing).length, 0);
    assert.ok(missing.diagnostics.some(diagnostic => diagnostic.code === "predicate-evidence-unavailable"));
    assert.equal(scanFile(facts.program.root, { detectors: [rule.id], maxSteps: 1 }).status, "incomplete");
  });
});

test("repeated dynamic queries agree through helpers and joins until storage changes", () => {
  fixture(`${header}
ledger roles: Map<Field,Map<Field,Boolean>>;
circuit hasRole(role: Field, account: Field): Boolean {
  if (roles.member(disclose(role)) && roles.lookup(disclose(role)).member(disclose(account))) {
    return roles.lookup(disclose(role)).lookup(disclose(account));
  } else { return false; }
}
export circuit grant(role: Field, account: Field): Boolean {
  if (hasRole(role, account)) { return false; }
  if (!roles.member(disclose(role))) { roles.insert(disclose(role), default<Map<Field,Boolean>>); }
  roles.lookup(disclose(role)).insert(disclose(account), true);
  return true;
}
export circuit repeated(key: Field): [] {
  const k = disclose(key); assert(!used.member(k), "fresh");
  if (!used.member(k)) { used.insert(k); } accepted = k;
}
export circuit independent(first: Field, second: Field): [] {
  const k = disclose(first); assert(!used.member(k), "fresh");
  if (!used.member(disclose(second))) { used.insert(k); } accepted = k;
}
export circuit changed(key: Field): [] {
  const k = disclose(key); assert(!used.member(k), "fresh"); used.insert(k);
  assert(used.member(k), "inserted"); used.remove(k); accepted = k;
}
export circuit saved(key: Field): [] {
  const k = disclose(key); const p = used.member(k); used.insert(k);
  const q = used.member(k); assert(!p, "fresh"); assert(q, "inserted"); accepted = k;
}
`, ["changed", "independent"], facts => {
    const entry = facts.program.entries.find(id => facts.program.symbols.get(id)!.name === "repeated")!;
    assert.equal(facts.paths.filter(path => path.entry === entry).length, 1);
  });
});

test("late aggregate equalities canonicalize components without merging different keys or receivers", () => {
  fixture(`${header}
struct Key { first: Field; second: Field; }
ledger compound: Set<Key>;
ledger compoundReceivers: Map<Key,Set<Field>>;
export circuit corrected(first: Key, second: Key): [] {
  assert(!compound.member(disclose(first)), "fresh"); compound.insert(disclose(second));
  assert(first == second, "same"); accepted = 1 as Field;
}
export circuit partial(first: Key, second: Key): [] {
  assert(!compound.member(disclose(first)), "fresh"); compound.insert(disclose(second));
  assert(first.first == second.first, "one field"); accepted = 1 as Field;
}
export circuit receiver(first: Key, second: Key, value: Field): [] {
  const x = disclose(value); assert(!compoundReceivers.lookup(disclose(first)).member(x), "fresh");
  compoundReceivers.lookup(disclose(second)).insert(x); assert(first == second, "same"); accepted = x;
}
export circuit wrongReceiver(first: Key, second: Key, value: Field): [] {
  const x = disclose(value); assert(!compoundReceivers.lookup(disclose(first)).member(x), "fresh");
  compoundReceivers.lookup(disclose(second)).insert(x); accepted = x;
}
`, ["partial", "wrongReceiver"]);
});

test("default analysis also retains exact dynamic query correlation and revision changes", () => {
  withFiles({ "main.compact": `${header}
circuit present(key: Field): Boolean { return used.member(disclose(key)); }
export circuit impossible(key: Field): [] { assert(!present(key), "absent"); assert(present(key), "present"); accepted = disclose(key); }
export circuit independent(first: Field, second: Field): [] { assert(!present(first), "absent"); assert(present(second), "present"); accepted = disclose(first); }
export circuit changed(key: Field): [] { assert(!present(key), "absent"); used.insert(disclose(key)); assert(present(key), "present"); accepted = disclose(key); }
` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file);
    let baseline: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      const counts = Object.fromEntries(program.entries.map(entry => [program.symbols.get(entry)!.name, facts.paths.filter(path => path.entry === entry).length]));
      assert.deepEqual(counts, { impossible: 0, independent: 1, changed: 1 });
      baseline ??= semanticPaths(facts); assert.deepEqual(semanticPaths(facts), baseline);
    }
  });
});

test("Boolean equality and negation relay required absence without promoting tautologies", () => {
  fixture(`${header}
export circuit relay(key: Field, flag: Boolean): [] {
  const k = disclose(key); const p = used.member(k); assert(p == flag, "same"); assert(!flag, "fresh"); accepted = k;
}
export circuit corrected(key: Field, flag: Boolean): [] {
  const k = disclose(key); const p = used.member(k); assert(p == flag, "same"); assert(!flag, "fresh"); used.insert(k); accepted = k;
}
export circuit negated(key: Field, flag: Boolean): [] {
  const k = disclose(key); const p = used.member(k); assert(p == !flag, "opposite"); assert(flag, "fresh"); accepted = k;
}
export circuit unequal(key: Field, flag: Boolean): [] {
  const k = disclose(key); const p = used.member(k); assert(flag, "fresh"); assert(p != flag, "opposite"); accepted = k;
}
export circuit chained(key: Field, flag: Boolean): [] {
  const k = disclose(key); const p = used.member(k); assert((p == false) == flag, "relay"); assert(flag, "fresh"); accepted = k;
}
export circuit unrelated(key: Field, flag: Boolean): [] {
  const k = disclose(key); used.member(k); assert(!flag, "other"); accepted = k;
}
export circuit tautology(key: Field): [] {
  const k = disclose(key); const p = used.member(k); assert(p != !p, "tautology"); accepted = k;
}
`, ["relay", "negated", "unequal", "chained"]);
});

test("nullifier manifest positive/corrected/lookalike cases are compiler-valid", () => {
  const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8"));
  for (const row of manifest.nullifierConsumption.cases) {
    const file = resolve("tests/corpus", row.file);
    fixture(readFileSync(file, "utf8"), row.lines.length ? ["accept"] : []);
    assert.deepEqual(scanFile(file, { detectors: [rule.id] }).findings.map(finding => finding.location.line), row.lines);
  }
});
