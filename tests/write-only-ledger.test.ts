import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, ledgerUsage, cachedLedgerUsage } from "../src/index.js";
import { writeOnlyLedger as rule } from "../src/detectors/informational.js";
import { sourceObservations } from "../src/analysis/source-observations.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const header = "pragma language_version >= 0.26.0; import CompactStandardLibrary;\n";
function checked(source: string, inspect: (program: Program, file: string) => void, files: Record<string, string> = {}): void {
  withFiles({ ...files, "main.compact": header + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    inspect(new Program(file), file);
  });
}
function agree(program: Program, names: string[]): void {
  const query = ledgerUsage(program);
  assert.equal(query.complete, true, JSON.stringify(query.issues));
  assert.deepEqual(query.observations.map(item => item.name).sort(), names);
  let oracle: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
    assert.deepEqual(facts.diagnostics, []);
    const findings = rule.run(facts);
    assert.deepEqual(findings.map(item => item.metadata.ledger).sort(), names);
    assert.ok(findings.every(item => item.severity === "info" && item.confidence === "high"
      && item.metadata.evidence === "resolved-ledger-writes-no-source-reads" && item.metadata.offchainReads === "not-analyzed"));
    oracle ??= findings;
    assert.deepEqual(findings, oracle, `${engine}/${cached}`);
  }
}

test("explicitly written Cells extend unused declarations with a precise source fact", () => {
  checked(`ledger role: Bytes<32>; ledger unused: Field;
    constructor(value: Bytes<32>) { role = disclose(value); }
    export circuit getRole(): Bytes<32> { return default<Bytes<32>>; }`, (program, file) => {
    agree(program, ["role"]);
    const unused = sourceObservations(program).observations.filter(item => item.kind === "unused-declaration");
    assert.deepEqual(unused.map(item => item.metadata.symbol), ["unused"]);
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(item => item.metadata.ledger), ["role"]);
    const normal = scanFile(file);
    assert.deepEqual(normal.findings.filter(item => item.detectorId === rule.id), []);
    assert.ok(!normal.coverage.detectors.includes(rule.id));
    assert.ok(report.findings[0].metadata.writers);
  });
});

test("bare reads, explicit methods, RHS projections and helper reads withhold absence", () => {
  for (const reader of ["return role;", "return role.read();", "return identity(role);", "return helper();"]) {
    checked(`ledger role: Field;
      constructor() { role.write(3 as Field); }
      circuit identity(value: Field): Field { return value; }
      ${reader === "return helper();" ? "circuit helper(): Field { return role; }" : ""}
      export circuit getRole(): Field { ${reader} }`, program => agree(program, []));
  }
  checked(`ledger role: Field;
    export circuit put(): [] { role = role + 1 as Field; }`, program => agree(program, []));
  checked(`struct Configuration { role: Field; }
    ledger settings: Configuration;
    constructor() { settings = Configuration { role: 3 as Field }; }
    export circuit getRole(): Field { return settings.role; }`, program => agree(program, []));
});

test("unreachable helpers and source-excluded reads still count as source reads", () => {
  checked(`ledger role: Field;
    constructor() { role = 3 as Field; }
    circuit unusedReader(): Field { return role; }
    export circuit getRole(): Field { return 0 as Field; }`, program => agree(program, []));
  checked(`ledger role: Field;
    constructor() { role = 3 as Field; }
    export circuit getRole(): Field { if (false) { return role; } return 0 as Field; }`, program => agree(program, []));
});

test("callback captures, helper transport and zero-iteration callback reads are retained", () => {
  for (const values of ["[1 as Field]", "default<Vector<0, Field>>"]) {
    checked(`ledger role: Field;
      constructor() { role = 3 as Field; }
      circuit read(value: Field): Field { return role; }
      export circuit getRole(): [] { map(read, ${values}); }`, program => agree(program, []));
  }
  checked(`ledger role: Field;
    constructor() { role = 3 as Field; }
    export circuit getRole(): Vector<1, Field> { return map((value: Field): Field => role, [1 as Field]); }`, program => agree(program, []));
});

test("native ADT mutations and nested receivers are excluded", () => {
  checked(`export ledger count: Counter;
    ledger members: Map<Field, Field>; ledger nested: Map<Field, Counter>;
    export circuit put(): [] {
      count.increment(1); members.insert(1 as Field, 2 as Field);
      nested.insert(1 as Field, default<Counter>);
    }`, program => agree(program, []));
});

test("same-name module fields retain canonical identity and one finding per declaration", () => {
  checked(`module A { export ledger setting: Field;
      export circuit initialize(): [] { setting = 1 as Field; } }
    module B { export ledger setting: Field;
      export circuit initialize(): [] { setting = 2 as Field; }
      export circuit read(): Field { return setting; } }
    import A prefix A_; import B prefix B_;
    export circuit initialize(): [] { A_initialize(); B_initialize(); }
    export circuit read(): Field { return B_read(); }`, program => {
    agree(program, ["setting"]);
    const item = ledgerUsage(program).observations[0];
    assert.equal(item.location.line, 2);
    assert.deepEqual([...new Set(item.instances.map(id => program.symbols.get(id)!.span.start))], [item.location.start]);
    const reader = program.entries.find(id => program.symbols.get(id)!.name === "read")!;
    assert.ok(item.instances.every(id => !program.functions.get(reader)!.readsState.has(id)));
  });
  checked(`module Store<T> { export ledger setting: Field;
      export circuit initialize(): [] { setting = 1 as Field; }
      export circuit read(): Field { return setting; } }
    import Store<Field> prefix A_; import Store<Boolean> prefix B_;
    export circuit initialize(): [] { A_initialize(); B_initialize(); }
    export circuit read(): Field { return A_read(); }`, program => agree(program, []));
});

test("imported prefixed reads are not lost across the physical file boundary", () => {
  checked(`import "Store" prefix Stored_;
    export circuit initialize(): [] { Stored_initialize(); }
    export circuit read(): Field { return Stored_read(); }`, program => agree(program, []), {
    "Store.compact": `module Store { import CompactStandardLibrary; export ledger setting: Field;
      export circuit initialize(): [] { setting = 1 as Field; }
      export circuit read(): Field { return setting; } }`,
  });
});

test("uninstantiated generic may-reads are explicitly rule-incomplete while baseline completes", () => {
  checked(`ledger role: Field;
    constructor() { role = 3 as Field; }
    circuit future<T>(value: T): Field { return role; }
    export circuit getRole(): Field { return 0 as Field; }`, (program, file) => {
    const query = ledgerUsage(program);
    assert.equal(query.complete, false);
    assert.deepEqual(query.observations, []);
    assert.deepEqual(query.issues.map(item => item.code), ["ledger-usage-source-unavailable"]);
    const baseline = scanFile(file, { detectors: [] });
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(baseline.status, "complete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.coverage.completedEntries, baseline.coverage.completedEntries);
    assert.equal(report.status, "incomplete");
    assert.ok(report.diagnostics.every(issue => issue.scope?.detectorId === rule.id));
    assert.ok(report.coverage.rules!.every(row => row.detectorId === rule.id && row.status === "incomplete"));
  });
});

test("budget exhaustion supplies no absence and cannot exhaust existing source observations", () => {
  checked(`ledger role: Field; export circuit initialize(): [] { role = 1 as Field; }`, program => {
    const before = sourceObservations(program), query = ledgerUsage(program);
    assert.equal(query.complete, true);
    assert.deepEqual(ledgerUsage(program, query.work), query);
    const exhausted = ledgerUsage(program, query.work - 1);
    assert.equal(exhausted.complete, false);
    assert.deepEqual(exhausted.observations, []);
    assert.deepEqual(exhausted.issues.map(item => item.code), ["ledger-usage-budget"]);
    assert.deepEqual(sourceObservations(program), before);
    assert.equal(cachedLedgerUsage(program), cachedLedgerUsage(program));
  });
});

test("selected import aliases in uninstantiated generics cannot borrow read absence", () => {
  checked(`module Store { export ledger role: Field;
      export circuit initialize(): [] { role = 3 as Field; } }
    import { role as adminValue, initialize } from Store;
    circuit future<T>(value: T): Field { return adminValue; }
    export circuit put(): [] { initialize(); }`, (program, file) => {
    const usage = ledgerUsage(program);
    assert.equal(usage.complete, false);
    assert.deepEqual(usage.observations, []);
    assert.deepEqual(usage.issues.map(item => item.code), ["ledger-usage-source-unavailable"]);
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.equal(report.status, "incomplete");
    assert.ok(report.diagnostics.every(issue => issue.scope?.detectorId === rule.id));
  });
});

test("a native sibling reader cannot certify an unbound generic Cell instance", () => {
  checked(`module Store<T> {
      export ledger setting: T;
      export circuit read(): [] { setting.read(); }
    }
    import Store<Counter> prefix A_; import Store<Field> prefix B_;
    constructor() { B_setting = 3 as Field; }
    export circuit touch(): [] { A_read(); }`, (program, file) => {
    const before = cachedLedgerUsage(program);
    assert.equal(before.complete, false);
    assert.deepEqual(before.observations, []);
    assert.deepEqual(before.issues.map(item => item.code), ["ledger-usage-source-unavailable"]);
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.equal(report.status, "incomplete");
    assert.deepEqual(report.findings, []);
    assert.ok(report.diagnostics.every(issue => issue.scope?.detectorId === rule.id));

    // Bind the concrete Cell reader lazily: the cache must notice the newly
    // represented function and replace uncertainty with its actual read fact.
    const reader = program.activeSymbols().find(symbol => symbol.name === "read"
      && !program.functions.has(symbol.id));
    assert.ok(reader);
    const bound = program.ensureFunction(reader.id);
    assert.ok(bound && [...bound.readsState].some(id => program.representationOf(program.symbols.get(id)!.type) === "Field"));
    const after = cachedLedgerUsage(program);
    assert.notEqual(after, before);
    assert.equal(after.complete, true);
    assert.deepEqual(after.observations, []);
  });
});

test("included generic reader bodies retain instance identity for absence screening", () => {
  checked(`module Store<T> { export ledger setting: T; include "reader"; }
    import Store<Counter> prefix A_; import Store<Field> prefix B_;
    constructor() { B_setting = 3 as Field; }
    export circuit touch(): [] { A_read(); }`, (program, file) => {
    const usage = ledgerUsage(program);
    assert.equal(usage.complete, false);
    assert.deepEqual(usage.observations, []);
    assert.ok(usage.issues.every(issue => issue.code === "ledger-usage-source-unavailable"
      && issue.location.file.endsWith("reader.compact")));
    assert.ok(usage.issues.length > 0);
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.equal(report.status, "incomplete");
    assert.deepEqual(report.findings, []);
    assert.ok(report.diagnostics.every(issue => issue.scope?.detectorId === rule.id));
  }, { "reader.compact": "export circuit read(): [] { setting.read(); }" });
});

test("unbound generic write targets are not reads, but their RHS and operands are", () => {
  for (const write of ["setting = value;", "setting.write(value);"]) {
    checked(`module Store<T> { export ledger setting: T;
        export circuit initialize(value: T): [] { ${write} } }
      import Store<Field> prefix Store_;
      constructor() { Store_initialize(3 as Field); }
      export circuit noop(): [] { }`, program => agree(program, ["setting"]));
  }
  checked(`ledger setting: Field;
    constructor() { setting = 3 as Field; }
    circuit future<T>(value: T): [] { setting.write(setting); }
    export circuit noop(): [] { }`, program => {
    const usage = ledgerUsage(program);
    assert.equal(usage.complete, false);
    assert.deepEqual(usage.observations, []);
    assert.deepEqual(usage.issues.map(issue => issue.code), ["ledger-usage-source-unavailable"]);
  });
});

test("owned Counter seed and quiet controls agree across the five corpus compiler profiles", () => {
  for (const [version, variable] of [["0.30.0", "COMPACTC_030_TEST"], ["0.31.1", "COMPACTC_031_TEST"],
    ["0.33.0-rc.2", "COMPACTC_033_RC2_TEST"], ["0.34.0", "COMPACTC_TEST"], ["0.35.0", "COMPACTC_035_TEST"]] as const) {
    for (const kind of ["positive", "corrected", "lookalike"]) {
      const file = resolve(`tests/corpus/known-bugs/counter-write-only-ledger-${kind}.compact`);
      if (process.env[variable]) {
        const compiled = validateWithCompiler(process.env[variable]!, file, [], 30000, 2, version);
        assert.equal(compiled.valid, true, `${version}/${kind}: ${compiled.error}`);
      }
      const report = scanFile(file, { compilerVersion: version, detectors: [rule.id] });
      assert.equal(report.status, "complete", `${version}/${kind}: ${JSON.stringify(report.diagnostics)}`);
      assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [29] : []);
      assert.ok(report.findings.every(item => Array.isArray(item.metadata.instances) && item.metadata.instances.length === 1), "Template and native Counter storage must not appear in the Cell observation");
    }
  }
});

test("unbound parameters and block/lambda locals do not impersonate written ledger fields", () => {
  for (const future of [
    "circuit future<T>(output: T): T { return output; }",
    "circuit future<T>(value: T): T { const output = value; return output; }",
    "circuit future<T>(value: T): [] { for (const output of 0..1) { output; } }",
    "circuit future<T>(value: T): Vector<1, Field> { return map((output: Field): Field => output, [1 as Field]); }",
  ]) checked(`ledger output: Field;
    constructor() { output = 3 as Field; } ${future}
    export circuit noop(): [] { }`, program => agree(program, ["output"]));

  for (const read of [
    "{ const output = 1 as Field; } return output;",
    "return map((value: Field): Field => output, [1 as Field])[0];",
  ]) checked(`ledger output: Field;
    constructor() { output = 3 as Field; }
    circuit future<T>(value: T): Field { ${read} }
    export circuit noop(): [] { }`, program => {
    const usage = ledgerUsage(program);
    assert.equal(usage.complete, false);
    assert.deepEqual(usage.observations, []);
    assert.deepEqual(usage.issues.map(issue => issue.code), ["ledger-usage-source-unavailable"]);
  });
});

test("unbound natural parameters shadow outer storage only in their defining scope", () => {
  for (const future of [
    "circuit future<#N>(): Field { return N as Field; }",
    "module Future<#N> { export circuit future(): Field { return N as Field; } }",
  ]) checked(`ledger N: Field;
    constructor() { N = 3 as Field; } ${future}
    export circuit noop(): [] { }`, program => agree(program, ["N"]));

  checked(`ledger N: Field;
    constructor() { N = 3 as Field; }
    circuit future<#M>(): Field { return N; }
    export circuit noop(): [] { }`, program => {
    const usage = ledgerUsage(program);
    assert.equal(usage.complete, false);
    assert.deepEqual(usage.observations, []);
    assert.deepEqual(usage.issues.map(issue => issue.code), ["ledger-usage-source-unavailable"]);
  });
});
