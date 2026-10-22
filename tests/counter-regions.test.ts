import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { extractTerminalCounterRegion, type CounterRegionExtraction } from "../src/analysis/counter-regions.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { Program } from "../src/semantic/index.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const prelude = "pragma language_version 0.26.0; import CompactStandardLibrary; export ledger count: Counter; ";
const fixedWorkload = (size: number): string => `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: size }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { ${Array.from({ length: size }, (_, index) => `if (disclose(flag${index})) { count.increment(1); }`).join(" ")} }`;

function source(source: string, callback: (program: Program, entry: string) => void, compiler = false): void {
  withFiles({ "main.compact": source }, directory => {
    const path = resolve(directory, "main.compact");
    if (compiler) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST!, path);
      assert.equal(result.valid, true, result.error);
    }
    const program = new Program(path);
    callback(program, program.entries.find(id => program.symbols.get(id)?.name === "entry")!);
  });
}

function eligible(result: CounterRegionExtraction) {
  assert.equal(result.status, "eligible", result.status === "ineligible" ? result.reason : result.status === "incomplete" ? JSON.stringify(result) : undefined);
  assert.ok(result.status === "eligible");
  return result.region;
}

for (const size of [4, 6, 10]) test(`qualified unchanged fixed stateful-branches-${size} source is eligible`, qualified, () => {
  source(fixedWorkload(size), (program, entry) => {
    const region = eligible(extractTerminalCounterRegion(program, entry));
    assert.equal(region.diamonds.length, size);
    assert.deepEqual(region.diamonds.map(diamond => diamond.amount), Array(size).fill(1n));
    assert.deepEqual(region.diamonds.map(diamond => diamond.parameter), program.functions.get(entry)!.declaration.parameters.map(parameter => parameter.symbol));
    assert.equal(region.ledger, program.activeSymbols().find(symbol => symbol.kind === "ledger")!.id);
    assert.equal(region.resetLocation, undefined);
    assert.equal(region.returnLocation, undefined);
  }, true);
});

for (const size of [1, 2, 8, 10]) test(`qualified initialized ${size}-diamond variant retains constant operands and terminal void return`, qualified, () => {
  const text = fixedWorkload(size).replace("{ if", "{ count.resetToDefault(); if")
    .replaceAll("increment(1)", "increment(65535 as Uint<16>)").replaceAll("; }", "; } else {}")
    .replace(/ }$/, " return []; }");
  source(text, (program, entry) => {
    const region = eligible(extractTerminalCounterRegion(program, entry));
    assert.deepEqual(region.diamonds.map(diamond => diamond.amount), Array(size).fill(65535n));
    assert.ok(region.resetLocation);
    assert.ok(region.returnLocation);
    for (const graph of Object.values(region.graphs)) {
      assert.ok(graph.reset);
      assert.notEqual(graph.return, undefined);
      assert.equal(graph.reset.abort, graph.abort);
    }
  }, true);
});

test("qualified zero/hex literals and imported canonical Counter ignore same-name user types", qualified, () => {
  source(`pragma language_version 0.26.0; import { Counter as Count } from CompactStandardLibrary;
    struct Counter { increment: Field; }
    export ledger arbitraryName: Count;
    export circuit entry(first: Boolean, second: Boolean): [] {
      if (disclose(first)) arbitraryName.increment(0);
      if (disclose(second)) { arbitraryName.increment(0xffff); } else { {} }
    }`, (program, entry) => {
    const region = eligible(extractTerminalCounterRegion(program, entry));
    assert.deepEqual(region.diamonds.map(diamond => diamond.amount), [0n, 65535n]);
    assert.equal(program.symbols.get(region.ledger)!.name, "arbitraryName");
  }, true);
});

test("qualified aliases to one canonical root remain one Counter region", qualified, () => {
  source(`pragma language_version 0.26.0; import CompactStandardLibrary;
    module Store { export ledger count: Counter; }
    import Store prefix First_; import Store prefix Second_;
    export { First_count };
    export circuit entry(first: Boolean, second: Boolean): [] {
      First_count.resetToDefault();
      if (disclose(first)) First_count.increment(1);
      if (disclose(second)) Second_count.increment(2);
    }`, (program, entry) => {
    const region = eligible(extractTerminalCounterRegion(program, entry));
    assert.equal(program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 1);
    assert.deepEqual(region.diamonds.map(diamond => diamond.amount), [1n, 2n]);
  }, true);
});

test("CFG sites retain abort-sensitive control expiry rather than syntactic continuation", () => {
  const text = prelude + `export circuit entry(first: Boolean, second: Boolean): [] {
    count.resetToDefault();
    if (disclose(first)) { count.increment(0 as Uint<16>); }
    if (disclose(second)) { count.increment(2); }
    return [];
  }`;
  source(text, (program, entry) => {
    const region = eligible(extractTerminalCounterRegion(program, entry));
    for (const [name, graph] of Object.entries(region.graphs)) {
      const cfg = name === "statements" ? program.functions.get(entry)!.cfg : program.instructionCFG(entry);
      for (const diamond of graph.diamonds) {
        assert.equal(diamond.controlJoin, cfg.nodes[diamond.branch].join);
        assert.equal(diamond.controlJoin, -1, "even zero increments retain the CFG's modeled abort path");
        assert.notEqual(diamond.controlJoin, diamond.normalContinuation);
        assert.deepEqual(cfg.nodes[diamond.branch].edges, [{ target: diamond.trueEntry, condition: true }, { target: diamond.normalContinuation, condition: false }]);
        assert.ok(cfg.nodes[diamond.increment.node].edges.some(edge => edge.target === graph.abort));
        assert.equal(diamond.increment.abort, graph.abort);
        const effect = cfg.nodes[diamond.increment.node];
        assert.equal(effect.expr?.kind ?? (effect.instruction?.kind === "evaluate" && effect.instruction.expression.kind), "member");
      }
      assert.equal(cfg.nodes[graph.return!].kind, "return");
      assert.ok(cfg.nodes[graph.reset!.node].edges.some(edge => edge.target === graph.abort));
    }
  });
});

test("source locations preserve exact occurrences, UTF-8 bytes and UTF-16 columns", () => {
  const text = prelude + "// 🕯\r\nexport circuit entry(first: Boolean, second: Boolean): [] { /* 🕯 */ if (disclose(first)) count.increment(1); if (disclose(second)) count.increment(1); }";
  source(text, (program, entry) => {
    const region = eligible(extractTerminalCounterRegion(program, entry));
    let from = 0;
    for (const diamond of region.diamonds) {
      const start = text.indexOf("count.increment(1)", from);
      const end = start + "count.increment(1)".length;
      assert.equal(diamond.incrementLocation.start, Buffer.byteLength(text.slice(0, start)));
      assert.equal(diamond.incrementLocation.end, Buffer.byteLength(text.slice(0, end)));
      assert.equal(diamond.incrementLocation.column, start - text.lastIndexOf("\n", start));
      from = end;
    }
    const before = program.functions.get(entry)!.declaration.span.start;
    region.location.start = -1;
    assert.equal(program.functions.get(entry)!.declaration.span.start, before, "extraction locations are detached");
  });
});

const negativeBodies = [
  ["reused flag", "if (disclose(flag)) count.increment(1); if (disclose(flag)) count.increment(2);"],
  ["nonempty false arm", "if (disclose(flag)) count.increment(1); else count.increment(2);"],
  ["two true-arm writes", "if (disclose(flag)) { count.increment(1); count.increment(2); }"],
  ["nested branch", "if (disclose(flag)) { if (disclose(other)) count.increment(1); }"],
  ["loop-expanded diamonds", "for (const index of 0..2) { if (disclose(flag)) count.increment(1); }"],
  ["decrement", "if (disclose(flag)) count.decrement(1);"],
  ["compound mutation", "if (disclose(flag)) count += 1;"],
  ["unconditional increment prefix", "count.increment(1); if (disclose(flag)) count.increment(1);"],
  ["reset after branch", "if (disclose(flag)) count.increment(1); count.resetToDefault();"],
  ["second reset prefix", "count.resetToDefault(); count.resetToDefault(); if (disclose(flag)) count.increment(1);"],
  ["following state read", "if (disclose(flag)) count.increment(1); count.read();"],
  ["following assertion", "if (disclose(flag)) count.increment(1); assert(count.read() == 0, \"count\");"],
  ["true-arm assertion", "if (disclose(flag)) { assert(true, \"check\"); count.increment(1); }"],
  ["early return", "if (disclose(flag)) return []; if (disclose(other)) count.increment(1);"],
  ["local flag snapshot", "const saved = flag; if (disclose(saved)) count.increment(1);"],
  ["computed flag", "if (disclose(flag && other)) count.increment(1);"],
  ["parameter amount", "if (disclose(flag)) count.increment(disclose(amount));"],
  ["constant expression", "if (disclose(flag)) count.increment(1 + 1);"],
  ["local amount", "const one: Uint<16> = 1; if (disclose(flag)) count.increment(one);"],
  ["capturing callback", "map((item: Boolean): Boolean => flag, [true]); if (disclose(flag)) count.increment(1);"],
  ["no diamonds", "count.resetToDefault();"],
] as const;

for (const [name, body] of negativeBodies) test(`qualified exact-engine fallback: ${name}`, qualified, () => {
  source(prelude + `export circuit entry(flag: Boolean, other: Boolean, amount: Uint<16>): [] { ${body} }`, (program, entry) => {
    const result = extractTerminalCounterRegion(program, entry);
    assert.equal(result.status, "ineligible", name);
    assert.equal(program.instructionNodeCount(), 0, "rejected source does not lower instructions");
  }, true);
});

const negativeSources = [
  ["projected parameter pattern", prelude + "export circuit entry([flag]: [Boolean]): [] { if (disclose(flag)) count.increment(1); }"],
  ["typed empty result schema", prelude + "export circuit entry(flag: Boolean): Vector<0,Field> { if (disclose(flag)) count.increment(1); return []; }"],
  ["nested storage", prelude + "export ledger table: Map<Field,Counter>; export circuit entry(flag: Boolean): [] { if (disclose(flag)) table.lookup(0 as Field).increment(1); }"],
  ["witness amount", prelude + "witness amount(): Uint<16>; export circuit entry(flag: Boolean): [] { if (disclose(flag)) count.increment(disclose(amount())); }"],
  ["same-name user circuit", prelude + "circuit increment(): [] { count.increment(1); } export circuit entry(flag: Boolean): [] { if (disclose(flag)) increment(); }"],
  ["helper condition", prelude + "circuit choose(flag: Boolean): Boolean { return flag; } export circuit entry(flag: Boolean): [] { if (disclose(choose(flag))) count.increment(1); }"],
  ["ledger condition", prelude + "export ledger flag: Boolean; export circuit entry(): [] { if (disclose(flag)) count.increment(1); }"],
  ["following state return", prelude + "export circuit entry(flag: Boolean): Uint<64> { if (disclose(flag)) count.increment(1); return count.read(); }"],
  ["same-name user Counter reset", "pragma language_version 0.26.0; import { Counter as Count } from CompactStandardLibrary; struct Counter { increment: Field; } export ledger fake: Counter; export ledger count: Count; export circuit entry(flag: Boolean): [] { fake.resetToDefault(); if (disclose(flag)) count.increment(1); }"],
  ["distinct same-name module ledgers", "pragma language_version 0.26.0; import CompactStandardLibrary; module First { export ledger count: Counter; } module Second { export ledger count: Counter; } import First prefix A_; import Second prefix B_; export { A_count, B_count }; export circuit entry(first: Boolean, second: Boolean): [] { if (disclose(first)) A_count.increment(1); if (disclose(second)) B_count.increment(1); }"],
] as const;

for (const [name, text] of negativeSources) test(`qualified identity/effect fallback: ${name}`, qualified, () => {
  source(text, (program, entry) => assert.equal(extractTerminalCounterRegion(program, entry).status, "ineligible"), true);
});

test("private direct conditions and non-entry helpers are not eligible", () => {
  source(prelude + "circuit helper(flag: Boolean): [] { if (disclose(flag)) count.increment(1); } export circuit entry(flag: Boolean): [] { if (flag) count.increment(1); }", (program, entry) => {
    assert.equal(extractTerminalCounterRegion(program, entry).status, "ineligible");
    const helper = program.activeSymbols().find(symbol => symbol.name === "helper")!;
    program.ensureFunction(helper.id);
    assert.equal(extractTerminalCounterRegion(program, helper.id).status, "ineligible");
    assert.equal(extractTerminalCounterRegion(program, "missing").status, "ineligible");
  });
});

test("source, combined CFG and branch extraction budgets never return eligible prefixes", () => {
  source(fixedWorkload(4), (program, entry) => {
    const result = extractTerminalCounterRegion(program, entry);
    assert.equal(result.status, "eligible");
    for (const [limit, used] of [["maxSyntaxNodes", result.work.syntaxNodes], ["maxCFGNodes", result.work.cfgNodes], ["maxBranches", result.work.branches]] as const) {
      const exhausted = extractTerminalCounterRegion(program, entry, { [limit]: used - 1 });
      assert.equal(exhausted.status, "incomplete", limit);
      assert.ok(exhausted.status === "incomplete");
      assert.deepEqual(exhausted.diagnostics.map(diagnostic => diagnostic.code), ["counter-region-budget"]);
      assert.equal("region" in exhausted, false);
      assert.equal(extractTerminalCounterRegion(program, entry, { [limit]: used }).status, "eligible", `${limit} exact bound`);
    }
    assert.throws(() => extractTerminalCounterRegion(program, entry, { maxBranches: 0 }));
    assert.throws(() => extractTerminalCounterRegion(program, entry, { maxSyntaxNodes: NaN }));
  });
  source(fixedWorkload(10), (program, entry) => {
    assert.equal(program.instructionNodeCount(), 0);
    const result = extractTerminalCounterRegion(program, entry, { maxCFGNodes: program.functions.get(entry)!.cfg.nodes.length });
    assert.equal(result.status, "incomplete");
    assert.equal(program.instructionNodeCount(), 0, "combined CFG budget is checked before lowering");
  });
});

test("source eligibility does not admit a CFG that skips later effects or loses abort edges", () => {
  source(fixedWorkload(2), (program, entry) => {
    const region = eligible(extractTerminalCounterRegion(program, entry));
    const cfg = program.functions.get(entry)!.cfg;
    const increment = cfg.nodes[region.graphs.statements.diamonds[0].increment.node];
    increment.edges.find(edge => edge.target !== cfg.abort)!.target = cfg.exit;
    assert.equal(extractTerminalCounterRegion(program, entry).status, "ineligible");
  });
  source(fixedWorkload(2), (program, entry) => {
    const region = eligible(extractTerminalCounterRegion(program, entry));
    const cfg = program.instructionCFG(entry);
    const increment = cfg.nodes[region.graphs.instructions.diamonds[0].increment.node];
    increment.edges = increment.edges.filter(edge => edge.target !== cfg.abort);
    assert.equal(extractTerminalCounterRegion(program, entry).status, "ineligible");
  });
});
