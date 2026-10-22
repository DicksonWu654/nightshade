import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { Program, Dataflow, scanFileIsolated } from "../src/index.js";
import { type Expr, type Pattern, AnalysisError } from "../src/model.js";
import type { FunctionInfo } from "../src/semantic/index.js";
import { LiveSet, liveVariables } from "../src/analysis/liveness.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles, semanticPaths } from "./helpers.js";

// Freeze the previous Set representation as a compatibility oracle. This
// checks every live-in row, including non-owned closure captures and IR temps.
function setLivenessReference(program: Program, fn: FunctionInfo) {
  const patterns = (pattern?: Pattern): string[] => pattern ? [...(pattern.symbol ? [pattern.symbol] : []), ...pattern.children.flatMap(patterns)] : [];
  const owned = (callee: FunctionInfo): Set<string> => new Set([...callee.declaration.parameters.flatMap(parameter => [parameter.symbol!, ...patterns(parameter.pattern)]), ...callee.cfg.nodes.flatMap(node => [...(node.binding ? [node.binding] : []), ...(node.instruction?.result ? [node.instruction.result] : []), ...patterns(node.pattern)])]);
  const captures = new Map<string, Set<string>>();
  const free = (callee: FunctionInfo): Set<string> => {
    const cached = captures.get(callee.symbol.id);
    if (cached) return cached;
    const result = new Set<string>();
    captures.set(callee.symbol.id, result);
    const declared = owned(callee);
    for (const node of callee.cfg.nodes) for (const symbol of node.expr ? used(node.expr) : []) if (!declared.has(symbol)) result.add(symbol);
    return result;
  };
  const used = (expr: Expr): Set<string> => {
    const result = new Set(expr.args.flatMap(arg => [...used(arg)]));
    const symbol = program.symbols.get(expr.symbol ?? "");
    if (expr.kind === "ref" && symbol && ["parameter", "local"].includes(symbol.kind)) result.add(symbol.id);
    const callee = symbol ? program.functions.get(symbol.id) : undefined;
    if (callee) for (const capture of free(callee)) result.add(capture);
    return result;
  };
  const liveIn = new Map(fn.cfg.nodes.map(node => [node.id, new Set<string>()]));
  const uses = new Map(fn.cfg.nodes.map(node => [node.id, new Set([...(node.instruction?.inputs ?? []), ...(node.expr ? used(node.expr) : []), ...(node.instruction?.kind === "evaluate" ? used({ ...node.instruction.expression, args: node.instruction.deferred ? node.instruction.expression.args : node.instruction.expression.kind === "map" || node.instruction.expression.kind === "fold" ? node.instruction.expression.args.slice(0, 1) : [] }) : [])])]));
  const definitions = new Map(fn.cfg.nodes.map(node => [node.id, new Set([...(node.binding ? [node.binding] : []), ...(node.instruction?.result ? [node.instruction.result] : []), ...patterns(node.pattern)])]));
  const incoming = new Map(fn.cfg.nodes.map(node => [node.id, [] as number[]]));
  for (const node of fn.cfg.nodes) for (const edge of node.edges) incoming.get(edge.target)!.push(node.id);
  const remaining = new Map(fn.cfg.nodes.map(node => [node.id, node.edges.length]));
  const pending = fn.cfg.nodes.filter(node => !node.edges.length).map(node => node.id);
  while (pending.length) {
    const node = pending.pop()!;
    const result = new Set(uses.get(node));
    for (const successor of fn.cfg.successors(node)) for (const variable of liveIn.get(successor)!) if (!definitions.get(node)!.has(variable)) result.add(variable);
    liveIn.set(node, result);
    for (const predecessor of incoming.get(node)!) {
      const count = remaining.get(predecessor)! - 1;
      remaining.set(predecessor, count);
      if (count === 0) pending.push(predecessor);
    }
  }
  return { owned: owned(fn), liveIn, joins: new Set([...incoming].filter(([, predecessors]) => predecessors.length > 1).map(([node]) => node)) };
}

for (const size of [0, 31, 32, 33, 63, 64, 65, 96, 97]) test(`indexed liveness retains membership and iteration at ${size} symbols`, () => {
  const symbols = Array.from({ length: size }, (_, index) => String(index));
  const indices = new Map(symbols.map((symbol, index) => [symbol, index]));
  const bits = new Uint32Array(Math.ceil(size / 32));
  for (let index = 0; index < size; index++) bits[index >>> 5] |= 1 << (index & 31);
  const actual = new LiveSet(symbols, indices, bits);
  assert.deepEqual([...actual], symbols);
  for (const symbol of symbols) assert.equal(actual.has(symbol), true);
  assert.equal(actual.has("absent"), false);
});

const capturedSource = `export circuit entry(secret: Field, flag: Boolean): Field {
  ${Array.from({ length: 72 }, (_, index) => `const c${index} = secret + (${index} as Field);`).join("\n")}
  if (disclose(flag)) { disclose(c31); }
  const [one, two] = [c32, c63];
  const result = map((item: Field): Field => item + one + two + c64, [secret]);
  const folded = fold((total: Field, item: Field): Field => total + item + c0, 0 as Field, [c71]);
  assert(flag || secret != (0 as Field), "guard");
  return disclose(result[0] + folded + ${Array.from({ length: 72 }, (_, index) => `c${index}`).join("+")});
}
export circuit empty(): [] {}`;

test("compiler-valid captured and short-circuit liveness matches the Set representation in both CFGs", () => {
  withFiles({ "main.compact": capturedSource }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    for (const fn of program.functions.values()) for (const cfg of [fn.cfg, program.instructionCFG(fn.symbol.id)]) {
      const target = { ...fn, cfg }, expected = setLivenessReference(program, target), actual = liveVariables(program, target);
      assert.deepEqual(actual.owned, expected.owned);
      assert.deepEqual(actual.joins, expected.joins);
      for (const [node, live] of expected.liveIn) {
        assert.deepEqual(new Set(actual.liveIn.get(node)), live, `${fn.symbol.name}:${node}`);
        for (const symbol of expected.owned) assert.equal(actual.liveIn.get(node)!.has(symbol), live.has(symbol));
      }
    }
    let expected: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      const paths = semanticPaths(facts);
      if (expected) assert.deepEqual(paths, expected);
      else expected = paths;
    }
  });
});

test("liveness storage exhaustion is explicit before matrix allocation", () => {
  withFiles({ "main.compact": capturedSource }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const fn = program.functions.get(program.entries[0])!;
    const target = { ...fn, cfg: program.instructionCFG(fn.symbol.id) };
    const measured = liveVariables(program, target);
    assert.ok(measured.storageBytes > 0);
    assert.throws(() => liveVariables(program, target, measured.storageBytes - 1), error => error instanceof AnalysisError && error.diagnostic.code === "liveness-budget");
    assert.equal(liveVariables(program, target, measured.storageBytes).storageBytes, measured.storageBytes);
    const empty = [...program.functions.values()].find(fn => fn.symbol.name === "empty")!;
    assert.equal(liveVariables(program, empty, 0).storageBytes, 0);
  });
});

function wideSource(count: number): string {
  return `export circuit entry(value: Field): Field {
    ${Array.from({ length: count }, (_, index) => `const saved${index} = value + ${index};`).join("\n")}
    ${Array.from({ length: count }, (_, index) => `assert(saved${index} != (0 as Field), "guard ${index}");`).join("\n")}
    return disclose(value);
  }`;
}

test("[timing] compiler-valid wide live ranges return a budget report rather than aborting the default worker", async context => {
  const directory = realpathSync(mkdtempSync(resolve(tmpdir(), "nightshade-wide-liveness-")));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = resolve(directory, "main.compact");
  writeFileSync(file, wideSource(2400));
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const result = await scanFileIsolated(file);
  assert.equal(result.status, "incomplete");
  assert.ok(result.metrics.instructionNodes > 20000);
  assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
  assert.ok(result.diagnostics.every(diagnostic => !diagnostic.code.startsWith("worker-")));
  assert.deepEqual(result.coverage.completedEntries, []);
});

test("[timing] oversized live ranges produce liveness-budget in a scan", async context => {
  const directory = realpathSync(mkdtempSync(resolve(tmpdir(), "nightshade-liveness-budget-")));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = resolve(directory, "main.compact");
  writeFileSync(file, wideSource(3000));
  const result = await scanFileIsolated(file);
  assert.equal(result.status, "incomplete");
  assert.equal(result.diagnostics[0].code, "liveness-budget");
  assert.deepEqual(result.coverage.completedEntries, []);
});

test("[timing] cached liveness tables share one storage allowance across entrypoints", async context => {
  const directory = realpathSync(mkdtempSync(resolve(tmpdir(), "nightshade-shared-liveness-")));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const file = resolve(directory, "main.compact");
  writeFileSync(file, wideSource(1800).replace("circuit entry(", "circuit first(") + "\n" + wideSource(1800).replace("circuit entry(", "circuit second("));
  const program = new Program(file);
  // Each table fits independently. Keeping both exceeds the shared allowance.
  for (const entry of program.entries) {
    const fn = program.functions.get(entry)!;
    assert.ok(liveVariables(program, { ...fn, cfg: program.instructionCFG(entry) }).storageBytes < 64 * 1024 * 1024);
  }
  const result = await scanFileIsolated(file);
  assert.equal(result.status, "incomplete");
  assert.equal(result.diagnostics[0].code, "liveness-budget");
  assert.deepEqual(result.coverage.completedEntries, []);
});
