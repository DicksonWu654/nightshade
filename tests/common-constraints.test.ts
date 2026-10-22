import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, type AbstractValue } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { commonScalarConstraints } from "../src/dataflow/common-constraints.js";
import { commonScalarConstraints as beforeB1 } from "./fixtures/common-constraints-before-b1.js";
import { HashRecipes } from "../src/dataflow/hash-recipes.js";
import { assumeScalar, binaryValue, refineScalar, type ScalarConstraints } from "../src/dataflow/transfers.js";
import type { Instruction } from "../src/ir/index.js";
import type { Span } from "../src/model.js";
import { withFiles } from "./helpers.js";

const location: Span = { file: "owned", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
const value = (identity: string): AbstractValue => ({ flows: [], ledger: new Set(), identity, type: "Uint<64>" });
const number = (constant: number): AbstractValue => ({ flows: [], ledger: new Set(), type: "Uint<64>", constantKind: "integer", constant: String(constant) });
const fresh = (): ScalarConstraints => ({ known: new Map(), truths: new Map(), excluded: new Map(), aggregateExclusions: new Map(), aggregateExclusionLeaves: 0, aggregateExclusionsExhausted: false });
const copy = (state: ScalarConstraints): ScalarConstraints => ({ ...state, known: new Map(state.known), truths: new Map(state.truths),
  excluded: new Map([...state.excluded].map(([key, values]) => [key, new Set(values)])), aggregateExclusions: new Map(state.aggregateExclusions),
  scalarEqualities: state.scalarEqualities && new Map(state.scalarEqualities), orderings: state.orderings && new Map(state.orderings) });
const predicate = (a: AbstractValue, operator: string, b: AbstractValue) => binaryValue([a, b], operator, location, "Uint<64>")!;
const assume = (state: ScalarConstraints, a: AbstractValue, operator: string, b: AbstractValue) => assert.equal(assumeScalar(predicate(a, operator, b), true, state), true);
const joined = (left: ScalarConstraints, right: ScalarConstraints): ScalarConstraints => {
  let work = 0, values = 0;
  const result = commonScalarConstraints(left, right, (w, v) => { work += w; values += v; return work <= 40000 && values <= 50000; });
  assert.equal(result.status, "available", result.status === "incomplete" ? result.reason : "");
  return result.constraints;
};

test("B1 scalar semantics match the frozen prior join through reversed and repeated joins", () => {
  for (const reverse of [false, true]) for (const recipesEnabled of [false, true]) {
    const recipes = recipesEnabled ? new HashRecipes(() => true, () => assert.fail("unexpected recipe exhaustion")) : undefined;
    const left = { ...fresh(), hashRecipes: recipes }, right = { ...fresh(), hashRecipes: recipes };
    const a = value("a"), b = value("b"), c = value("c"), d = value("d"), pinned = value("pinned"), pinnedPeer = value("pinned-peer");
    assume(left, a, "==", b); assume(right, a, "==", c); assume(right, c, "==", b);
    assume(left, pinned, "==", number(5)); assume(right, pinned, "==", number(5));
    assume(left, pinnedPeer, "==", number(5)); assume(right, pinnedPeer, "==", number(5));
    assume(left, b, "!=", number(4)); assume(right, a, "!=", number(4));
    assume(left, a, "<", number(9)); assume(right, a, "<", number(7));
    // Independent observation objects, equal immutable predicate keys.
    assume(left, a, "<", d); assume(right, a, "<", d);
    const splitOperand = value("split");
    const split = predicate(splitOperand, "<", d);
    assert.equal(assumeScalar(split, true, left), true);
    assert.equal(assumeScalar(split, false, right), true);
    left.truths.set("truth-only", true); right.truths.set("truth-only", true);
    const operands = [a, b, c, d, pinned, pinnedPeer, splitOperand, { ...value("truth-only"), type: "Boolean" }];
    if (recipes) {
      const choice = recipes.choose("selector", "a", "b")!;
      const selected = value(choice);
      assert.equal(assumeScalar({ ...value("selector"), type: "Boolean" }, true, left), true);
      assert.equal(assumeScalar({ ...value("selector"), type: "Boolean" }, false, right), true);
      assume(left, selected, "!=", number(4)); assume(right, selected, "!=", number(4));
      operands.push(selected);
    }
    const inputs = reverse ? [right, left] : [left, right];
    const before = inputs.map(copy);
    const run = (join: typeof commonScalarConstraints, first: ScalarConstraints, second: ScalarConstraints): ScalarConstraints => {
      let steps = 0, values = 0;
      const result = join(first, second, (work, allocated) => (steps += work) <= 400000 && (values += allocated) <= 50000);
      assert.equal(result.status, "available", result.status === "incomplete" ? result.reason : "");
      return result.constraints;
    };
    let current = run(commonScalarConstraints, inputs[0], inputs[1]);
    let prior = run(beforeB1, inputs[0], inputs[1]);
    assert.deepEqual(inputs, before, "join must preserve both input states");
    const comparisons = operands.flatMap(first => [...operands, number(4), number(5), number(7), number(9)]
      .filter(second => first.type === second.type)
      .flatMap(second => (first.type === "Boolean" ? ["==", "!="] : ["==", "!=", "<", "<=", ">", ">="])
        .map(operator => predicate(first, operator, second))));
    const queries = [...operands, ...comparisons];
    // assumeScalar consumes Boolean guards after semantic type validation.
    // Numeric operands remain refinement queries; asserting a Uint directly
    // would overwrite its known integer with a Boolean outside this contract.
    const guards = [...operands.filter(operand => operand.type === "Boolean"), ...comparisons];
    for (let iteration = 0; iteration < 2; iteration++) {
      for (const query of queries) assert.deepEqual(refineScalar(query, current), refineScalar(query, prior),
        `query ${query.identity}; reversed=${reverse}; recipes=${recipesEnabled}; iteration=${iteration}`);
      // Shared constants omit redundant edge syntax, but all represented
      // facts and subsequent constraints must keep their scalar meaning.
      for (const query of guards) for (const truth of [false, true])
        assert.equal(assumeScalar(query, truth, copy(current)), assumeScalar(query, truth, copy(prior)), query.identity);
      current = run(commonScalarConstraints, current, inputs[0]);
      prior = run(beforeB1, prior, inputs[0]);
    }
  }
});

test("common constraints preserve equivalent transitive guards from compiler-valid source paths", () => {
  const source = `import CompactStandardLibrary;
export circuit entry(flag: Boolean, a: Field, b: Field, c: Field): [] {
  if (disclose(flag)) { assert(a == b, "direct"); }
  else { assert(a == c, "first"); assert(c == b, "second"); }
  assert(a != b, "contradiction");
}`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file), flow = new Dataflow(program);
    const states: ScalarConstraints[] = [];
    const hook = flow as unknown as { evaluateInstruction(instruction: Instruction, predecessor: number, state: ScalarConstraints, stack: string[], location: Span): unknown };
    const ordinary = hook.evaluateInstruction;
    hook.evaluateInstruction = function (instruction, predecessor, state, stack, at) {
      if (instruction.kind === "evaluate" && instruction.expression.kind === "assert" && instruction.expression.span.file === file
        && instruction.expression.span.start === source.lastIndexOf("assert(a != b")) states.push(copy(state));
      return ordinary.call(this, instruction, predecessor, state, stack, at);
    };
    const facts = flow.analyze();
    assert.deepEqual(facts.diagnostics, []); assert.equal(facts.paths.length, 0); assert.equal(states.length, 2);
    const sourceValue = (name: string): AbstractValue => {
      const operands = states.flatMap(state => [...state.scalarEqualities!.values()].flatMap(relation => [relation.left, relation.right]));
      const origin = operands.flatMap(value => value.flows).find(flow => flow.source.kind === "entry-parameter" && flow.source.name === name)!.source;
      return { ...value(origin.id), type: "Field" };
    };
    const condition = binaryValue([sourceValue("a"), sourceValue("b")], "!=", location, "Field")!;
    const before = states.map(copy), common = joined(states[0], states[1]);
    assert.equal(refineScalar(condition, common).constant, "false");
    assert.deepEqual(states, before, "common views must not refine either retained alternative");
  });
});

test("common scalar facts do not import a saved path-local constant into the other alternative", () => {
  const left = fresh(), right = fresh(), a = value("a"), b = value("b");
  assume(left, a, "==", number(3));
  assume(left, { ...a, constantKind: "integer", constant: "3" }, "==", b);
  assume(right, a, "==", b);
  const common = joined(left, right);
  assert.equal(common.known.size, 0);
  assert.equal(refineScalar(predicate(a, "==", b), common).constant, "true");
  assert.equal(refineScalar(predicate(b, "==", number(3)), common).constant, undefined);
});

test("bounds and exclusions follow common equivalence classes without retaining a stronger arm", () => {
  const left = fresh(), right = fresh(), a = value("a"), b = value("b"), c = value("c");
  assume(left, a, "==", b); assume(left, a, "<=", number(5)); assume(left, b, "!=", number(4));
  assume(right, a, "==", c); assume(right, c, "==", b); assume(right, b, "<=", number(9)); assume(right, a, "!=", number(4));
  const common = joined(left, right);
  assert.equal(refineScalar(predicate(b, ">", number(9)), common).constant, "false");
  assert.equal(refineScalar(predicate(a, "<=", number(5)), common).constant, undefined);
  assert.equal(refineScalar(predicate(a, "==", number(4)), common).constant, "false");
  assert.equal(refineScalar(predicate(b, "==", number(4)), common).constant, "false");
  assert.equal(refineScalar(predicate(a, "==", c), common).constant, undefined);
});

test("dense common classes retain a spanning relation set within the shared allowance", () => {
  const left = fresh(), right = fresh(), operands = Array.from({ length: 128 }, (_, i) => value(`v${i}`));
  for (let i = 1; i < operands.length; i++) { assume(left, operands[i - 1], "==", operands[i]); assume(right, operands[0], "==", operands[i]); }
  let work = 0, values = 0;
  const common = commonScalarConstraints(left, right, (w, v) => { work += w; values += v; return work <= 5000 && values <= 5000; });
  assert.equal(common.status, "available");
  if (common.status !== "available") return;
  assert.equal(common.constraints.scalarEqualities!.size, 127);
  assert.equal(refineScalar(predicate(operands[0], "!=", operands[127]), common.constraints).constant, "false");
});

test("shared immutable ordered prefixes retain their facts without repeating implication queries", () => {
  const prefix = fresh(), a = value("a");
  for (let index = 1; index <= 32; index++) assume(prefix, a, "<", value(`b${index}`));
  const left = copy(prefix), right = copy(prefix);
  assume(left, a, ">", number(4)); assume(right, a, ">", number(7));
  let work = 0;
  const common = commonScalarConstraints(left, right, steps => (work += steps) <= 1500);
  assert.equal(common.status, "available", JSON.stringify(common));
  if (common.status !== "available") return;
  for (let index = 1; index <= 32; index++) assert.equal(refineScalar(predicate(a, ">=", value(`b${index}`)), common.constraints).constant, "false");
  assert.equal(refineScalar(predicate(a, ">", number(4)), common.constraints).constant, "true");
  assert.equal(refineScalar(predicate(a, ">", number(7)), common.constraints).constant, undefined);
  assert.equal(commonScalarConstraints(left, right, () => false).status, "incomplete");
});

test("exhausted input domains and common-view work/value exhaustion remain incomplete", () => {
  const left = fresh(), right = fresh();
  assume(left, value("a"), "==", value("b")); assume(right, value("a"), "==", value("b"));
  for (const property of ["scalarEqualitiesExhausted", "orderingsExhausted", "aggregateExclusionsExhausted"] as const)
    assert.equal(commonScalarConstraints({ ...left, [property]: true }, right, () => true).status, "incomplete");
  assert.equal(commonScalarConstraints(left, right, () => false).status, "incomplete");
  assert.equal(commonScalarConstraints(left, right, (_w, v) => !v).status, "incomplete");
});

test("indirect hash refinement refusal cannot publish available common constraints", () => {
  // 41 is refused inside the indirect recipe refinement (HashRecipes.contains);
  // without input exclusions the join skips its exclusion pairing pass.
  for (const limit of [41, 46, 1000]) {
    let work = 0, active = false, refused = false;
    const charge = (steps: number): boolean => {
      if (active) work += steps;
      if (work > limit) refused = true;
      return !refused;
    };
    const recipes = new HashRecipes(charge, () => assert.fail("unexpected depth refusal"));
    const chosen = recipes.choose("flag", "a", "b")!;
    const left = { ...fresh(), hashRecipes: recipes }, right = { ...fresh(), hashRecipes: recipes };
    assert.equal(assumeScalar({ ...value("flag"), type: "Boolean" }, true, left), true);
    assert.equal(assumeScalar({ ...value("flag"), type: "Boolean" }, false, right), true);
    for (const state of [left, right]) assume(state, value(chosen), "!=", value("c"));
    active = true;
    const result = commonScalarConstraints(left, right, charge);
    assert.equal(result.status, refused ? "incomplete" : "available", `work limit ${limit}`);
    if (limit === 41) assert.equal(refused, true);
    if (limit === 1000) assert.equal(refused, false);
  }
});

test("hash normalization depth refusal survives a successful outer budget check", () => {
  let depths = 0;
  const recipes = new HashRecipes(() => true, () => { depths++; });
  let chosen = "seed";
  for (let i = 0; i < 258; i++) chosen = recipes.choose(`flag${i}`, chosen, `other${i}`)!;
  const left = { ...fresh(), hashRecipes: recipes }, right = { ...fresh(), hashRecipes: recipes };
  left.truths.set(chosen, true); right.truths.set(chosen, true);
  assert.equal(commonScalarConstraints(left, right, () => true).status, "incomplete");
  assert.ok(depths > 0);
  assert.equal(recipes.exhausted, true);
  assert.equal(commonScalarConstraints(fresh(), left, () => true).status, "incomplete");
});

test("shared-constant classes keep constants without materialized equality chains", () => {
  const prefix = fresh(), pinned = Array.from({ length: 8 }, (_, i) => value(`p${i}`)), split = Array.from({ length: 4 }, (_, i) => value(`s${i}`));
  for (const operand of pinned) assume(prefix, operand, "==", number(5));
  const left = copy(prefix), right = copy(prefix);
  for (const operand of split) { assume(left, operand, "==", number(1)); assume(right, operand, "==", number(2)); }
  const common = joined(left, right);
  // Every pinned member keeps its constant; equalities among them are implied, not edges.
  for (const operand of pinned) assert.equal(refineScalar(predicate(operand, "==", number(5)), common).constant, "true");
  assert.equal(refineScalar(predicate(pinned[0], "==", pinned[7]), common).constant, "true");
  assert.equal(refineScalar(predicate(pinned[0], "!=", pinned[3]), common).constant, "false");
  const relationOperands = [...common.scalarEqualities!.values()].flatMap(relation => [relation.left.identity, relation.right.identity]);
  assert.ok(pinned.every(operand => !relationOperands.includes(operand.identity)));
  // Classes whose constants differ between the inputs still retain their equality edges.
  assert.equal(common.scalarEqualities!.size, split.length - 1);
  for (const operand of split) assert.equal(refineScalar(predicate(operand, "==", number(1)), common).constant, undefined);
  assert.equal(refineScalar(predicate(split[0], "==", split[3]), common).constant, "true");
  // A later join of the result with a sibling keeps the same facts.
  const again = joined(common, copy(prefix));
  for (const operand of pinned) assert.equal(refineScalar(predicate(operand, "==", number(5)), again).constant, "true");
  assert.equal(refineScalar(predicate(split[0], "==", split[3]), again).constant, undefined);
});

test("orderings retained by both inputs skip implication queries; opposite truths are dropped", () => {
  const prefix = fresh(), a = value("a"), bounds = Array.from({ length: 32 }, (_, i) => value(`b${i}`));
  for (const bound of bounds) assume(prefix, a, "<", bound);
  // An earlier join re-materializes every retained ordering: same predicates and
  // truths as the untouched sibling, but different observation objects.
  const earlier = joined(copy(prefix), copy(prefix));
  for (const bound of bounds) assert.notEqual(earlier.orderings!.get(predicate(a, "<", bound).identity!), prefix.orderings!.get(predicate(a, "<", bound).identity!));
  const left = copy(earlier), right = copy(prefix), split = predicate(a, "<", value("c"));
  assert.equal(assumeScalar(split, true, left), true);
  assert.equal(assumeScalar(split, false, right), true);
  let work = 0;
  const common = commonScalarConstraints(left, right, steps => (work += steps) <= 1500);
  assert.equal(common.status, "available", JSON.stringify(common));
  if (common.status !== "available") return;
  for (const bound of bounds) assert.equal(refineScalar(predicate(a, ">=", bound), common.constraints).constant, "false");
  assert.equal(common.constraints.orderings!.has(split.identity!), false);
  assert.equal(refineScalar(split, common.constraints).constant, undefined);
  // A one-sided ordering still needs (and pays for) the implication query.
  const implied = copy(prefix), alone = copy(prefix);
  assume(implied, a, "<", number(3)); assume(alone, a, "<", number(2));
  const query = joined(implied, alone);
  assert.equal(refineScalar(predicate(a, "<", number(3)), query).constant, "true");
  assert.equal(refineScalar(predicate(a, "<", number(2)), query).constant, undefined);
});

test("exclusions are intersected only when both inputs retain grouped exclusions", () => {
  const left = fresh(), right = fresh(), a = value("a"), b = value("b");
  assume(left, a, "!=", number(4)); assume(left, b, "!=", number(6));
  assume(right, a, "!=", number(4));
  const common = joined(left, right);
  assert.equal(refineScalar(predicate(a, "==", number(4)), common).constant, "false");
  assert.equal(refineScalar(predicate(b, "==", number(6)), common).constant, undefined);
  const none = joined(left, fresh());
  assert.equal(none.excluded.size, 0);
  assert.equal(refineScalar(predicate(a, "==", number(4)), none).constant, undefined);
});
