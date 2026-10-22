import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program } from "../src/index.js";
import { merklePathWitnessTargets } from "../src/semantic/merkle-targets.js";
import { merkleLeafBindingReview as rule } from "../src/detectors/merkle-leaf-binding.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

function check(file: string, expected: Array<[string, number]>): void {
  if (process.env.COMPACTC_TEST) {
    const validation = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(validation.valid, true, validation.error);
  }
  const program = new Program(file);
  let baseline: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const actual: Array<[string, number]> = [];
    for (const entry of program.entries) {
      const analyze = (summarizePureRoots: boolean) => {
        const flow = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
          "equivalent-states", false, false, "all", true, false, false, false,
          false, false, true, false, false, true, merklePathWitnessTargets(program).targets);
        const facts = flow.analyzeMerkleLeafBindingEntry(entry, summarizePureRoots);
        assert.deepEqual(facts.diagnostics, []);
        assert.deepEqual(facts.completedEntries, [entry]);
        return rule.run(facts);
      };
      const summarized = analyze(true);
      const ordinary = analyze(false);
      assert.deepEqual(summarized, ordinary, `${file}: ${entry}, ${engine}, cached=${cached}`);
      actual.push(...summarized.map(finding => [finding.metadata.entry, finding.metadata.argumentIndex] as [string, number]));
    }
    assert.deepEqual(actual.sort(([a, ai], [b, bi]) => a.localeCompare(b) || ai - bi), expected.slice().sort(([a, ai], [b, bi]) => a.localeCompare(b) || ai - bi));
    baseline ??= actual; assert.deepEqual(actual, baseline);
  }
}

for (const [name, expected] of [
  ["positive", [["accept", 1], ["accept", 2]]],
  // input2 remains an independent unbound lookup input after input1 is bound.
  ["corrected", [["accept", 2]]],
  // Binding the wrong byte input does not clear the intended input.
  ["lookalike", [["accept", 1]]],
  ["single-positive", [["accept", 0]]],
  ["single-corrected", []],
  ["single-lookalike", []],
] as const) test(`byte leaf binding: ${name}`, () => {
  check(resolve(`tests/corpus/drafts/merkle-byte-binding/${name}.compact`), expected as unknown as Array<[string, number]>);
});

test("direct-byte controls preserve exact checked-path and conversion identity", () => {
  check(resolve("tests/corpus/drafts/merkle-byte-binding/controls.compact"), [
    ["separate", 1], ["separate", 2],
    ["conversionRoundtrip", 1], ["conversionRoundtrip", 2],
  ]);
});
