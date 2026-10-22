import type { AbstractValue, AnalysisFacts } from "../../src/dataflow/index.js";
import type { Span } from "../../src/model.js";
import { expectedProvenance, renderProvenanceCase, type ProvenanceCase, type ProvenanceTag } from "./provenance-model.js";

export interface ProvenanceFailure {
  property: string;
  field: string;
  message: string;
}

/**
 * Compare analyzer observations against the independent owned linear grammar.
 * This is a self-authored structural oracle, not independent security review or
 * a concrete oracle for information leakage, authorization or arbitrary Compact.
 */
export function checkProvenance(input: ProvenanceCase, facts: AnalysisFacts): ProvenanceFailure | undefined {
  const expected = expectedProvenance(input);
  const failure = (property: string, field: string, message: string): ProvenanceFailure => ({ property, field, message });
  const same = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);
  const sameSpan = (a: Span, b: Span): boolean => a.file === b.file && a.start === b.start && a.end === b.end;
  const sourceText = renderProvenanceCase(input);
  if (facts.program.rootSource.text !== sourceText) return failure("fixture-source", "source", "Facts do not describe the exact owned fixture");
  if (facts.diagnostics.length || facts.program.entries.length !== 1 || facts.completedEntries.length !== 1 || facts.completedEntries[0] !== facts.program.entries[0]) return failure("incomplete", "entries", "The single fixture entry must finish without diagnostics");
  if (facts.failedAssertions.length) return failure("unexpected-failure", "assertions", "The initialized linear fixture cannot fail its designated guard");
  if (facts.paths.length !== 1 || facts.paths[0].entry !== facts.program.entries[0]) return failure("path-count", "paths", "The linear fixture has exactly one successful path");
  const path = facts.paths[0];
  const assertion = 'assert(authorized, "owned guard")';
  const assertionStart = sourceText.indexOf(assertion);
  const guards = input.operations.filter(operation => operation.kind === "guard").length;
  if (path.bindings.length || path.path.length !== guards || path.path.some(step => step.kind !== "constraint" || step.label !== "assertion must succeed"
    || step.location.file !== facts.program.rootSource.ast.span.file || step.location.start !== assertionStart || step.location.end !== assertionStart + assertion.length)) {
    return failure("unexpected-constraint", "path", "Expected only the designated successful guard assertions, without branch decisions or hash bindings");
  }
  const functions = [...facts.program.functions.values()];
  const guard = functions.find(fn => fn.symbol.name === "guard")?.symbol.id;
  const entry = facts.program.functions.get(path.entry);
  if (!guard || !entry || entry.declaration.parameters.length !== 2) return failure("fixture-symbols", "functions", "Expected generated entry and guard identities");
  const parameters = new Map(entry.declaration.parameters.map(parameter => [parameter.name, parameter]));
  const sourceIds = new Map<string, string>();
  const names = (ids: string[]): string[] => ids.map(id => facts.program.symbols.get(id)?.name ?? `<unresolved:${id}>`);
  const tags = (value: AbstractValue, wanted: ProvenanceTag[], field: string, scalar = true): ProvenanceFailure | undefined => {
    if (scalar && (value.items !== undefined || value.fields !== undefined)) return failure("value-shape", field, "Expected a scalar provenance checkpoint");
    const actual: ProvenanceTag[] = [];
    for (const flow of value.flows) {
      const source = flow.source;
      const parameter = parameters.get(source.name);
      if (!parameter || source.kind !== "entry-parameter" || source.symbol !== parameter.symbol || !sameSpan(source.location, parameter.span)) return failure("source-origin", field, "Flow does not originate at its declared fixture parameter");
      const prior = sourceIds.get(source.name);
      if (!source.id || prior !== undefined && prior !== source.id || [...sourceIds].some(([name, id]) => name !== source.name && id === source.id)) return failure("source-identity", field, "Source identities must stay stable and distinct");
      sourceIds.set(source.name, source.id);
      if (!flow.trace.some(step => step.kind === "source" && step.label === source.name && sameSpan(step.location, parameter.span))) return failure("source-trace", field, "Flow is missing its parameter origin trace");
      actual.push({ source: source.name as ProvenanceTag["source"], form: flow.form as ProvenanceTag["form"] });
    }
    const sorted = (entries: ProvenanceTag[]): ProvenanceTag[] => [...entries].sort((a, b) => a.source.localeCompare(b.source) || a.form.localeCompare(b.form));
    if (!same(sorted(actual), sorted(wanted))) return failure("provenance", field, `Expected ${JSON.stringify(sorted(wanted))}, received ${JSON.stringify(sorted(actual))}`);
    return undefined;
  };
  if (path.writes.length !== expected.writes.length) return failure("write-count", "writes", "A write was dropped or invented");
  if (path.sinks.length !== expected.writes.length + 1) return failure("sink-count", "sinks", "Every scalar assignment has one sink followed by the exported return");
  for (let index = 0; index < expected.writes.length; index++) {
    const write = path.writes[index];
    const sink = path.sinks[index];
    const wanted = expected.writes[index];
    const field = `writes/${index}`;
    if (facts.program.symbols.get(write.ledger)?.name !== wanted.root || write.region.length) return failure("write-order", field, "Wrong root or non-root write in the ordered history");
    if (!same(names(write.callPath), wanted.callPath)) return failure("call-path", field, "Write call history does not match the fixed route");
    if (write.guards.includes(guard) !== wanted.guarded) return failure("guard", field, "Designated guard completion was lost or retained past relevant invalidation");
    for (const [name, value, wantedTags] of [["before", write.before, wanted.before], ["after", write.after, wanted.after]] as const) {
      const problem = tags(value, wantedTags, `${field}/${name}`);
      if (problem) return problem;
    }
    if (sink.kind !== "ledger-write" || sink.name !== wanted.root || !same(names(sink.callPath), wanted.callPath) || !sameSpan(sink.location, write.location)) return failure("sink-order", `sinks/${index}`, "Assignment sink is missing, reordered or attached to another call");
    const problem = tags(sink.value, wanted.after, `sinks/${index}`);
    if (problem) return problem;
  }
  const returned = path.sinks.at(-1)!;
  if (returned.kind !== "exported-return" || returned.name !== "entry" || !same(names(returned.callPath), ["entry"])) return failure("return-sink", "return", "Expected the final exported entry result");
  if (!returned.value.items || returned.value.items.length !== expected.checkpoints.length || returned.value.fields) return failure("return-shape", "checkpoints", "Incorrect checkpoint tuple layout");
  for (let index = 0; index < expected.checkpoints.length; index++) {
    const checkpoint = returned.value.items[index];
    if (!checkpoint.items || checkpoint.items.length !== 3 || checkpoint.fields) return failure("return-shape", `checkpoints/${index}`, "Expected current/saved/unrelated scalar triple");
    for (let field = 0; field < 3; field++) {
      const problem = tags(checkpoint.items[field], expected.checkpoints[index][field], `checkpoints/${index}/${["current", "saved", "unrelated"][field]}`);
      if (problem) return problem;
    }
    const union = [...new Map(expected.checkpoints[index].flat().map(tag => [`${tag.source}:${tag.form}`, tag])).values()];
    const problem = tags(checkpoint, union, `checkpoints/${index}`, false);
    if (problem) return problem;
  }
  const union = [...new Map(expected.checkpoints.flat(2).map(tag => [`${tag.source}:${tag.form}`, tag])).values()];
  return tags(returned.value, union, "return", false);
}
