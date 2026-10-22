import type { AbstractValue, AnalysisFacts } from "../../src/dataflow/index.js";
import type { Span } from "../../src/model.js";
import type { ProvenanceFailure } from "./provenance-check.js";

/** A fixed two-arm fixture family, not an arbitrary source or target interface. */
export interface BranchProvenanceCase {
  schemaVersion: "nightshade-branch-provenance-case-1";
  guardArm: boolean;
  invalidate: "before-copy" | "after-copy" | "none";
  swapped: boolean;
}
export function validateBranchProvenanceCase(value: unknown): BranchProvenanceCase {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error("Invalid branch provenance model");
  const keys = ["schemaVersion", "guardArm", "invalidate", "swapped"];
  if (Reflect.ownKeys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) throw new Error("Invalid branch provenance model fields");
  for (const key of keys) if (!("value" in Object.getOwnPropertyDescriptor(value, key)!)) throw new Error("Invalid branch provenance accessor");
  const item = value as BranchProvenanceCase;
  if (item.schemaVersion !== "nightshade-branch-provenance-case-1" || typeof item.guardArm !== "boolean" || typeof item.swapped !== "boolean" || !["before-copy", "after-copy", "none"].includes(item.invalidate)) throw new Error("Invalid branch provenance options");
  return { schemaVersion: item.schemaVersion, guardArm: item.guardArm, invalidate: item.invalidate, swapped: item.swapped };
}

export function renderBranchProvenanceCase(value: BranchProvenanceCase): string {
  const input = validateBranchProvenanceCase(value);
  const first = input.swapped ? "second" : "first", second = input.swapped ? "first" : "second";
  return `pragma language_version 0.26.0;
export ledger stored: Field;
export ledger authorized: Boolean;
export ledger unrelated: Field;
circuit guard(): [] { assert(authorized, "owned branch guard"); }
circuit put(value: Field): [] { stored = disclose(value); }
circuit copy(value: Field): [] { put(value); }
circuit leafRead(): Field { return stored; }
circuit nestedRead(): Field { return leafRead(); }
export circuit entry(first: Field, second: Field, flag: Boolean): [Field, Field, Field] {
  stored = 0 as Field;
  authorized = true;
  unrelated = 0 as Field;
  if (disclose(flag)) {
    ${input.guardArm ? "guard();" : ""}
    put(${first});
  } else {
    ${input.guardArm ? "" : "guard();"}
    put(${second});
  }
  const saved = stored;
  const current = nestedRead();
  nestedRead();
  unrelated = 0 as Field;
  ${input.invalidate === "before-copy" ? "authorized = true;" : ""}
  copy(saved);
  ${input.invalidate === "after-copy" ? "authorized = true;" : ""}
  put(0 as Field);
  return [current, saved, stored];
}
`;
}

type Tag = { source: "first" | "second" | "flag"; form: "raw" | "derived" };
type SourceSite = Omit<Span, "file">;
interface ExpectedWrite { root: string; before: Tag[]; after: Tag[]; guarded: boolean; route: string[]; site: SourceSite }

/** Fixed ASCII source positions, independent of parser/CFG spans and observations. */
function sourceSite(source: string, text: string, occurrence = 0): SourceSite {
  let start = -1;
  for (let index = 0; index <= occurrence; index++) {
    start = source.indexOf(text, start + 1);
    if (start < 0) throw new Error(`Missing fixed provenance source site: ${text}`);
  }
  const end = start + text.length;
  return { start, end, line: source.slice(0, start).split("\n").length, column: start - source.lastIndexOf("\n", start - 1),
    endLine: source.slice(0, end).split("\n").length, endColumn: end - source.lastIndexOf("\n", end - 1) };
}

/** Expectations depend on the input flag, never on observed source tags or guards. */
export function branchProvenanceExpectation(value: BranchProvenanceCase, flag: boolean) {
  const input = validateBranchProvenanceCase(value);
  const source = renderBranchProvenanceCase(input);
  const putSite = sourceSite(source, "stored = disclose(value)");
  const selected: Tag["source"] = flag !== input.swapped ? "first" : "second";
  const tagged: Tag[] = [{ source: selected, form: "raw" }, { source: "flag", form: "derived" }];
  // ADR 0015 deliberately models structural may-abort effects, even when a
  // particular initialized assertion is known true. The conditional writes and
  // guard call therefore retain the decision's control dependency through the
  // continuation. This is a dependency contract, not observable leakage.
  const control: Tag[] = [{ source: "flag", form: "derived" }];
  let guarded = flag === input.guardArm;
  const writes: ExpectedWrite[] = ["stored", "authorized", "unrelated"].map(root => ({ root, before: [], after: [], guarded: false, route: ["entry"], site: sourceSite(source, `${root} = ${root === "authorized" ? "true" : "0 as Field"}`) }));
  writes.push({ root: "stored", before: [], after: tagged, guarded, route: ["entry", "put"], site: putSite });
  writes.push({ root: "unrelated", before: [], after: control, guarded, route: ["entry"], site: sourceSite(source, "unrelated = 0 as Field", 1) });
  const invalidate = () => {
    writes.push({ root: "authorized", before: [], after: control, guarded, route: ["entry"], site: sourceSite(source, "authorized = true", 1) });
    guarded = false;
  };
  if (input.invalidate === "before-copy") invalidate();
  writes.push({ root: "stored", before: tagged, after: tagged, guarded, route: ["entry", "copy", "put"], site: putSite });
  if (input.invalidate === "after-copy") invalidate();
  writes.push({ root: "stored", before: tagged, after: control, guarded, route: ["entry", "put"], site: putSite });
  return { writes, returned: [tagged, tagged, control] as Tag[][], returnSite: sourceSite(source, "return [current, saved, stored];"), assertions: flag === input.guardArm ? 1 : 0 };
}

/** The fixed branch site associates paths with input flags before checking effects. */
export function checkBranchProvenance(value: BranchProvenanceCase, facts: AnalysisFacts): ProvenanceFailure | undefined {
  const input = validateBranchProvenanceCase(value);
  const source = renderBranchProvenanceCase(input);
  const fail = (property: string, field: string, message: string): ProvenanceFailure => ({ property, field, message });
  if (facts.program.rootSource.text !== source) return fail("fixture-source", "source", "Mismatched owned branch source");
  if (facts.diagnostics.length || facts.completedEntries.length !== 1 || facts.program.entries.length !== 1 || facts.completedEntries[0] !== facts.program.entries[0]) return fail("incomplete", "entries", "Expected one completed entry with no diagnosed gap");
  if (facts.failedAssertions.length || facts.paths.length !== 2) return fail("path-count", "paths", "Both Boolean inputs succeed, each with its own effect history");
  const guard = [...facts.program.functions.values()].find(fn => fn.symbol.name === "guard")!.symbol.id;
  const entry = facts.program.functions.get(facts.program.entries[0])!;
  const parameters = new Map(entry.declaration.parameters.map(parameter => [parameter.name, parameter]));
  const rootFile = facts.program.rootSource.ast.span.file;
  const branchStart = source.indexOf("disclose(flag)");
  const branchEnd = branchStart + "disclose(flag)".length;
  const branchStatementStart = source.indexOf("if (disclose(flag))");
  const branchStatementEnd = source.indexOf("\n  const saved = stored;");
  const assertionStart = source.indexOf('assert(authorized, "owned branch guard")');
  const assertionEnd = assertionStart + 'assert(authorized, "owned branch guard")'.length;
  const names = (ids: string[]) => ids.map(id => facts.program.symbols.get(id)?.name);
  const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
  const atSite = (actual: Span, wanted: SourceSite): boolean => actual.file === rootFile
    && (Object.keys(wanted) as (keyof SourceSite)[]).every(key => actual[key] === wanted[key]);
  const normalized = (tags: Tag[]) => [...tags].sort((a, b) => a.source.localeCompare(b.source) || a.form.localeCompare(b.form));
  const sourceIds = new Map<string, string>();
  const checkValue = (actual: AbstractValue, wanted: Tag[], field: string, scalar = true): ProvenanceFailure | undefined => {
    if (scalar && (actual.items || actual.fields)) return fail("value-shape", field, "Expected a scalar value");
    const tags: Tag[] = [];
    for (const flow of actual.flows) {
      const parameter = parameters.get(flow.source.name);
      if (!parameter || flow.source.kind !== "entry-parameter" || flow.source.symbol !== parameter.symbol || flow.source.location.file !== rootFile || flow.source.location.start !== parameter.span.start || flow.source.location.end !== parameter.span.end) return fail("source-origin", field, "Unexpected source identity");
      if (!flow.trace.some(step => step.kind === "source" && step.label === parameter.name && step.location.file === rootFile && step.location.start === parameter.span.start && step.location.end === parameter.span.end)) return fail("source-trace", field, "Missing source origin");
      if (!flow.source.id || sourceIds.has(parameter.name) && sourceIds.get(parameter.name) !== flow.source.id || [...sourceIds].some(([name, id]) => name !== parameter.name && id === flow.source.id)) return fail("source-identity", field, "Source identities must remain distinct and stable across paths");
      sourceIds.set(parameter.name, flow.source.id);
      tags.push({ source: parameter.name as Tag["source"], form: flow.form as Tag["form"] });
    }
    return same(normalized(tags), normalized(wanted)) ? undefined : fail("provenance", field, `Expected ${JSON.stringify(normalized(wanted))}, received ${JSON.stringify(normalized(tags))}`);
  };
  const flags = new Set<boolean>();
  for (const path of facts.paths) {
    if (path.entry !== entry.symbol.id || path.bindings.length) return fail("path-entry", "paths", "Unexpected entry or hash binding");
    const decisions = path.path.filter(step => step.kind === "branch");
    if (decisions.length !== 1) return fail("branch-count", "flag", "Expected exactly one input branch");
    const decision = decisions[0];
    const label = /^condition may be (true|false)$/.exec(decision.label);
    // Each engine uses either the source condition or its containing statement.
    // Both allowed sites are fixed by the renderer, never inferred from flows.
    const location = decision.location;
    const validSite = location.file === rootFile && (location.start === branchStart && location.end === branchEnd || location.start === branchStatementStart && location.end === branchStatementEnd);
    if (!label || !validSite) return fail("branch-origin", "flag", "Wrong decision label or source site");
    const flag = label[1] === "true";
    if (flags.has(flag)) return fail("input-coverage", "flag", "Duplicated input path");
    flags.add(flag);
    const expected = branchProvenanceExpectation(input, flag);
    const assertions = path.path.filter(step => step.kind !== "branch");
    if (assertions.length !== expected.assertions || assertions.some(step => step.kind !== "constraint" || step.label !== "assertion must succeed" || step.location.file !== rootFile || step.location.start !== assertionStart || step.location.end !== assertionEnd)) return fail("assertion-history", "path", "Guard assertions crossed branch histories");
    if (path.writes.length !== expected.writes.length || path.sinks.length !== expected.writes.length + 1) return fail("effect-count", "effects", "Missing or invented ordered write/sink");
    for (const [index, wanted] of expected.writes.entries()) {
      const write = path.writes[index], sink = path.sinks[index];
      const field = `flag:${flag}/writes/${index}`;
      if (facts.program.symbols.get(write.ledger)?.name !== wanted.root || write.region.length || !same(names(write.callPath), wanted.route)) return fail("effect-history", field, "Wrong root/order/call history");
      // Repeated and nested calls share the assignment's definition site; their
      // route records the call history. Matching two corrupted spans is not proof.
      if (!atSite(write.location, wanted.site) || !atSite(sink.location, wanted.site)) return fail("effect-site", field, "Write or sink does not identify its fixed assignment site");
      if (write.guards.includes(guard) !== wanted.guarded) return fail("guard", field, "Missing, stale or opposite-branch guard");
      if (sink.kind !== "ledger-write" || sink.name !== wanted.root || !same(names(sink.callPath), wanted.route) || !same(sink.location, write.location)) return fail("sink-history", field, "Wrong public sink history");
      for (const [actual, tags, suffix] of [[write.before, wanted.before, "before"], [write.after, wanted.after, "after"], [sink.value, wanted.after, "sink"]] as const) {
        const problem = checkValue(actual, tags, `${field}/${suffix}`);
        if (problem) return problem;
      }
    }
    const returned = path.sinks.at(-1)!;
    if (returned.kind !== "exported-return" || returned.name !== "entry" || !same(names(returned.callPath), ["entry"]) || returned.value.fields || returned.value.items?.length !== 3) return fail("return-shape", "return", "Wrong export boundary or return layout");
    if (!atSite(returned.location, expected.returnSite)) return fail("return-site", "return", "Exported sink does not identify its fixed return statement");
    for (let index = 0; index < 3; index++) {
      const problem = checkValue(returned.value.items[index], expected.returned[index], `flag:${flag}/return/${index}`);
      if (problem) return problem;
    }
    const union = [...new Map(expected.returned.flat().map(tag => [`${tag.source}:${tag.form}`, tag])).values()];
    const problem = checkValue(returned.value, union, `flag:${flag}/return`, false);
    if (problem) return problem;
  }
  return flags.size === 2 ? undefined : fail("input-coverage", "flag", "Missing Boolean input history");
}
