import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { AnalysisFacts, Dataflow, Program, detectors, parseSource, scanFile } from "../src/index.js";
import { decodeString } from "../src/parser/strings.js";
import { literalConstant, MAX_LITERAL_BYTES } from "../src/dataflow/constants.js";
import { human, sarif } from "../src/reporting/index.js";
import { semanticPaths, withFiles } from "./helpers.js";

let compilerChecked = false;
function compile(path: string, valid: boolean): string | undefined {
  const executable = process.env.COMPACTC_TEST;
  if (!executable) return undefined;
  const run = (args: string[]) => spawnSync(executable, args, { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
  if (!compilerChecked) {
    assert.equal(run(["--version"]).stdout.trim(), "0.34.0");
    assert.equal(run(["--language-version"]).stdout.trim(), "0.26.0");
    compilerChecked = true;
  }
  const output = resolve(dirname(path), "compiled");
  const result = run(["--skip-zk", path, output]);
  assert.equal(result.status === 0, valid, result.stderr);
  return valid ? readFileSync(resolve(output, "contract/index.js"), "utf8") : undefined;
}

function compare(source: string | Record<string, string>, check: (facts: AnalysisFacts, generated?: string) => void): void {
  const files = typeof source === "string" ? { "main.compact": source } : source;
  withFiles({ ...files, "main.compact": `pragma language_version >= 0.26.0;\n${files["main.compact"]}` }, directory => {
    const path = resolve(directory, "main.compact");
    const generated = compile(path, true);
    const program = new Program(path);
    const facts = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    const reference = new Dataflow(program, 20000, 256, 50000, "expressions").analyze();
    for (const result of [facts, expanded, reference]) {
      assert.deepEqual(result.diagnostics, []);
      assert.deepEqual(result.completedEntries, program.entries);
    }
    assert.deepEqual(facts.paths, expanded.paths);
    assert.deepEqual(facts.failedAssertions, expanded.failedAssertions);
    assert.deepEqual(facts.failedAssertions, reference.failedAssertions);
    assert.deepEqual(semanticPaths(facts), semanticPaths(reference));
    const observations = (result: AnalysisFacts) => detectors.flatMap(detector => detector.run(result)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(observations(facts), observations(reference));
    check(facts, generated);
  });
}

function returned(facts: AnalysisFacts) {
  return facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
}

const literals: [string, string, string][] = [
  ["single quoted", "'hello'", "hello"],
  ["empty", "''", ""],
  ["escaped quotes", String.raw`'\'\"'`, "'\""],
  ["backslash", String.raw`'\\'`, "\\"],
  ["control escapes", String.raw`'\n\r\0\b\f\t\v'`, "\n\r\0\b\f\t\v"],
  ["NUL followed by a digit is not octal", String.raw`'\01'`, "\0" + "1"],
  ["hexadecimal character is UTF-8 rather than one byte", String.raw`'\xE9'`, "é"],
  ["mixed-case Unicode digits", String.raw`'\u03a9\u00E9'`, "Ωé"],
  ["literal non-BMP Unicode", "'Ω🚀'", "Ω🚀"],
  ["unescaped newline", "'first\nsecond'", "first\nsecond"],
  ["escaped newline", "'first\\\nsecond'", "firstsecond"],
  ["escape-looking text after an escaped backslash", String.raw`'\\n'`, "\\n"],
  ["comment-like and generic-like text", "'//<a>,/*b*/'", "//<a>,/*b*/"],
  ["escaped line separators stay data", String.raw`'\u0085\u2028\u2029'`, "\u0085\u2028\u2029"],
  ["paragraph separator is not normalized", "'a\u2029b'", "a\u2029b"],
];

for (const [name, token, expected] of literals) test(`Compact literal: ${name}`, () => {
  const bytes = Buffer.from(expected, "utf8");
  compare(`export circuit entry(): Bytes<${bytes.length}> { return ${token}; }`, (facts, generated) => {
    assert.equal(returned(facts)[0].constantKind, "bytes");
    assert.equal(returned(facts)[0].constant, bytes.toString("hex"));
    if (generated !== undefined) {
      const array = /new Uint8Array\(\[([\d,\s]*)\]\)/.exec(generated)?.[1];
      assert.notEqual(array, undefined, generated.slice(-1500));
      assert.deepEqual(JSON.parse(`[${array}]`), [...bytes]);
    }
  });
});

for (const [name, ending] of [["CRLF", "\r\n"], ["CR", "\r"], ["NEL", "\u0085"], ["CRNEL", "\r\u0085"], ["LS", "\u2028"]]) {
  for (const escaped of [false, true]) test(`input transcoding ${name}, continuation=${escaped}`, () => {
    const value = escaped ? "ab" : "a\nb";
    compare(`export circuit entry(): Bytes<${value.length}> { return 'a${escaped ? "\\" : ""}${ending}b'; }`, (facts, generated) => {
      assert.equal(returned(facts)[0].constant, Buffer.from(value).toString("hex"));
      if (generated !== undefined) assert.deepEqual(JSON.parse(`[${/new Uint8Array\(\[([\d,\s]*)\]\)/.exec(generated)![1]}]`), [...Buffer.from(value)]);
    });
  });
}

for (const [token, length, expected] of [["''", 0, ""], ["'é'", 2, "c3a9"], [String.raw`'\xE9'`, 4, "c3a90000"], ["'a\\\nb'", 4, "61620000"]] as const) test(`padding uses decoded bytes: ${JSON.stringify(token)}, ${length}`, () => {
  compare(`export circuit entry(): Bytes<${length}> { return pad(${length}, ${token}); }`, (facts, generated) => {
    assert.equal(returned(facts)[0].constant, expected);
    if (generated !== undefined) assert.deepEqual(JSON.parse(`[${/new Uint8Array\(\[([\d,\s]*)\]\)/.exec(generated)![1]}]`), [...Buffer.from(expected, "hex")]);
  });
});

for (const reference of ["'parts/Helper'", String.raw`"parts/Hel\x70er"`, "'parts/Hel\\\nper'"]) test(`quoted module import ${JSON.stringify(reference)}`, () => {
  compare({
    "main.compact": `import ${reference} prefix Helper_; export circuit entry(secret: Field): Field { return Helper_pass(secret); }`,
    "parts/Helper.compact": "module Helper { export circuit pass(value: Field): Field { return value; } }",
  }, facts => {
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
    assert.equal(facts.program.files.size, 2);
  });
});

for (const reference of ["'parts/body'", String.raw`"parts/b\u006fdy"`, "'parts/bo\\\r\ndy'"]) test(`quoted inclusion ${JSON.stringify(reference)}`, () => {
  compare({
    "main.compact": `include ${reference};`,
    "parts/body.compact": "export circuit entry(secret: Field): Field { return secret; }",
  }, facts => {
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
    assert.equal(facts.program.sources.inclusions.length, 1);
    assert.ok(returned(facts)[0].flows[0].source.location.file.endsWith("/parts/body.compact"));
  });
});

test("single-quoted external imports cannot resolve to same-named local modules", () => {
  compare({
    "main.compact": "module Helper { export circuit pass(value: Field): Field { return 0 as Field; } } import 'Helper' prefix External_; export circuit entry(secret: Field): Field { return External_pass(secret); }",
    "Helper.compact": "module Helper { export circuit pass(value: Field): Field { return value; } }",
  }, facts => assert.equal(returned(facts)[0].flows[0].source.name, "secret"));
});

test("assertion messages use decoded content with canonical display quoting", () => {
  compare(String.raw`export circuit entry(): [] { assert(false, 'bad\x20condition'); }`, facts => assert.equal(facts.failedAssertions[0].message, JSON.stringify("bad condition")));
});

for (const type of [String.raw`Opaque<'str\x69ng'>`, String.raw`Opaque<"Uint8\u0041rray">`, "Opaque<'str\\\ning'>"]) test(`decoded Opaque kind ${JSON.stringify(type)}`, () => {
  compare(`export circuit entry(secret: ${type}): ${type} { return secret; }`, facts => assert.equal(returned(facts)[0].flows[0].source.name, "secret"));
});

test("equivalent escaped Opaque types share generic specialization identity", () => {
  compare(String.raw`circuit pass<T>(value: T): T { return value; } export circuit entry(secret: Opaque<'string'>): Opaque<'string'> { return pass<Opaque<'str\x69ng'>>(pass<Opaque<"string">>(secret)); }`, facts => {
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
    assert.equal([...facts.program.functions.values()].filter(fn => fn.symbol.name === "pass").length, 1);
  });
});

for (const condition of [String.raw`'\xE9' == 'é'`, "'a\\\nb' == 'ab'", String.raw`'\01' == '\u00001'`]) test(`decoded equality preserves a private branch: ${JSON.stringify(condition)}`, () => {
  compare(`export circuit entry(secret: Field): Field { if (${condition}) { return secret; } return 0 as Field; }`, facts => {
    assert.equal(returned(facts).length, 1);
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
  });
});

test("continued padded randomness remains a constant at a commitment sink", () => {
  compare("import CompactStandardLibrary; export circuit entry(secret: Field): Bytes<32> { return disclose(persistentCommit<Field>(secret, pad(32, 'a\\\r\nb'))); }", facts => {
    const commitment = returned(facts)[0].commitments![0];
    assert.equal(commitment.randomness.constant, "6162".padEnd(64, "0"));
    assert.equal(detectors.find(detector => detector.id === "predictable-commitment-randomness")!.run(facts).length, 1);
    assert.ok(readFileSync(commitment.location.file).subarray(commitment.location.start, commitment.location.end).toString().includes("'a\\\r\nb'"));
  });
});

for (const [name, ending] of [["LF", "\n"], ["CRLF", "\r\n"], ["CR", "\r"], ["NEL", "\u0085"], ["CRNEL", "\r\u0085"], ["LS", "\u2028"]]) test(`original source mapping and frames survive ${name} normalization`, () => {
  // Keep the primary finding at an assertion site; literal-false reverts are
  // deliberately suppressed by the universal impossible-assertion contract.
  const statement = 'assert(1 > 2, "bad\\ncondition")';
  const source = ["// comment must end here", "export circuit entry(): [] {", `  /* Ω🚀 */ ${statement};`, "}"].join(ending);
  compare(source, facts => {
    const location = facts.failedAssertions[0].location;
    const original = readFileSync(location.file, "utf8");
    const prefix = original.slice(0, original.indexOf(statement));
    assert.equal(location.start, Buffer.byteLength(prefix));
    assert.equal(location.end, location.start + Buffer.byteLength(statement));
    assert.equal(location.line, 4);
    assert.equal(location.column, "  /* Ω🚀 */ ".length + 1);
    const result = scanFile(location.file);
    assert.equal(result.status, "complete");
    assert.equal(result.findings.length, 1);
    assert.ok(human(result).includes(`4 |   /* Ω🚀 */ ${statement};`));
    const report = sarif(result) as { runs: { results: { locations: { physicalLocation: { region: { byteOffset: number; startLine: number; startColumn: number } } }[] }[] }[] };
    assert.deepEqual(report.runs[0].results[0].locations[0].physicalLocation.region.byteOffset, location.start);
    assert.equal(report.runs[0].results[0].locations[0].physicalLocation.region.startLine, 4);
    assert.equal(report.runs[0].results[0].locations[0].physicalLocation.region.startColumn, location.column);
    assert.equal(facts.program.files.get(location.file)!.text, original);
  });
});

const invalidTokens = [String.raw`'\/'`, String.raw`'\a'`, String.raw`'\1'`, String.raw`'\q'`, String.raw`'\x0'`, String.raw`'\xGG'`, String.raw`'\u012'`, String.raw`'\u00GG'`, String.raw`'\u{41}'`];
for (const token of invalidTokens) test(`compiler-rejected string escape ${token}`, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; export circuit entry(): [] { const value = ${token}; }` }, directory => {
    const path = resolve(directory, "main.compact");
    compile(path, false);
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, "invalid-string");
    assert.deepEqual(result.coverage.completedEntries, []);
    const location = result.diagnostics[0].location;
    assert.equal(readFileSync(path).subarray(location.start, location.end).toString(), token);
  });
});

for (const body of [String.raw`circuit unused<T>(): [] { const value = '\q'; }`, String.raw`export circuit check(): [] { assert(true, '\q'); }`, String.raw`type Unused = Opaque<'str\qing'>;`]) test(`string escapes are checked even when a declaration or message is unused: ${body}`, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${body} export circuit entry(): [] {}` }, directory => {
    const path = resolve(directory, "main.compact");
    compile(path, false);
    assert.equal(scanFile(path).diagnostics[0]?.code, "invalid-string");
  });
});

for (const expression of ["pad(0,'a')", "pad(1,'é')", String.raw`pad(1,'\xFF')`, "pad(3,'🚀')"]) test(`compiler-rejected UTF-8 padding ${expression}`, () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; export circuit entry(): [] { const value = ${expression}; }` }, directory => {
    const path = resolve(directory, "main.compact");
    compile(path, false);
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.equal(result.diagnostics[0]?.code, "invalid-padding");
    assert.deepEqual(result.coverage.completedEntries, []);
  });
});

test("Unicode escape scalars reject surrogate code units rather than combining them", () => {
  const location = { file: "unit.compact", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
  for (const token of [String.raw`'\ud800'`, String.raw`'\udfff'`, String.raw`'\ud83d\ude80'`, "'\ud800'"]) assert.throws(() => decodeString(token, location), /scalar|surrogate/);
  assert.equal(decodeString(String.raw`'\uD7FF\uE000'`, location), "\ud7ff\ue000");
});

test("padding analysis limit is distinct from compiler source-size legality", () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; export circuit entry(): [] { const value = pad(${MAX_LITERAL_BYTES + 1}, ''); }` }, directory => {
    const path = resolve(directory, "main.compact");
    compile(path, true);
    for (const engine of ["instructions", "expressions"] as const) {
      const facts = new Dataflow(new Program(path), 20000, 256, 50000, engine).analyze();
      assert.deepEqual(facts.diagnostics.map(diagnostic => diagnostic.code), ["literal-budget"]);
      assert.deepEqual(facts.completedEntries, []);
    }
  });
});

test("maximum analyzed padding has an exact zero-filled constant", () => {
  const source = parseSource("unit.compact", `export circuit entry(): [] { const value = pad(${MAX_LITERAL_BYTES}, 'a'); }`);
  const block = source.ast.declarations[0].body!;
  assert.equal(block.kind, "block");
  if (block.kind !== "block") return;
  const binding = block.body[0];
  assert.equal(binding.kind, "bind");
  if (binding.kind !== "bind") return;
  const value = literalConstant(binding.expr)!;
  assert.equal(value.value.length, 2 * MAX_LITERAL_BYTES);
  assert.equal(value.value.slice(0, 4), "6100");
  assert.equal(value.value.slice(-4), "0000");
});
