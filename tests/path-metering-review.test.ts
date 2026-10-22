import assert from "node:assert/strict";
import test from "node:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Program, scanFile } from "../src/index.js";
import { immutableOperandKey } from "../src/dataflow/immutable-key.js";
import { prepareSourceClaims } from "../src/semantic/source-claims.js";
import { prepareSourceMapGetters } from "../src/semantic/source-map-getters.js";
import { genericWitnessAbi } from "../src/semantic/generic-witness-abi.js";

function relocated(run: (short: string, long: string) => void) {
  const temporary = mkdtempSync(join(tmpdir(), "ns-review-"));
  try {
    const short = join(temporary, "s");
    let long = temporary;
    while (long.length < 320) long = join(long, "long-checkout-0123456789-abcdef");
    mkdirSync(short); mkdirSync(long, { recursive: true });
    run(short, long);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

test("quoted Opaque arguments preserve sibling type accounting at default budgets", context => {
  relocated((short, long) => {
    for (const [shape, declaration, key] of [
      ["tuple", "new type Tag=Bytes<4>;", '[Tag,Opaque<"string">]'],
      ["phantom", "new type Tag=Bytes<4>; struct Box<T,U>{value:T;}", 'Box<Tag,Opaque<"string">>'],
    ]) {
      const header = `import CompactStandardLibrary;${declaration}witness lookup<T>(key:${key}):Maybe<T>;`;
      const source = header + ["Uint<64>", "Bytes<32>"].map((type, index) =>
        `export circuit entry${index}(key:${key}):Maybe<${type}>{${`lookup<${type}>(key);`.repeat(125)}return disclose(lookup<${type}>(key));}`).join("\n");
      const summaries = [short, long].map(directory => {
        const file = join(directory, `${shape}.compact`); writeFileSync(file, source);
        const program = new Program(file), enumeration = genericWitnessAbi(program);
        const result = scanFile(file, { detectors: ["generic-witness-maybe-abi"] });
        const summary = { status: result.status, diagnostics: result.diagnostics.map(d => [d.code, d.message]),
          findings: result.findings.map(f => [f.detectorId, f.location.line]),
          work: result.ruleObservationWork?.map(r => r.metrics), enumeration: { complete: enumeration.complete, work: enumeration.work } };
        context.diagnostic(JSON.stringify({ shape, pathLength: file.length, ...summary }));
        return summary;
      });
      assert.deepEqual(summaries[1], summaries[0]);
      assert.equal(summaries[0].status, "complete");
      assert.equal(summaries[0].findings.length, 1);
    }
  });
});

test("nested generic and tuple types charge no checkout prefix", context => {
  relocated((short, long) => {
    const declaration = "import CompactStandardLibrary; new type NumberValue = Uint<64>; new type BytesValue = Bytes<32>; witness lookup<T>(key:Bytes<4>):Maybe<T>;";
    const entries = ["NumberValue", "BytesValue"].map((type, index) =>
      `export circuit entry${index}(key:Bytes<4>):Maybe<${type}>{${`lookup<${type}>(key);`.repeat(20)}return disclose(lookup<${type}>(key));}`).join("\n");
    const summaries = [short, long].map(directory => {
      const file = join(directory, "generic.compact");
      writeFileSync(file, declaration + entries);
      const program = new Program(file);
      const enumeration = genericWitnessAbi(program);
      const result = scanFile(file, { detectors: ["generic-witness-maybe-abi"] });
      const summary = { status: result.status, diagnostics: result.diagnostics.map(d => [d.code, d.message]),
        findings: result.findings.map(f => [f.detectorId, f.location.line]),
        work: result.ruleObservationWork?.map(r => r.metrics), enumeration: { complete: enumeration.complete, work: enumeration.work } };
      context.diagnostic(JSON.stringify({ pathLength: file.length, ...summary }));
      return summary;
    });
    assert.deepEqual(summaries[1], summaries[0]);
    assert.equal(summaries[0].status, "complete");
    assert.equal(summaries[0].findings.length, 1);

    const types = "new type Tag=Field; struct Box<T>{value:T;} export circuit generic(value:Box<Tag>):Box<Tag>{return value;} export circuit tuple(value:[Tag,Field]):[Tag,Field]{return value;}";
    const measured = [short, long].map(directory => {
      const file = join(directory, "shapes.compact"); writeFileSync(file, types);
      const program = new Program(file);
      return program.entries.map(entry => program.meteringIdentity(program.symbols.get(entry)!.type));
    });
    assert.deepEqual(measured[1], measured[0]);
  });
});

test("public-key membership finding metadata is stable after relocation", () => {
  relocated((short, long) => {
    const source = readFileSync(resolve("tests/corpus/known-bugs/sdk-public-key-membership-positive.compact"), "utf8");
    const summaries = [short, long].map(directory => {
      const file = join(directory, "membership.compact"); writeFileSync(file, source);
      const result = scanFile(file);
      assert.ok(result.findings.some(finding => finding.detectorId === "public-key-membership-authorization"));
      return JSON.parse(JSON.stringify({
        status: result.status, diagnostics: result.diagnostics, findings: result.findings,
        metrics: { steps: result.metrics.steps, paths: result.metrics.paths, values: result.metrics.abstractValues },
        ruleObservationWork: result.ruleObservationWork,
      }).replaceAll(directory, "<ROOT>"));
    });
    assert.deepEqual(summaries[1], summaries[0]);
  });
});

test("pathname spellings cannot erase source identifiers at the 65536 identity cap", context => {
  relocated(short => {
    const filename = "A".repeat(200), identifier = "A".repeat(80000);
    writeFileSync(join(short, filename), `export circuit ${identifier}(value:Field):Field{return value;}`);
    const cwd = process.cwd();
    try {
      process.chdir(short);
      const program = new Program(filename), entry = program.entries[0];
      let values = 0;
      const meter = Object.assign((_work: number, retained: number) => { values += retained; return true; },
        { identityText: program.meteringIdentity });
      const result = immutableOperandKey({ identity: entry, flows: [], ledger: new Set() }, 4096, undefined, meter);
      context.diagnostic(JSON.stringify({ raw: entry.length, measured: program.meteringIdentity(entry).length, values, complete: result.complete }));
      assert.equal(result.complete, false, "source identifier exceeds the unchanged 65536-character cap");
      assert.ok(program.meteringIdentity(entry).endsWith(`::${identifier}`));
    } finally { process.chdir(cwd); }
  });
});

test("a physical symlink target cannot consume a different symbol identity", () => {
  relocated(short => {
    const identifier = "A".repeat(180), file = join(short, "main.compact"), other = `${file}::${identifier}`;
    writeFileSync(file, `import "Other"; export circuit ${identifier}(value:Field):Field{return value;}`);
    writeFileSync(other, "module Other { export circuit get():Field{return 1;} }");
    symlinkSync(other, join(short, "Other.compact"));
    const program = new Program(file);
    assert.equal(program.meteringIdentity(program.entries[0]), program.meteringIdentity(file) + "::" + identifier);
  });
});

test("List growth retains identical default-budget evidence after checkout relocation", context => {
  relocated((short, long) => {
    const header = "import CompactStandardLibrary; export ledger records:Map<Bytes<32>,List<Bytes<32>>>;";
    const parameters = "recipient:Bytes<32>,color:Bytes<32>,amount:Uint<128>,memo:Bytes<32>";
    const body = 'sendUnshielded(disclose(color),disclose(amount),right<ContractAddress,UserAddress>(UserAddress{bytes:disclose(recipient)}));records.lookup(disclose(recipient)).pushFront(disclose(memo));assert(disclose(amount)<=100,"cap");';
    const source = header + Array.from({ length: 26 }, (_, i) => `export circuit entry${i}(${parameters}):[]{${body}}`).join("\n");
    const results = [short, long].map(directory => {
      const file = join(directory, "many.compact"); writeFileSync(file, source);
      const result = scanFile(file, { detectors: ["zero-transfer-retained-list-review"] });
      const summary = { status: result.status, diagnostics: result.diagnostics.map(d => [d.code, d.message]),
        findings: result.findings.map(f => [f.detectorId, f.location.line]), work: result.ruleObservationWork?.map(r => r.metrics) };
      context.diagnostic(JSON.stringify({ pathLength: file.length, ...summary }));
      return summary;
    });
    assert.deepEqual(results[1], results[0]);
    assert.equal(results[0].status, "complete"); assert.equal(results[0].findings.length, 26);
  });
});

for (const kind of ["issuance", "map-getter"] as const) test(`canonical ${kind} policy preparation and scan budgets ignore checkout prefix`, context => {
  relocated((short, long) => {
    const name = kind === "issuance" ? "source-claim-shielded-issuance-review-case-42" : "source-claim-map-getter-review-case-5";
    const source = readFileSync(resolve(`tests/corpus/synthetic-regressions/state16/${name}-positive.compact`), "utf8");
    const results = [short, long].map(directory => {
      const file = join(directory, "claim.compact"); writeFileSync(file, source);
      const program = new Program(file);
      let work = 0, values = 0;
      const charge = (steps = 1, retained = 0) => { work += steps; values += retained; return true; };
      const id = (name: string) => [...program.symbols.values()].find(s => s.name === name)!.id;
      let policies;
      if (kind === "issuance") {
        const policy = { kind: "non-transferable-shielded-issuance" as const, circuit: id("issue"), quote: "// Contract claim: recipients cannot transfer issued coins to other parties." };
        prepareSourceClaims(program, [policy], charge); policies = { sourceClaims: [policy] };
      } else {
        const setter = id("setAdmin"), getter = id("getRoleAdmin");
        const policy = { setter, getter, map: id("roleAdmin"), setterKey: setter + "::parameter:role", setterValue: setter + "::parameter:admin", getterKey: getter + "::parameter:role",
          quote: "// Documentation claims DEFAULT_ADMIN_ROLE is customizable by roleAdmin entry." };
        prepareSourceMapGetters(program, [policy], charge); policies = { sourceMapGetters: [policy] };
      }
      const detectors = [kind === "issuance" ? "source-claim-shielded-issuance-review" : "source-claim-map-getter-review"];
      const result = scanFile(file, { detectors, policies });
      const summary = { preparation: { work, values }, status: result.status, diagnostics: result.diagnostics.map(d => [d.code, d.message]),
        findings: result.findings.map(f => [f.detectorId, f.location.line]), work: result.ruleObservationWork?.map(r => r.metrics) };
      context.diagnostic(JSON.stringify({ pathLength: file.length, ...summary }));
      return summary;
    });
    assert.deepEqual(results[1], results[0]);
    assert.equal(results[0].status, "complete"); assert.equal(results[0].findings.length, 1);
  });
});
