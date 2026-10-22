import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { querySourceEntry } from "../src/dataflow/source-queries.js";
import { withFiles } from "./helpers.js";

// A hash chain over private proof data compared with a ledger root (a Merkle
// charter check) is a possible preimage binding only for its direct raw hash
// sources. Source queries admit it when no such source can be published and no
// selected history has a trusted preimage; findings match exhaustive histories.
const climb = (proof: string) => `
  const h0 = persistentHash<Vector<2, Bytes<32>>>([pad(32, "leaf"), disclose(node)]);
  const h1 = disclose(${proof}.indices[0]) ? persistentHash<Vector<3, Bytes<32>>>([pad(32, "node"), disclose(${proof}.siblings[0]), h0])
    : persistentHash<Vector<3, Bytes<32>>>([pad(32, "node"), h0, disclose(${proof}.siblings[0])]);
  const h2 = disclose(${proof}.indices[1]) ? persistentHash<Vector<3, Bytes<32>>>([pad(32, "node"), disclose(${proof}.siblings[1]), h1])
    : persistentHash<Vector<3, Bytes<32>>>([pad(32, "node"), h1, disclose(${proof}.siblings[1])]);
  assert(h2 == root, "charter");
`;
const header = `import CompactStandardLibrary;
export ledger root: Bytes<32>;
export ledger members: Map<Uint<8>, Field>;
export ledger shown: Bytes<32>;
struct Proof { siblings: Vector<2, Bytes<32>>, indices: Vector<2, Boolean> }
witness authorized(): Boolean;
witness flags(): Vector<4, Boolean>;
witness proofOf(node: Bytes<32>): Proof;
`;
const expand = `  const selected = flags();
  for (const i of 0..4) { if (disclose(selected[i])) { members.insert(i as Uint<8>, 1 as Field); } }
`;

function withProgram(source: string, run: (program: Program, file: string) => void): void {
  withFiles({ "main.compact": header + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    run(new Program(file), file);
  });
}
const signatures = (result: ReturnType<typeof scanFile>) => result.findings.map(finding => ({
  detector: finding.detectorId, location: finding.location, fingerprint: finding.fingerprint, message: finding.message,
  effects: finding.metadata.affectedEffects, soleGate: finding.metadata.soleGate,
})).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));

test("charter hash chains against ledger roots are admitted by source queries and keep exhaustive findings", () => {
  for (const [name, proof, parameter] of [["parameter", "proof", ", proof: Proof"], ["witness", "p", ""]] as const) {
    withProgram(`export circuit register(node: Bytes<32>${parameter}): [] {
  assert(authorized(), "authorization");
${parameter ? "" : "  const p = proofOf(node);\n"}${climb(proof)}${expand}}`, (program, file) => {
      for (const engine of ["instructions", "expressions"] as const) {
        const query = querySourceEntry(new Dataflow(program, 40000, 8, 50000, engine), program.entries[0]);
        assert.equal(query.status, "covered", `${name}/${engine}: ${query.status === "incomplete" ? query.reason : ""}`);
      }
      const projected = scanFile(file, { maxPaths: 8 }), exact = scanFile(file);
      assert.equal(projected.coverage.baselineStatus, "complete", JSON.stringify(projected.diagnostics));
      assert.equal(exact.coverage.baselineStatus, "complete", JSON.stringify(exact.diagnostics));
      // The sound exact digest observer refuses hidden selector constraints.
      // This query still completes baseline facts; extra rule obligations remain explicit.
      for (const result of [projected,exact]) if (result.status !== "complete") {
        assert.ok(result.diagnostics.length > 0);
        assert.ok(result.diagnostics.every(issue=>issue.scope?.detectorId === "low-entropy-hash-disclosure"
          && issue.code === "observation-compression-dependency"),JSON.stringify(result.diagnostics));
      }
      assert.deepEqual(signatures(projected), signatures(exact), name);
      assert.ok(projected.findings.some(finding => finding.detectorId === "spoofable-authorization"
        && finding.metadata.historyCoverage === "shared-source-query-with-ordinary-witnesses"), name);
    });
  }
});

test("a published direct hash source of a ledger comparison keeps the source query incomplete", () => {
  withProgram(`export circuit register(node: Bytes<32>, proof: Proof): [] {
  assert(authorized(), "authorization");
${climb("proof")}  shown = disclose(proof.siblings[1]);
${expand}}`, (program, file) => {
    const query = querySourceEntry(new Dataflow(program, 40000, 8), program.entries[0]);
    assert.equal(query.status, "incomplete");
    if (query.status === "incomplete") assert.match(query.reason, /ledger-bound preimage source may be published/);
    const projected = scanFile(file, { maxPaths: 8 });
    assert.equal(projected.status, "incomplete");
  });
});

test("direct private preimage checks remain outside source-query certification", () => {
  withProgram(`export circuit register(secret: Bytes<32>): [] {
  assert(persistentHash<Bytes<32>>(disclose(secret)) == root, "secret");
${expand}}`, program => {
    const exact = new Dataflow(program, 40000, 256).analyze();
    assert.deepEqual(exact.diagnostics, []);
    assert.ok(exact.paths.every(path => path.bindings.length > 0));
    const query = querySourceEntry(new Dataflow(program, 40000, 8), program.entries[0]);
    assert.equal(query.status, "incomplete");
    if (query.status === "incomplete") assert.match(query.reason, /[Pp]reimage/);
  });
});


test("a compressed selector cannot replace the origin of a later required authorization guard",()=>withProgram(`
witness direction(): Boolean;
export circuit register(a: Bytes<32>, b: Bytes<32>): [] {
  const flag=direction();
  const candidate=disclose(flag) ? persistentHash<Vector<2,Bytes<32>>>([disclose(a),disclose(b)])
    : persistentHash<Vector<2,Bytes<32>>>([disclose(b),disclose(a)]);
  assert(candidate==root,"root");
  assert(flag,"actual authorization");
  members.insert(1,1 as Field);
}`, (program,file)=>{
  for(const engine of ["instructions","expressions"] as const)for(const cached of [false,true]) {
    const query=querySourceEntry(new Dataflow(program,40000,256,50000,engine,cached,cached),program.entries[0]);
    assert.equal(query.status,"incomplete");
    if(query.status==="incomplete") assert.match(query.reason,/choice-only selector.*origin is unresolved/);
  }
  const exact=scanFile(file,{detectors:["spoofable-authorization"]});
  assert.equal(exact.status,"complete",JSON.stringify(exact.diagnostics));
  assert.equal(exact.findings.length,1);
  assert.equal(exact.findings[0].location.line,readFileSync(file,"utf8").split("\n").findIndex(line=>line.includes('assert(flag,"actual authorization")'))+1);
}));
