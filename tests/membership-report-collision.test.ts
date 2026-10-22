import assert from "node:assert/strict";
import test from "node:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { publicKeyMembershipObservations } from "../src/analysis/public-key-membership.js";

test("membership report tokens preserve distinct branch receivers and queries after relocation", () => {
  const temporary = mkdtempSync(join(tmpdir(), "ns-member-branches-"));
  try {
    const short = join(temporary, "s");
    let long = temporary;
    while (long.length < 320) long = join(long, "long-checkout-0123456789-abcdef");
    for (const selector of ["selected", "persistentHash<Bytes<32>>(selected)"]) {
      const source = `import CompactStandardLibrary;
export ledger members:Map<Bytes<32>,Set<Bytes<32>>>;export ledger stored:Field;
export circuit entry(a:Bytes<32>,b:Bytes<32>,flag:Boolean,next:Field):[]{
  const selected=disclose(flag)?a:b;
  assert(members.lookup(disclose(${selector})).member(disclose(ownPublicKey().bytes)),"member");
  stored=disclose(next);
}`;
      const reports = [short, long].map(directory => {
        mkdirSync(directory, { recursive: true });
        const file = join(directory, "main.compact"); writeFileSync(file, source);
        const facts = new Dataflow(new Program(file), 40000, 256, 50000, "instructions", true, true,
          "equivalent-states", false, true, "all", false, true).analyze();
        const observed = publicKeyMembershipObservations(facts);
        assert.deepEqual(observed.diagnostics, []);
        const raw = observed.observations.flatMap(observation => observation.reaches.map(reach => reach.guard));
        assert.equal(new Set(raw.map(guard => guard.receiver)).size, 2);
        assert.equal(new Set(raw.map(guard => guard.query.result.identity)).size, 2);
        const snapshot = () => {
          const result = scanFile(file, { detectors: ["public-key-membership-authorization"] });
          assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
          assert.deepEqual(result.diagnostics, []);
          assert.equal(result.findings.length, 1);
          const history = result.findings[0].metadata.historyEvidence as { receiverIdentity: string; queryResultIdentity: string; memberIdentity: string }[];
          assert.equal(history.length, raw.length);
          assert.equal(new Set(history.map(item => item.receiverIdentity)).size, 2);
          assert.equal(new Set(history.map(item => item.queryResultIdentity)).size, 2);
          assert.equal(new Set(history.map(item => item.memberIdentity)).size, new Set(raw.map(guard => guard.member)).size);
          return JSON.parse(JSON.stringify({ status: result.status, coverage: result.coverage,
            diagnostics: result.diagnostics, findings: result.findings,
            metrics: Object.fromEntries(Object.entries(result.metrics).filter(([key]) => !key.endsWith("Ms"))),
            ruleObservationWork: result.ruleObservationWork }).replaceAll(directory, "<ROOT>"));
        };
        const first = snapshot();
        assert.deepEqual(snapshot(), first, "fresh scans retain deterministic tokens");
        return first;
      });
      assert.deepEqual(reports[1], reports[0], selector);
    }
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
