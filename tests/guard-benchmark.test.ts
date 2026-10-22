import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { withFiles } from "./helpers.js";

const worker = fileURLToPath(new URL("../benchmarks/guards.js", import.meta.url));

test("guard benchmark qualifies only its two policy rules on complete core facts", () => {
  for (const size of [6, 12]) {
    const source = `pragma language_version >= 0.26.0; export ledger authorized: Boolean; export ledger sensitive: Field; ${Array.from({ length: size }, (_, index) => `circuit check${index}(): [] { assert(authorized, "authorized"); }`).join(" ")} export circuit entry(${Array.from({ length: size }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { assert(authorized, "authorized"); ${Array.from({ length: size }, (_, index) => `if (disclose(flag${index})) { check${index}(); }`).join(" ")} sensitive = 1 as Field; }`;
    withFiles({ "main.compact": source }, directory => {
      const measure = (mode: "covered" | "exact") => {
        const result = spawnSync(process.execPath, [worker, "--worker", resolve(directory, "main.compact"), mode], { encoding: "utf8", timeout: 30000 });
        assert.equal(result.status, 0, result.stderr);
        return JSON.parse(result.stdout) as {
          baselineComplete: boolean; selectedRulesComplete: boolean | null; complete: boolean;
          diagnostics: string[]; ruleDiagnostics: string[]; selectedRuleFindingCounts: Record<string, number> | null;
          detectorObservationSha256: string | null; paths: number; guardSubsumptions: number;
        };
      };
      const covered = measure("covered"), exact = measure("exact");
      assert.equal(covered.baselineComplete, true);
      assert.equal(covered.selectedRulesComplete, true);
      assert.equal(covered.complete, true);
      assert.deepEqual(covered.diagnostics, []);
      assert.deepEqual(covered.ruleDiagnostics, []);
      assert.deepEqual(covered.selectedRuleFindingCounts, {
        "declared-secret-publication": size, "unguarded-sensitive-state-write": size,
      });
      assert.match(covered.detectorObservationSha256!, /^[a-f0-9]{64}$/);
      assert.equal(covered.paths, 1);
      assert.equal(covered.guardSubsumptions, size);
      assert.equal(exact.guardSubsumptions, 0);
      if (size === 6) {
        assert.equal(exact.baselineComplete, true);
        assert.equal(exact.selectedRulesComplete, true);
        assert.equal(exact.complete, true);
        assert.deepEqual(exact.diagnostics, []);
        assert.deepEqual(exact.selectedRuleFindingCounts, covered.selectedRuleFindingCounts);
        assert.equal(exact.paths, 64);
        assert.equal(exact.detectorObservationSha256, covered.detectorObservationSha256);
      } else {
        assert.equal(exact.baselineComplete, false);
        assert.equal(exact.selectedRulesComplete, null);
        assert.equal(exact.complete, false);
        assert.deepEqual(exact.diagnostics, ["analysis-budget"]);
        assert.deepEqual(exact.ruleDiagnostics, []);
        assert.equal(exact.selectedRuleFindingCounts, null);
        assert.equal(exact.detectorObservationSha256, null);
        assert.equal(exact.paths, 250);
      }
    });
  }
});
