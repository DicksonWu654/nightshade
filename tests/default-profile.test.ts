import assert from "node:assert/strict";
import test from "node:test";
import { scanFile } from "../src/index.js";
import { hygieneOnlyDetectors as hygiene } from "./helpers.js";
const file = "tests/corpus/informational/dead-code-positive.compact";

test("audit is the default profile and hygiene restores the historical selection", () => {
  const audit = scanFile(file);
  assert.ok(audit.coverage.detectors.includes("freshness-bound-caller-time"));
  assert.ok(audit.coverage.detectors.includes("discarded-shielded-send-result"));
  assert.ok(audit.coverage.detectors.includes("merkle-membership-not-enforced"));
  assert.deepEqual(audit.coverage.detectors.filter(id => hygiene.has(id)), []);
  const explicitAudit = scanFile(file, { profile: "audit" });
  assert.deepEqual(explicitAudit.coverage.detectors, audit.coverage.detectors);
  const legacy = scanFile(file, { profile: "hygiene" });
  assert.deepEqual(new Set(legacy.coverage.detectors.filter(id => hygiene.has(id))), hygiene);
});
