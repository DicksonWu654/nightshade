import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import type { Diagnostic, Span } from "../src/model.js";
import type { ReviewBrief, ReviewQuestion } from "../src/reporting/review.js";
import { compactReviewDiagnostics, relativeReviewBrief, reviewMarkdown } from "../src/reporting/review-presentation.js";

const location = (file: string, line = 1): Span => ({ file, start: line - 1, end: line, line, column: 1, endLine: line, endColumn: 2 });
function fixture(root: string): ReviewBrief {
  return {
    schemaVersion: "nightshade-review-1", root, status: "incomplete", semanticProfile: "test-profile", scope: "Source facts need review.", pathFormat: "absolute",
    identity: { toolVersion: "test", sources: [{ file: root, sha256: "source-digest" }], budgets: { maxSteps: 20, maxPaths: 20, maxValues: 20 } },
    coverage: { scan: null, inventory: "incomplete", histories: "incomplete", diagnostics: [] },
    circuits: [], stateMachine: { scope: "May-read and may-write sketch.", fields: [] }, findings: [],
    questions: Array.from({ length: 12 }, (_, index): ReviewQuestion => ({
      id: `question-${index + 1}`, rank: index + 1, score: 100 - index, signals: ["observed-signal"], priority: index < 3 ? "high" : "medium", kind: "value-authorization", circuitIds: [], locations: [location(root)], question: `Review fact ${index + 1}?`, basis: "An observed source operation.",
    })),
    questionSummary: { generated: 12, visible: 10, collapsed: 2 },
    summary: { status: "incomplete", circuitCount: 0, findingCount: 0, questionCount: 12, visibleQuestions: 10, collapsedQuestions: 2, diagnosticGroups: 0, topQuestions: [] },
    explorer: { status: "not-run", replays: [], reason: "No replay executed." }, limitations: ["No authentication proof."],
  };
}

test("review presentation leads with compact top five and collapses beyond ten without losing questions", () => {
  const brief = fixture("/project/contracts/main.compact");
  const before = structuredClone(brief);
  const rendered = reviewMarkdown(brief);
  const summary = rendered.split("\n").slice(0, 13).join("\n");
  assert.match(summary, /Status: \*\*incomplete\*\*; profile: test-profile/);
  assert.match(summary, /Circuits: 0; audit findings: 0; review questions: 12/);
  assert.match(summary, /5\. \*\*medium\*\* Review fact 5\?/);
  assert.doesNotMatch(summary, /Review fact 6\?/);
  const collapsed = rendered.indexOf("<details><summary>2 more questions</summary>");
  assert.ok(collapsed > rendered.indexOf("**#10 /"));
  assert.ok(rendered.indexOf("**#11 /") > collapsed);
  assert.ok(rendered.indexOf("**#12 /") > collapsed);
  assert.match(rendered, /Signals: observed-signal/);
  assert.deepEqual(brief, before);
});

test("review diagnostic aggregation counts occurrences, preserves every unique span and is idempotent", () => {
  const diagnostics: Diagnostic[] = Array.from({ length: 5 }, (_, index) => ({ code: "analysis-budget", message: "Bounded analysis stopped", location: location("/project/main.compact", index + 1) }));
  diagnostics.push({ ...diagnostics[0] }, { ...diagnostics[0], message: "A different budget stopped" });
  const compact = compactReviewDiagnostics(diagnostics);
  assert.equal(compact.length, 2);
  assert.equal(compact[0].count, 6);
  assert.equal(compact[0].locations!.length, 5);
  assert.equal(compact[1].count, 1);
  assert.deepEqual(compactReviewDiagnostics(compact), compact);
  const brief = fixture("/project/main.compact");
  brief.coverage.diagnostics = compactReviewDiagnostics(diagnostics);
  const rendered = reviewMarkdown(brief);
  assert.match(rendered, /Coverage diagnostics: 7 occurrences in 2 groups/);
  assert.match(rendered, /analysis-budget × 6/);
  assert.match(rendered, /2 more locations in JSON/);
  assert.equal((rendered.match(/Bounded analysis stopped/g) ?? []).length, 1);
  assert.equal(diagnostics.length, 7);
});

test("portable review copies repo-relative identities and external dependency paths, preserving source excerpts", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-review-presentation-"));
  try {
    mkdirSync(resolve(directory, ".git"));
    mkdirSync(resolve(directory, "contracts"));
    const root = resolve(directory, "contracts/main.compact");
    const library = resolve(directory, "../external/library.compact");
    const brief = fixture(root);
    brief.identity.sources.push({ file: library, sha256: "library-digest" });
    brief.questions[0].circuitIds = [`${root}::mint`, `${library}::helper`];
    brief.questions[0].locations.push(location(library));
    brief.coverage.diagnostics.push({ code: "missing", count: 1, message: `Imported ${library} while processing ${root}`, location: location(root), scope: { kind: "rule", detectorId: "test", entry: `${root}::mint` } });
    brief.explorer.artifactPath = resolve(directory, "evidence/explorer.json");
    const before = structuredClone(brief);
    const portable = relativeReviewBrief(brief);
    assert.equal(portable.root, "contracts/main.compact");
    assert.equal(portable.identity.sources[1].file, "../external/library.compact");
    assert.deepEqual(portable.questions[0].circuitIds, ["contracts/main.compact::mint", "../external/library.compact::helper"]);
    assert.equal(portable.coverage.diagnostics[0].scope!.entry, "contracts/main.compact::mint");
    assert.equal(portable.explorer.artifactPath, "evidence/explorer.json");
    assert.ok(!JSON.stringify(portable).includes(directory));
    assert.deepEqual(relativeReviewBrief(portable), portable);
    assert.equal(reviewMarkdown(portable), reviewMarkdown(brief));
    assert.deepEqual(brief, before);
    // Literal source text that resembles an absolute host path remains source text.
    const literal = { ...brief, circuits: [{ expression: root, value: library }] } as unknown as ReviewBrief;
    const literalCopy = relativeReviewBrief(literal);
    assert.deepEqual(literalCopy.circuits, literal.circuits);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
