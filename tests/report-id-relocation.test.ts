import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { reviewFile } from "../src/reporting/review.js";
import { auditFile } from "../src/reporting/auditor.js";

const source = `pragma language_version 0.26.0;
import CompactStandardLibrary;
export ledger items: Map<Bytes<32>, Field>;
circuit save(key: Bytes<32>, value: Field): [] {
  items.insert(disclose(persistentHash<Bytes<32>>(key)), disclose(value));
}
export circuit put(first: Bytes<32>, second: Bytes<32>, next: Field): [] {
  save(first, next);
  save(second, next);
}
`;

function relocated(run: (roots: string[]) => void): void {
  const temporary = mkdtempSync(resolve(tmpdir(), "report-ids-"));
  const roots = [resolve(temporary, "s"), resolve(temporary, "long-component-".repeat(12), "another-component-".repeat(10))];
  try {
    assert.ok(roots[1].length >= 300);
    for (const root of roots) {
      mkdirSync(root, { recursive: true });
      writeFileSync(resolve(root, "main.compact"), source);
    }
    run(roots);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

test("review question IDs use portable source coordinates", () => relocated(roots => {
  const reports = roots.map(root => reviewFile(resolve(root, "main.compact")));
  for (const [index, report] of reports.entries()) {
    assert.equal(report.status, "complete", JSON.stringify(report.coverage.diagnostics));
    assert.ok(report.questions.length > 0);
    assert.equal(report.root, resolve(roots[index], "main.compact"), "Reported physical paths remain unchanged");
  }
  assert.deepEqual(reports[0].questions.map(({ id, kind, rank }) => ({ id, kind, rank })),
    reports[1].questions.map(({ id, kind, rank }) => ({ id, kind, rank })));
}));

test("auditor write site IDs omit raw operand digests and retain separate invocation sites", () => relocated(roots => {
  const reports = roots.map(root => auditFile(resolve(root, "main.compact"), "ledger-access"));
  const snapshots = reports.map((report, index) => {
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    const data = report.data as { sites: { id: string; location: { file: string }; occurrences: number }[];
      histories: { writes: { site: string }[] }[] };
    assert.equal(data.sites.length, 2, "Both calls to the same source write retain separate sites");
    assert.equal(new Set(data.sites.map(site => site.id)).size, 2);
    assert.ok(data.sites.every(site => site.location.file === resolve(roots[index], "main.compact")));
    return JSON.parse(JSON.stringify(data).replaceAll(roots[index], "<ROOT>"));
  });
  assert.deepEqual(snapshots[0], snapshots[1]);
}));

test("review CLI artifact names depend on source paths within the requested root", () => relocated(roots => {
  const snapshots = roots.map(root => {
    const output = resolve(root, "out");
    const command = spawnSync(process.execPath, [fileURLToPath(new URL("../src/cli.js", import.meta.url)),
      "review", resolve(root, "main.compact"), "--out", output], { encoding: "utf8", timeout: 15000 });
    assert.equal(command.status, 0, command.stderr + command.stdout);
    const manifest = JSON.parse(readFileSync(resolve(output, "manifest.json"), "utf8"));
    assert.equal(manifest.contracts.length, 1);
    assert.equal(manifest.contracts[0].status, "complete");
    assert.equal(readdirSync(output).length, 3);
    return manifest.contracts.map(({ json, markdown }: { json: string; markdown: string }) => ({ json, markdown }));
  });
  assert.deepEqual(snapshots[0], snapshots[1]);
}));
