import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { Dataflow, Program } from "../src/index.js";
import { AnalysisFacts } from "../src/dataflow/index.js";

// Historical default rules retained only by the explicit hygiene profile.
export const hygieneOnlyDetectors = new Set([
  "unnecessary-disclose", "time-dependence", "unused-declaration",
  "always-true-assertion", "dead-code", "constant-condition", "shadowing",
]);

export function withFiles(files: Record<string, string>, callback: (directory: string) => void, temporaryDirectory = tmpdir()): void {
  // Fixture expectations use physical source paths. Canonicalize only this
  // generated directory; intentional symlinks inside fixtures remain intact.
  const directory = realpathSync(mkdtempSync(resolve(temporaryDirectory, "nightshade-test-")));
  try {
    for (const [name, source] of Object.entries(files)) {
      mkdirSync(dirname(resolve(directory, name)), { recursive: true });
      writeFileSync(resolve(directory, name), source);
    }
    callback(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function analyze(source: string, callback: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const facts = new Dataflow(new Program(resolve(directory, "main.compact"))).analyze();
    assert.deepEqual(facts.diagnostics, []);
    callback(facts);
  });
}

export function semanticPaths(facts: AnalysisFacts): string[] {
  const normalize = (value: unknown): unknown => {
    if (value instanceof Set) return [...value].sort();
    if (Array.isArray(value)) return value.map(normalize);
    if (value && typeof value === "object") {
      const record = value as Record<string, unknown>;
      return Object.fromEntries(Object.keys(record).filter(key => key !== "trace").sort().map(key => {
        const item = key === "label" && record.kind === "branch" ? String(record.label).match(/(?:true|false)$/)?.[0] ?? record.label : record[key];
        return [key, normalize(item)];
      }));
    }
    return value;
  };
  return facts.paths.map(path => JSON.stringify(normalize(path))).sort();
}
