import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

test("every local Markdown file link resolves in the actual npm package file list", () => {
  const pack = spawnSync("npm", ["pack", "--dry-run", "--ignore-scripts", "--json"], { encoding: "utf8", timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
  assert.equal(pack.status, 0, pack.stderr);
  const files = new Set<string>(JSON.parse(pack.stdout)[0].files.map((file: { path: string }) => file.path));
  let checked = 0;
  for (const file of files) {
    if (!file.endsWith(".md")) continue;
    const text = readFileSync(file, "utf8");
    for (const match of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
      const url = match[1].split("#")[0];
      if (!url || /^[a-z]+:/i.test(url)) continue;
      const target = relative(process.cwd(), resolve(dirname(file), decodeURIComponent(url))).replaceAll("\\", "/");
      assert.ok(files.has(target), `${file}: ${match[1]} is missing from the package`);
      checked++;
    }
  }
  assert.ok(checked > 100, `Only checked ${checked} package links`);
  assert.ok(![...files].some(path => path.startsWith("tests/")), "Source test corpora stay outside the package");
});
