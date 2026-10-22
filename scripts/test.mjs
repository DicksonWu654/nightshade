import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { availableParallelism } from "node:os";

// Real deadlines and compiled multi-evaluation runs are host-sensitive. Keep
// their assertions and limits intact, but run them separately and serially.
// Injected-clock budget tests stay in the ordinary correctness suite.
const [suite, ...arguments_] = process.argv.slice(2);
const selected = [], options = new Map();
for (let index = 0; index < arguments_.length; index++) {
  const argument = arguments_[index];
  if (argument === "--concurrency") {
    const value = arguments_[++index];
    if (options.has(argument) || !/^[1-9]\d*$/.test(value ?? "") || Number(value) > 64) { console.error("Concurrency must be an integer from 1 to 64"); process.exit(2); }
    options.set(argument, Number(value));
  } else selected.push(argument);
}
const concurrency = suite === "timing" ? 1 : options.get("--concurrency") ?? Math.min(32, availableParallelism());
if (suite === "timing" && options.has("--concurrency") && options.get("--concurrency") !== 1) { console.error("Timing suite must remain serial"); process.exit(2); }
if (suite !== "correctness" && suite !== "timing") {
  console.error("Usage: node scripts/test.mjs correctness|timing [--concurrency N] [dist/tests/FILE.test.js ...]");
  process.exit(2);
}
const files = selected.length ? selected : readdirSync("dist/tests")
  .filter(name => name.endsWith(".test.js")).sort().map(name => resolve("dist/tests", name));
if (!files.length || files.some(name => name.startsWith("-") || !name.endsWith(".test.js"))) {
  console.error("Expected at least one built .test.js file");
  process.exit(2);
}
const missing = files.filter(name => !existsSync(name) || !statSync(name).isFile());
if (missing.length) {
  console.error(`Built test files not found: ${missing.join(", ")}`);
  process.exit(2);
}
console.error(`Running ${suite}: ${files.length} files, ${concurrency} workers; all assertions retained.`);
const env = { ...process.env };
if (suite === "correctness") env.NIGHTSHADE_FIXTURE_CACHE ??= resolve(".cache/compactc-fixtures/v1");
else { delete env.NIGHTSHADE_FIXTURE_CACHE; env.NIGHTSHADE_DISABLE_FIXTURE_CACHE = "1"; }
const result = spawnSync(process.execPath, ["--test", `--test-concurrency=${concurrency}`,
  `--test-${suite === "timing" ? "name" : "skip"}-pattern=\\[timing\\]`, ...files], { stdio: "inherit", env });
if (result.error) console.error(result.error.message);
process.exit(result.status ?? 1);
