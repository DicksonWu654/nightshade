import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

export function analyzerIdentity(): string {
  const identity = createHash("sha256");
  const sources = readdirSync("src", { recursive: true }).map(String).filter(file => /\.(ts|c|cjs|json)$/.test(file)).map(file => `src/${file}`);
  for (const file of [...sources, "binding.gyp", "scripts/build-parser.mjs", "package.json", "package-lock.json"].sort()) {
    identity.update(file).update("\0").update(readFileSync(resolve(file))).update("\0");
  }
  return identity.digest("hex");
}
