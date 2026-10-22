import { createHash } from "node:crypto";
import { basename, delimiter, dirname, relative, resolve } from "node:path";
import { mkdirSync, statSync, writeFileSync, readFileSync, realpathSync } from "node:fs";
import { discoverProjectIsolated } from "../semantic/project.js";
import type { CompilerVersion, ZkirVersion } from "../semantic/profile.js";
import type { ExecutionLimits } from "../runtime/process.js";
import { reviewFileIsolated, reviewMarkdown, type ReviewOptions } from "./review.js";
import { repositoryRelativePath } from "./review-presentation.js";

/** Offline opt-in command. Each contract runs in its own supervised worker. */
export async function reviewCommand(args: string[], compilerVersion?: CompilerVersion, zkirVersion?: ZkirVersion): Promise<number> {
  const options: ReviewOptions = { compilerVersion, zkirVersion }, limits: ExecutionLimits = {};
  const values = new Map<string, string>(); let root: string | undefined;
  const flags = ["--out", "--compact-path", "--max-steps", "--max-paths", "--max-values", "--timeout-ms", "--heap-mib", "--explorer-report"];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (flags.includes(arg)) {
      const value = args[++i];
      if (!value || value.startsWith("--") || values.has(arg)) throw new Error(`${arg} requires exactly one value`);
      values.set(arg, value);
    } else if (arg.startsWith("-") || root) throw new Error("Use nightshade review ROOT --out NEW_DIRECTORY [--compact-path PATHS] [--compiler-version V] [--zkir-version 2|3] [--max-steps N] [--max-paths N] [--max-values N] [--timeout-ms N] [--heap-mib N]");
    else root = resolve(arg);
  }
  if (!root || !values.has("--out")) throw new Error("review requires ROOT and --out NEW_DIRECTORY");
  for (const [flag, key] of [["--max-steps", "maxSteps"], ["--max-paths", "maxPaths"], ["--max-values", "maxValues"]] as const) if (values.has(flag)) {
    const number = Number(values.get(flag)); if (!Number.isSafeInteger(number) || number < 1) throw new Error(`${flag} must be a positive integer`); options[key] = number;
  }
  for (const [flag, key] of [["--timeout-ms", "timeoutMs"], ["--heap-mib", "heapMiB"]] as const) if (values.has(flag)) {
    const number = Number(values.get(flag)); if (!Number.isSafeInteger(number) || number < 1) throw new Error(`${flag} must be a positive integer`); limits[key] = number;
  }
  const searchPaths = values.get("--compact-path")?.split(delimiter).filter(Boolean).map(p => resolve(p)) ?? [];
  const discovery = statSync(root).isDirectory() ? await discoverProjectIsolated(root, [], limits) : undefined;
  const files = discovery?.files ?? [root];
  let explorer: import("./review.js").ReviewBrief["explorer"] | undefined;
  if (values.has("--explorer-report")) {
    if (discovery) throw new Error("--explorer-report requires a single contract root");
    const path = resolve(values.get("--explorer-report")!);
    if (statSync(path).size > 8 * 1024 * 1024) throw new Error("Explorer attachment exceeds 8 MiB");
    const bytes = readFileSync(path); if (bytes.length > 8 * 1024 * 1024) throw new Error("Explorer attachment exceeds 8 MiB");
    const supplied = JSON.parse(bytes.toString("utf8"));
    if (supplied.schemaVersion !== "nightshade-explore-2" || typeof supplied.root !== "string" || realpathSync(supplied.root) !== realpathSync(root)
      || !Array.isArray(supplied.replay) || supplied.replay.length > 10000
      || supplied.replay.some((r: Record<string, unknown>) => !r || typeof r.circuit !== "string" || typeof r.status !== "string" || (r.replayId !== undefined && typeof r.replayId !== "string")))
      throw new Error("Explorer attachment must be a bounded nightshade-explore-2 report for this root");
    explorer = { status: "attached-source-unverified", artifactPath: path, artifactSha256: createHash("sha256").update(bytes).digest("hex"),
      reason: "Supplied historical replay references only. Source/build/runtime identity and replay outcomes have not been reverified by review mode. No private arguments, witness values or state are copied.",
      replays: supplied.replay.map((r: { replayId?: string; circuit: string; status: string; transition?: boolean }) => ({ id: r.replayId, circuit: r.circuit, status: r.status, transition: r.transition === true })) };
  }
  const output = resolve(values.get("--out")!);
  mkdirSync(output); // Refuses overwrite; existing evidence is never replaced.
  const manifest = { schemaVersion: "nightshade-review-batch-1", status: "complete", root: repositoryRelativePath(root, root), libraries: discovery?.libraries ?? [], diagnostics: discovery?.diagnostics ?? [], contracts: [] as { root: string; status: string; json: string; markdown: string; questions: number }[] };
  if (discovery?.status === "incomplete" || !files.length) manifest.status = "incomplete";
  for (const file of files) {
    const brief = await reviewFileIsolated(file, { ...options, searchPaths: [...searchPaths, ...discovery?.searchPaths[file] ?? []] }, limits);
    if (explorer) brief.explorer = explorer;
    const sourceDirectory = discovery ? root : dirname(root);
    const stem = `${basename(file, ".compact")}-${createHash("sha256").update(relative(sourceDirectory, file)).digest("hex").slice(0, 12)}`;
    writeFileSync(resolve(output, `${stem}.json`), JSON.stringify(brief, null, 2) + "\n", { flag: "wx" });
    writeFileSync(resolve(output, `${stem}.md`), reviewMarkdown(brief), { flag: "wx" });
    manifest.contracts.push({ root: brief.root, status: brief.status, json: `${stem}.json`, markdown: `${stem}.md`, questions: brief.questions.length });
    if (brief.status !== "complete") manifest.status = "incomplete";
  }
  writeFileSync(resolve(output, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
  console.log(JSON.stringify(manifest, null, 2));
  return manifest.status === "complete" ? 0 : 2;
}
