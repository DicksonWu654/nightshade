import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSource } from "../parser/index.js";
import { AnalysisError, type Diagnostic } from "../model.js";
import { excludedRoot } from "../reporting/selection.js";
import { runNodeModule, WorkerFailure, type ExecutionLimits } from "../runtime/process.js";

export interface ProjectDiscovery {
  status: "complete" | "incomplete";
  files: string[];
  libraries: string[];
  excluded: string[];
  searchPaths: Record<string, string[]>;
  diagnostics: Diagnostic[];
}
const skipped = new Set(["node_modules", "dist", "managed", ".git", ".cache", "build", "prebuilds"]);
const empty = (): ProjectDiscovery => ({ status: "incomplete", files: [], libraries: [], excluded: [], searchPaths: {}, diagnostics: [] });
const location = (path: string) => ({ file: resolve(path), start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 });

/** Source-only discovery: no package scripts, compiler config or project code runs.
 * Unparseable/uncertain inputs remain scan candidates, so first failures stay visible. */
export function discoverProject(path: string, exclusions: readonly string[] = []): ProjectDiscovery {
  const root = resolve(path), result = empty();
  let visited = 0, sources = 0, bytes = 0;
  const directories = [root];
  try {
    while (directories.length) {
      const directory = directories.pop()!;
      for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
        if (++visited > 100000) throw new AnalysisError({ code: "discovery-budget", message: "Project discovery exceeds 100000 filesystem entries", location: location(directory) });
        if (entry.isSymbolicLink() || skipped.has(entry.name)) continue;
        const file = resolve(directory, entry.name);
        if (entry.isDirectory()) { directories.push(file); continue; }
        if (!entry.isFile() || !entry.name.endsWith(".compact")) continue;
        if (++sources > 4096) throw new AnalysisError({ code: "discovery-budget", message: "Project discovery exceeds 4096 Compact sources", location: location(file) });
        if (excludedRoot(file, root, exclusions)) { result.excluded.push(file); continue; }
        const size = statSync(file).size;
        // The actual scan diagnoses oversized sources without discovery reading them.
        if (size <= 8 * 1024 * 1024) {
          bytes += size;
          if (bytes > 64 * 1024 * 1024) throw new AnalysisError({ code: "discovery-budget", message: "Project discovery exceeds 64 MiB of source text", location: location(file) });
          try {
            const ast = parseSource(file, readFileSync(file, "utf8")).ast;
            if (ast.declarations.length === 1 && ast.declarations[0].kind === "module" && !ast.exports.length && !ast.includes?.length) {
              result.libraries.push(file); continue;
            }
          } catch (error) { if (!(error instanceof AnalysisError)) throw error; }
        }
        result.files.push(file);
        const searchPaths: string[] = [];
        for (let parent = dirname(file);; parent = dirname(parent)) {
          const dependency = resolve(parent, "node_modules");
          if (existsSync(dependency) && statSync(dependency).isDirectory()) searchPaths.push(dependency);
          if (parent === root || dirname(parent) === parent) break;
        }
        // Explicit COMPACT_PATH/config/CLI paths take priority in the caller.
        result.searchPaths[file] = [...searchPaths, root];
      }
    }
    result.files.sort(); result.libraries.sort(); result.excluded.sort(); result.status = "complete";
  } catch (error) {
    result.diagnostics.push(error instanceof AnalysisError ? error.diagnostic : { code: "discovery-error", message: error instanceof Error ? error.message : String(error), location: location(root) });
  }
  return result;
}

export async function discoverProjectIsolated(path: string, exclusions: readonly string[], limits: ExecutionLimits = {}): Promise<ProjectDiscovery> {
  try {
    const { stdout } = await runNodeModule(fileURLToPath(new URL("../runtime/worker.js", import.meta.url)), { kind: "discover", path: resolve(path), options: {}, exclusions }, limits);
    const result = JSON.parse(stdout) as ProjectDiscovery;
    if (!["complete", "incomplete"].includes(result.status) || !Array.isArray(result.files) || !Array.isArray(result.libraries) || !Array.isArray(result.excluded)
      || !result.searchPaths || !Array.isArray(result.diagnostics) || result.status === "complete" && result.diagnostics.length)
      throw new WorkerFailure("worker-protocol", "Discovery worker returned an invalid report");
    return result;
  } catch (error) {
    const result = empty();
    result.diagnostics.push({ code: error instanceof WorkerFailure ? error.code : "discovery-worker-error", message: error instanceof Error ? error.message : String(error), location: location(path) });
    return result;
  }
}
