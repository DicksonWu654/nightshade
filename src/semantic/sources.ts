import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { ScopeAst, SourceFile, Span, fail } from "../model.js";
import { parseSource } from "../parser/index.js";

export class Sources {
  readonly files = new Map<string, SourceFile>();
  readonly inclusions: { source: string; site: Span }[] = [];
  cacheHits = 0;
  private expansions = 0;
  private bytes = 0;

  constructor(readonly searchPaths: string[]) {}

  resolve(name: string, site: Span, kind: "include" | "import"): string {
    return realpathSync(this.locate(name, site, kind, dirname(site.file)));
  }

  locate(name: string, site: Span, kind: "include" | "import", base: string): string {
    const paths = isAbsolute(name) ? [name] : [base, ...this.searchPaths].map(directory => directory ? `${directory}/${name}` : name);
    const found = paths.find(path => existsSync(path) && statSync(path).isFile());
    if (!found) fail(`unresolved-${kind}`, `Cannot resolve ${name}`, site);
    return found;
  }

  read(path: string): SourceFile {
    const canonical = realpathSync(path);
    const cached = this.files.get(canonical);
    if (cached) { this.cacheHits++; return cached; }
    const location = { file: canonical, start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
    if (this.files.size >= 512) fail("project-budget", "Project exceeds 512 physical sources", location);
    if (statSync(canonical).size > 8 * 1024 * 1024) fail("source-budget", "Source exceeds the 8 MiB per-file limit", location);
    this.bytes += statSync(canonical).size;
    if (this.bytes > 64 * 1024 * 1024) fail("project-budget", "Project exceeds 64 MiB of source text", location);
    const source = parseSource(canonical, readFileSync(canonical, "utf8"));
    this.files.set(canonical, source);
    return source;
  }

  expand(original: ScopeAst, chain: string[] = [], base = dirname(original.span.file)): ScopeAst {
    if (++this.expansions > 2048) fail("include-budget", "Source expansion exceeds 2048 scopes/includes", original.span);
    if (chain.length > 32) fail("include-depth", "Include nesting exceeds 32 files", original.span);
    const scope = structuredClone(original);
    const declarations: ScopeAst["declarations"] = [];
    const imports: ScopeAst["imports"] = [];
    let order = 0;
    const elements = [
      ...scope.declarations.map(value => ({ kind: "declaration" as const, value })),
      ...scope.imports.map(value => ({ kind: "import" as const, value })),
      ...(scope.includes ?? []).map(value => ({ kind: "include" as const, value })),
    ].sort((left, right) => left.value.span.start - right.value.span.start);
    for (const element of elements) {
      if (element.kind === "declaration") {
        element.value.order = order++;
        if (element.value.scope) element.value.scope = this.expand(element.value.scope, chain, base);
        declarations.push(element.value);
      } else if (element.kind === "import") {
        element.value.order = order++;
        imports.push(element.value);
      } else {
        const path = this.locate(`${element.value.path}.compact`, element.value.span, "include", base);
        const canonical = realpathSync(path);
        if (chain.includes(canonical) || canonical === original.span.file) fail("include-cycle", "Cyclic source inclusion", element.value.span);
        this.inclusions.push({ source: canonical, site: element.value.span });
        const included = this.expand(this.read(path).ast, [...chain, original.span.file], dirname(path));
        const nested = [...included.declarations, ...included.imports].sort((left, right) => left.order! - right.order!);
        for (const value of nested) value.order = order++;
        declarations.push(...included.declarations);
        imports.push(...included.imports);
        scope.exports.push(...included.exports);
        scope.pragmas.push(...included.pragmas);
      }
    }
    return { ...scope, declarations, imports, includes: [] };
  }
}
