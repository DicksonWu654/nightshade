import type { ScanResult } from "../index.js";
import type { SourceFile, Span } from "../model.js";

/** Only owned parser comments can carry directives; string contents never do. */
export function applyInlineSuppressions(result: ScanResult, files: Iterable<SourceFile>, detectorIds: readonly string[]): void {
  const known = new Set(detectorIds);
  let directives = 0;
  const issue = (code: string, message: string, location: Span): void => {
    result.diagnostics.push({ code, message, location }); result.status = "incomplete";
  };
  for (const source of files) for (const comment of source.comments ?? []) {
    if (!comment.text.startsWith("//")) continue;
    const text = comment.text.slice(2).trim();
    if (!/^nightshade-disable(?:-|\b)/.test(text)) continue;
    if (++directives > 512) { issue("suppression-budget", "Inline suppressions exceed 512 directives", comment.span); return; }
    const match = /^nightshade-disable-(next-line|line)\s+([a-z0-9,-]+)\s+--\s+(.+)$/.exec(text);
    const ids = match?.[2].split(",");
    if (!match || match[3].trim().length < 8 || !ids?.length || ids.some(id => !known.has(id)) || new Set(ids).size !== ids.length) {
      issue("invalid-inline-suppression", "Use nightshade-disable-next-line or nightshade-disable-line, known comma-separated detector IDs, and -- followed by a reason of at least 8 characters", comment.span);
      continue;
    }
    const line = comment.span.line + (match[1] === "next-line" ? 1 : 0);
    for (const id of ids) {
      const findings = result.findings.filter(finding => finding.detectorId === id && finding.location.file === source.path && finding.location.line === line);
      if (!findings.length) {
        // A dependency can be used by another root, and an opt-in rule need not
        // be selected in this invocation. Neither makes its directive stale.
        if (source.path === (result.coverage.resolved[0] ?? result.coverage.attempted[0]) && result.coverage.detectors.includes(id))
          issue("unused-inline-suppression", `Inline suppression for ${id} matches no finding on line ${line}`, comment.span);
        continue;
      }
      for (const finding of findings) finding.suppression = { reason: match[3].trim(), kind: "inSource" };
    }
  }
}
