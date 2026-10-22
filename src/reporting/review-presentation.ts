import { existsSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import type { Diagnostic, Span } from "../model.js";
import type { ReviewBrief, ReviewDiagnostic } from "./review.js";

/** Group repeated coverage notices without dropping their source locations. */
export function compactReviewDiagnostics(diagnostics: readonly Diagnostic[]): ReviewDiagnostic[] {
  const groups = new Map<string, ReviewDiagnostic>();
  for (const diagnostic of diagnostics as readonly ReviewDiagnostic[]) {
    const key = JSON.stringify([diagnostic.code, diagnostic.message]);
    let group = groups.get(key);
    if (!group) {
      group = { ...structuredClone(diagnostic), count: 0, locations: [] };
      groups.set(key, group);
    }
    group.count! += diagnostic.count ?? 1;
    const seen = new Set(group.locations!.map(location => JSON.stringify(location)));
    for (const location of diagnostic.locations?.length ? diagnostic.locations : [diagnostic.location]) {
      const id = JSON.stringify(location);
      if (!seen.has(id)) { group.locations!.push({ ...location }); seen.add(id); }
    }
  }
  return [...groups.values()];
}

export function repositoryBase(root: string): string {
  let cursor = resolve(root);
  try { if (!statSync(cursor).isDirectory()) cursor = dirname(cursor); } catch { cursor = dirname(cursor); }
  const fallback = cursor;
  for (;;) {
    if (existsSync(resolve(cursor, ".git"))) return cursor;
    const parent = dirname(cursor);
    if (parent === cursor) return fallback;
    cursor = parent;
  }
}

export function repositoryRelativePath(path: string, root: string): string {
  const base = repositoryBase(root);
  return relative(base, resolve(path)).split(sep).join("/") || ".";
}

/** Make a portable copy. Source excerpts and byte offsets remain unchanged. */
export function relativeReviewBrief(report: ReviewBrief, base?: string): ReviewBrief {
  const copy = structuredClone(report);
  copy.coverage.diagnostics = compactReviewDiagnostics(copy.coverage.diagnostics);
  if (report.pathFormat === "repository-relative") return copy;
  const directory = resolve(base ?? repositoryBase(report.root));
  const paths = new Set<string>();
  const collect = (value: unknown, key = ""): void => {
    if (typeof value === "string" && ["file", "root", "artifactPath"].includes(key) && isAbsolute(value)) paths.add(value);
    else if (Array.isArray(value)) value.forEach(item => collect(item));
    else if (value && typeof value === "object") for (const [field, item] of Object.entries(value)) collect(item, field);
  };
  collect(copy);
  const replacements = [...paths].sort((a, b) => b.length - a.length).map(path => [path, relative(directory, path).split(sep).join("/") || "."] as const);
  const convert = (value: unknown, key = ""): unknown => {
    if (typeof value === "string") {
      // These fields contain literal source, not identity or presentation paths.
      if (key === "expression" || key === "value") return value;
      let text = value;
      for (const [path, portable] of replacements) text = text.split(path).join(portable);
      if (key === "message") text = text.replace(/(?<![\w:./])\/(?:[\w.-]+\/)+[\w.-]+/g, path => relative(directory, path).split(sep).join("/"));
      return text.split(directory + sep).join("");
    }
    if (Array.isArray(value)) return value.map(item => convert(item));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([field, item]) => [field, convert(item, field)]));
    return value;
  };
  const portable = convert(copy) as ReviewBrief;
  portable.pathFormat = "repository-relative";
  return portable;
}

const md = (value: unknown) => String(value).replace(/[|<>`]/g, c => `&#${c.charCodeAt(0)};`).replace(/\r?\n/g, " ");
const pos = (span: Span) => `${span.file}:${span.line}:${span.column}`;
export function reviewMarkdown(input: ReviewBrief): string {
  const report = relativeReviewBrief(input);
  const names = new Map(report.stateMachine.fields.map(field => [field.id, field.name]));
  const circuitNames = new Map(report.circuits.map(row => [row.id, row.name]));
  const diagnostics = report.coverage.diagnostics as ReviewDiagnostic[];
  const occurrences = diagnostics.reduce((count, diagnostic) => count + (diagnostic.count ?? 1), 0);
  const lines = [`# Nightshade review: ${md(report.root)}`, "", `Status: **${report.status}**; profile: ${md(report.semanticProfile ?? "unavailable")}`,
    `Circuits: ${report.circuits.length}; audit findings: ${report.findings.length}; review questions: ${report.questions.length} (${report.questionSummary.visible} shown; ${report.questionSummary.collapsed} collapsed).`,
    `Coverage diagnostics: ${occurrences} occurrences in ${diagnostics.length} groups.`, "", "Top review questions:"];
  for (const question of report.questions.slice(0, 5)) {
    const text = question.question.length > 160 ? question.question.slice(0, 157) + "…" : question.question;
    const circuits = question.circuitIds.slice(0, 3).map(id => md(circuitNames.get(id) ?? id)).join(", ");
    lines.push(`${question.rank}. **${question.priority}** ${md(text)} (${circuits || md(question.kind)}${question.circuitIds.length > 3 ? ", …" : ""}; score ${question.score})`);
  }
  if (!report.questions.length) lines.push("No fact-triggered questions were produced; coverage status still applies.");
  lines.push("", report.scope, "", "## Prioritized review questions", "");
  const questionLine = (question: ReviewBrief["questions"][number]) => `- **#${question.rank} / ${question.priority} / ${md(question.kind)}** [${md(question.id)}] (score ${question.score}): ${md(question.question)} Basis: ${md(question.basis)} Signals: ${question.signals.map(md).join(", ")}. Circuits: ${question.circuitIds.map(id => md(circuitNames.get(id) ?? id)).join(", ")}. Sources: ${question.locations.map(location => md(pos(location))).join(", ")}.`;
  const visible = Math.min(report.questionSummary.visible, 10);
  lines.push(...report.questions.slice(0, visible).map(questionLine));
  if (report.questions.length > visible) lines.push("", `<details><summary>${report.questions.length - visible} more questions</summary>`, "", ...report.questions.slice(visible).map(questionLine), "", "</details>");
  lines.push("", "## Coverage", "", `Audit scan: ${report.coverage.scan?.baselineStatus ?? "unavailable"}; inventory: ${report.coverage.inventory}; histories: ${report.coverage.histories}.`);
  for (const diagnostic of diagnostics) {
    const locations = diagnostic.locations ?? [diagnostic.location];
    lines.push(`- ${md(diagnostic.code)} × ${diagnostic.count ?? 1}: ${md(diagnostic.message)} (${locations.slice(0, 3).map(location => md(pos(location))).join("; ")}${locations.length > 3 ? `; ${locations.length - 3} more locations in JSON` : ""})`);
  }
  lines.push("", "## Circuit table", "", "| Circuit / source | Caller inputs | Witnesses | Authorization evidence | Ledger reads | Ledger writes | Disclosure / time / value sites |", "|---|---|---|---|---|---|---|");
  for (const row of report.circuits) lines.push(`| ${md(row.name)} (${md(pos(row.location))}) | ${row.arguments.map(argument => md(`${argument.name}: ${argument.type} (${argument.control})`)).join("; ")} | ${row.witnesses.map(witness => md(witness.name)).join(", ")} | ${md(row.authorization.strength)}; ${row.historyStatus}, ${row.histories} histories | ${row.reads.map(id => md(names.get(id) ?? id)).join(", ")} | ${row.writes.map(id => md(names.get(id) ?? id)).join(", ")} | ${row.disclosures.length} / ${row.timeUsage.length} / ${row.valueMovement.length} |`);
  lines.push("", "## Cross-circuit state sketch", "", report.stateMachine.scope, "", "| Field | May-readers | May-writers | Marker | Assignments |", "|---|---|---|---|---|");
  for (const field of report.stateMachine.fields) lines.push(`| ${md(field.name)} | ${field.readers.map(id => md(circuitNames.get(id) ?? id)).join(", ")} | ${field.writers.map(id => md(circuitNames.get(id) ?? id)).join(", ")} | ${md(field.marker)} | ${field.assignments.map(write => md(write.value)).join("; ")} |`);
  for (const row of report.circuits) {
    lines.push("", `## Circuit: ${md(row.name)}`, "", `Source: ${md(pos(row.location))}. ${md(row.authorization.scope)}`);
    lines.push("", "### Authorization histories", "", `Evidence: ${md(row.authorization.strength)}. History coverage: ${row.historyStatus}.`, "",
      ...row.authorization.histories.map(history => `- History ${history.history}: observed private-preimage sources: ${history.privatePreimages.map(md).join(", ") || "none"}; constraints: ${history.constraints.map(constraint => `${md(pos(constraint.location))} (truth=${constraint.truth}, writes before=${constraint.writesBefore}, operations before=${constraint.operationsBefore})`).join("; ") || "none"}.`));
    for (const [title, sites] of [["Checks", row.assertions], ["Disclosures", row.disclosures], ["Time usage", row.timeUsage], ["Value movement", row.valueMovement]] as const) {
      lines.push("", `### ${title}`, "", ...sites.map(site => `- ${md(site.expression)} (${md(pos(site.location))})`));
    }
    lines.push("", "### Audit-default findings", "", ...row.findings.map(finding => `- ${md(finding.detectorId)} (${finding.severity}): ${md(finding.message)} (${md(pos(finding.location))})`));
    lines.push("", "### Observed public sinks", "", ...row.publicSinks.map(sink => `- History ${sink.history}: ${md(sink.kind)} ${md(sink.name)} (${md(pos(sink.location))}); private sources: ${sink.privateSources.map(md).join(", ")}.`));
  }
  lines.push("", "## All audit-default findings", "", ...report.findings.map(finding => `- ${md(finding.detectorId)} (${finding.severity}): ${md(finding.message)} (${md(pos(finding.location))})`), "", "## Explorer", "", report.explorer.reason, "", "## Limitations", "", ...report.limitations.map(limitation => `- ${limitation}`), "");
  if (report.explorer.replays.length) lines.push("## Supplied replay references", "", ...report.explorer.replays.map(replay => `- ${md(replay.circuit)}: ${md(replay.status)}, transition=${replay.transition}; replay ${md(replay.id ?? "unavailable")}`), "");
  return lines.join("\n");
}
