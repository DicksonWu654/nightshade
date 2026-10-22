import { readFileSync } from "node:fs";
import { detectorMetadata } from "../detectors/metadata.js";
import { detectors } from "../detectors/index.js";
import type { Severity } from "../detectors/types.js";

const packageInfo = JSON.parse(readFileSync(new URL("../../../package.json", import.meta.url), "utf8")) as { repository?: { url?: string } };
const candidate = packageInfo.repository?.url?.replace(/^git\+/, "").replace(/\.git$/, "");
/** Owner placeholders never become misleading external report links. */
export const informationUri = candidate && /^https:\/\//.test(candidate)
  && !/example\.(com|invalid)|TODO|\/OWNER\//i.test(candidate) ? candidate : undefined;
const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
// Rule-priority mapping for GitHub display; not a computed vulnerability CVSS score.
const securityPriority: Record<Severity, string> = { info: "0.0", low: "3.0", medium: "5.0", high: "8.0", critical: "9.5" };

export function sarifRule(detector: { id: string; description: string; defaultEnabled?: boolean }) {
  const builtIn = detectors.some(rule => rule.id === detector.id);
  const metadata = builtIn ? detectorMetadata(detector.id) : undefined;
  const documentation = builtIn
    ? readFileSync(new URL(`../../../docs/detectors/${detector.id}.md`, import.meta.url), "utf8")
    : detector.description;
  // A shared descriptor must not inflate lower-priority variants. Each result
  // still reports its own severity and SARIF level.
  const severity = metadata?.severityLevels.reduce((a, b) => rank[a] <= rank[b] ? a : b) ?? "info";
  return { id: detector.id, shortDescription: { text: detector.description },
    fullDescription: { text: documentation.replace(/^#.*\n/, "").trim() },
    help: { text: documentation, markdown: documentation },
    ...(informationUri && builtIn ? { helpUri: `${informationUri}/blob/v0.1.0/docs/detectors/${detector.id}.md` } : {}),
    defaultConfiguration: { enabled: detector.defaultEnabled !== false,
      level: severity === "info" ? "note" : rank[severity] >= rank.high ? "error" : "warning" },
    properties: { tags: ["security"], ...(metadata ? { ...metadata, "security-severity": securityPriority[severity] } : {}) } };
}
