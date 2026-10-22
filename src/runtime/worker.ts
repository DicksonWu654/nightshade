import { scanFile, ScanOptions } from "../index.js";
import { auditFile, type AuditorPrinter } from "../reporting/auditor.js";
import { discoverProject } from "../semantic/project.js";
import { reviewFile } from "../reporting/review.js";

const chunks: Buffer[] = [];
let length = 0;
for await (const chunk of process.stdin) {
  const buffer = Buffer.from(chunk);
  length += buffer.length;
  if (length > 1024 * 1024) throw new Error("Worker request exceeds 1 MiB");
  chunks.push(buffer);
}
const request = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { path: string; options: ScanOptions; kind?: "audit" | "discover" | "review"; printer?: AuditorPrinter; exclusions?: string[] };
if (typeof request.path !== "string" || !request.options || typeof request.options !== "object") throw new Error("Invalid scan request");
process.stdout.write(JSON.stringify(request.kind === "review" ? reviewFile(request.path, request.options) : request.kind === "discover" ? discoverProject(request.path, request.exclusions) : request.kind === "audit" ? auditFile(request.path, request.printer!, request.options) : scanFile(request.path, request.options)));
