import { checkCase } from "./check.js";
import { validateCase } from "./model.js";

const chunks: Buffer[] = [];
let size = 0;
for await (const chunk of process.stdin) {
  const buffer = Buffer.from(chunk);
  size += buffer.length;
  if (size > 1024 * 1024) throw new Error("Generated-test request exceeds 1 MiB");
  chunks.push(buffer);
}
const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
if (!request || typeof request !== "object" || !request.options || typeof request.options !== "object" || Array.isArray(request.options)) throw new Error("Invalid generated-test request");
if (Object.keys(request.options).some(key => !["compiler", "maxSteps", "maxPaths", "maxValues"].includes(key))) throw new Error("Unknown generated-test option");
if (request.options.compiler !== undefined && typeof request.options.compiler !== "string") throw new Error("Invalid compiler path");
validateCase(request.case);
process.stdout.write(JSON.stringify(checkCase(request.case, request.options)));
