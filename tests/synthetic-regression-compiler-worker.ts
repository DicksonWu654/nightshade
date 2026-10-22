import { validateWithCompiler } from "./compiler-fixtures.js";
import type { CompilerVersion, ZkirVersion } from "../src/semantic/profile.js";

const chunks: Buffer[] = [];
let bytes = 0;
for await (const chunk of process.stdin) {
  const buffer = Buffer.from(chunk); bytes += buffer.length;
  if (bytes > 1024 * 1024) throw new Error("Compiler request exceeds 1 MiB");
  chunks.push(buffer);
}
const request = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
  compiler: string; source: string; searchPaths: string[]; zkirVersion: ZkirVersion; compilerVersion: CompilerVersion;
};
process.stdout.write(JSON.stringify(validateWithCompiler(request.compiler, request.source, request.searchPaths, 30000, request.zkirVersion, request.compilerVersion)));
