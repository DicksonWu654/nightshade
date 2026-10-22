import { createHash } from "node:crypto";
import type { Span } from "../model.js";
import type { Program } from "../semantic/index.js";

/** Report-only names for opaque engine keys. Their digest recipes may contain
 * physical compiler identities and cannot be recovered from the digest. Keep
 * distinct raw keys distinct using their canonical companion recipes, without
 * emitting their path-dependent spelling or relying on encounter order. Never
 * use these names for analysis equality. */
export class ReportIdentityKeys {
  private readonly namespace: string;
  constructor(private readonly program: Program, entry: string, site: Span) {
    this.namespace = JSON.stringify([program.meteringIdentity(entry), program.meteringPath(site.file), site.start, site.end]);
  }

  private token(key: string): string {
    return createHash("sha256").update(JSON.stringify([this.namespace, this.program.reportIdentity(key)])).digest("hex");
  }

  /** Only call at owned operand/address/region slots, never on source text,
   * labels, messages or quotes. Constant payloads remain literal. */
  readonly key = (key: string): string => this.project(key, 0);

  private project(key: string, depth: number): string {
    if (/^(?:constant:|field:|key:(?!identity:|id:))/.test(key)) return key;
    if (depth > 256) return "opaque:" + this.token(key);
    const digest = /^((?:native|hash-derived|collection-derived|merkle-digest|collection-query|hash-choice|hash-relation(?::(?:true|false))?|expression|aggregate):[0-9a-f]{64})(?=$|::)/.exec(key);
    if (digest) return "opaque:" + this.token(digest[1]) + key.slice(digest[1].length);
    for (const wrapper of ["key:identity:", "key:id:", "id:", "identity:", "ledger:", "read:",
      "collection:", "list:", "merkle-root:", "merkle-query:", "!"])
      if (key.startsWith(wrapper)) return wrapper + this.project(key.slice(wrapper.length), depth + 1);
    if (/^[\[{"]/.test(key)) {
      try {
        // An owned JSON address may be followed by a revision/query suffix.
        let nesting = 0, quoted = false, escaped = false, end = key.length;
        for (let index = 0; index < key.length; index++) {
          const char = key[index];
          if (quoted) {
            if (escaped) escaped = false;
            else if (char === "\\") escaped = true;
            else if (char === '"') { quoted = false; if (!nesting) { end = index + 1; break; } }
          } else if (char === '"') quoted = true;
          else if (char === "[" || char === "{") nesting++;
          else if ((char === "]" || char === "}") && --nesting === 0) { end = index + 1; break; }
        }
        const visit = (value: unknown, nested = depth + 1): unknown => typeof value === "string" ? this.project(value, nested)
          : nested > 256 ? "opaque:" + this.token(JSON.stringify(value))
          : Array.isArray(value) ? value[0] === "constant" || value[1] === "constant" ? value : value.map(child => visit(child, nested + 1))
          : value && typeof value === "object" && "kind" in value && "value" in value ? value
          : value && typeof value === "object" ? Object.fromEntries(Object.entries(value).map(([name, child]) => [name, visit(child, nested + 1)])) : value;
        return JSON.stringify(visit(JSON.parse(key.slice(0, end)))) + this.project(key.slice(end), depth + 1);
      } catch { /* Unknown encodings retain their text. */ }
    }
    return key;
  }

  region(parts: readonly string[]): string[] {
    return parts.map(part => part.startsWith("key:identity:") ? "key:identity:" + this.key(part.slice(13))
      : part.startsWith("key:id:") ? "key:" + this.key(part.slice(4)) : part);
  }

  /** Report-only token for a whole opaque key identified by its owning layer.
   * Retains content-derived key distinctions; never use for analysis equality. */
  opaqueIdentity(raw: string): string { return this.token("identity:" + raw); }

  /** Some analysis domains are untagged hashes. Only their explicit descriptor
   * domain slots may call this; arbitrary hexadecimal source data stays data. */
  domain(raw: string): string { return this.token("domain:" + raw); }
}
