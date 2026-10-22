/** Accounting representations are built alongside compiler identities. Physical
 * pathnames are atoms only at known path positions; arbitrary source text is
 * never searched for pathname substrings. Equality keys stay in the caller. */
export class IdentityAccounting {
  constructor(private readonly paths = new Map<string, string>(),
    private readonly identities = new Map<string, string>(),
    private readonly companions?: Map<string, string>) {}

  /** Report companions share the compilation's structural pathname grammar,
   * but never change accounting, equality or cache keys. */
  reporting(): IdentityAccounting { return new IdentityAccounting(this.paths, this.identities, new Map()); }

  readonly remember = (raw: string, companion: string): string => {
    this.companions!.set(raw, companion);
    return raw;
  };

  path(path: string): string {
    let token = this.paths.get(path);
    if (!token) this.paths.set(path, token = `@file${String(this.paths.size).padStart(8, "0")}`);
    return token;
  }

  register(identity: string, accounting: string): string {
    this.identities.set(identity, accounting);
    // Prefixes are semantic identities, never physical pathnames. A pathname
    // can itself spell another module's entire symbol ID (e.g. a symlink).
    return identity;
  }

  readonly text = (identity: string): string => this.measure(identity, 0);

  private measure(identity: string, depth: number): string {
    if (depth > 256) return identity;
    const known = this.companions?.get(identity) ?? this.identities.get(identity);
    if (known !== undefined) return known;
    // Byte projections own a complete digest identity before their suffix.
    // Look up that exact atom rather than searching companion substrings.
    if (this.companions) {
      const byte = /^(.*)(::byte:[0-9]+)$/.exec(identity);
      const atom = byte && this.companions.get(byte[1]);
      if (atom !== undefined && atom !== null) return atom + byte![2];
    }
    // Constant payloads and struct field labels are source data, not identities.
    if (/^(?:constant:|field:|key:(?!identity:))/.test(identity)) return identity;
    // Inspect relation tags before the unary ! wrapper: !=: owns a complete
    // operand slot and must not be split into ! followed by opaque =: text.
    const relation = /^(?:==:|!=:|scalar-relation:(?:true|false):|aggregate-relation:|ordered:[^<>]*(?:<[^>]*>)?:(?:<=|>=|<|>):)/.exec(identity);
    if (relation) return relation[0] + this.measure(identity.slice(relation[0].length), depth + 1);
    for (const prefix of ["!", "key:identity:", "identity:", "id:", "parameter:", "read:",
      "ledger:coin-index:", "ledger:kernel-context:", "ledger:kernel-predicate:",
      "ledger:", "merkle-root:", "merkle-query:", "collection:", "list:", "fields:", "items:"]) {
      if (identity.startsWith(prefix)) return prefix + this.measure(identity.slice(prefix.length), depth + 1);
    }
    // JSON containers are part of the owned identity grammar. Parse quoted
    // strings before inspecting their identity positions, preserving escaping
    // on re-encoding (including nested JSON encodings).
    if (identity[0] === '[' || identity[0] === '"' || identity[0] === '{') {
      const end = this.jsonEnd(identity);
      if (end !== undefined) {
        try {
          const visit = (value: unknown): unknown => typeof value === "string" ? this.measure(value, depth + 1)
            : Array.isArray(value) ? value[0] === "constant" ? value : value.map(visit)
            : value && typeof value === "object" && "kind" in value && "value" in value ? value
            : value && typeof value === "object" ? Object.fromEntries(Object.entries(value).map(([key, child]) => [key, visit(child)])) : value;
          return JSON.stringify(visit(JSON.parse(identity.slice(0, end)))) + this.measure(identity.slice(end), depth + 1);
        } catch { /* An unknown encoding remains fully charged. */ }
      }
    }
    // Only complete registered semantic prefixes may precede an owned suffix.
    // Their accounting retains every source identifier character, even when it
    // happens to spell a filename. No physical-path prefix matching occurs.
    let prefix = "";
    for (const key of this.identities.keys()) if (key.length > prefix.length && identity.startsWith(key)
      && [":", "<"].includes(identity[key.length])) prefix = key;
    if (prefix) return this.identities.get(prefix)! + this.measure(identity.slice(prefix.length), depth + 1);
    const path = this.paths.get(identity);
    if (path !== undefined && /[/\\]/.test(identity)) return path;
    // Source spans are registered by their constructors. Type argument and
    // identity suffix positions may contain further canonical identities.
    if (identity[0] === ":") {
      const match = /^(:+(?:local|loop|pending|pattern|lambda|import|parameter):)/.exec(identity);
      if (match) return match[0] + this.measure(identity.slice(match[0].length), depth + 1);
      // Region revisions/query tags and kernel identities delimit another
      // operand or JSON key. Only these owned suffix positions are inspected.
      const operand = /^:(?:[0-9]+:(?:[A-Za-z]+:)?)?(?=id:|identity:|constant:|\[|"|\{)/.exec(identity);
      if (operand) return operand[0] + this.measure(identity.slice(operand[0].length), depth + 1);
      return identity;
    }
    const type = this.measureTypeArguments(identity, depth);
    if (type !== undefined) return type;
    return identity;
  }

  /** Type constructors and tuples are the only unregistered strings whose
   * argument slots may contain canonical symbol identities. Keep their exact
   * separators and all non-path source characters while visiting each slot. */
  private measureTypeArguments(identity: string, depth: number): string | undefined {
    const tuple = identity[0] === "[" && identity.endsWith("]");
    const suffix = identity[0] === "<" && identity.endsWith(">");
    const open = tuple || suffix ? 0 : identity.indexOf("<");
    if (open < 0 || !identity.endsWith(tuple ? "]" : ">")) return undefined;
    const head = identity.slice(0, open);
    if (head && !/^[A-Za-z_$][\w$-]*$/.test(head)
      && !/^standard-type::[A-Za-z_$][\w$-]*$/.test(head)
      && !this.identities.has(head)) return undefined;
    const openings = "<[({", closings = ">])}";
    const stack: string[] = [];
    let quoted = false, escaped = false;
    // A quoted type argument (Opaque's payload) is source text, unlike a JSON
    // identity wrapper. Preserve it literally, including any pathname spelling.
    const argument = (text: string): string => text.startsWith('"') ? text : this.measure(text, depth + 1);
    let start = open + 1, result = this.measure(head, depth + 1) + identity[open];
    for (let index = start; index < identity.length - 1; index++) {
      const char = identity[index];
      if (quoted) {
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === '"') quoted = false;
        continue;
      }
      if (char === '"') { quoted = true; continue; }
      if (openings.includes(char)) stack.push(char);
      else if (closings.includes(char)) {
        if (stack.pop() !== openings[closings.indexOf(char)]) return undefined;
      } else if (char === "," && stack.length === 0) {
        result += argument(identity.slice(start, index)) + ",";
        start = index + 1;
      }
    }
    if (stack.length || quoted) return undefined;
    return result + argument(identity.slice(start, -1)) + identity.at(-1);
  }

  private jsonEnd(text: string): number | undefined {
    let nesting = 0, quoted = false, escaped = false;
    for (let index = 0; index < text.length; index++) {
      const char = text[index];
      if (quoted) {
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === '"') { quoted = false; if (!nesting) return index + 1; }
      } else if (char === '"') quoted = true;
      else if (char === "[" || char === "{") nesting++;
      else if ((char === "]" || char === "}") && --nesting === 0) return index + 1;
    }
    return undefined;
  }
}
