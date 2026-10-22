import { fail, type Expr, type Parameter, type Pattern, type ScopeAst, type Span, type Statement } from "../model.js";
import { naturalValue, numericTypeError, typeArguments, type TypeTerm } from "./types.js";

export const SEMANTIC_PROFILE = "compact-0.34.0-zkir2";
export const ZKIR3_PROFILE = "compact-0.34.0-zkir3";
export type ZkirVersion = 2 | 3;
export const COMPILER_PROFILES = {
  "0.28.0": { languageVersion: "0.20.0", runtimeVersion: "0.14.0", sourceCommit: "dce2f11d28460d6379e45e770952a2fbbe1d2ecd", library: "standard-library-0.28", legacy: true },
  "0.29.0": { languageVersion: "0.21.0", runtimeVersion: "0.14.0", sourceCommit: "f17a98c1c1557c4a1e4bf391e0018543aa358bdd", library: "standard-library-0.29", legacy: true },
  "0.30.0": { languageVersion: "0.22.0", runtimeVersion: "0.15.0", sourceCommit: "705c2274b5f7bf6c309f9811143b1832281f7876", library: "standard-library-0.30", legacy: true },
  "0.31.1": { languageVersion: "0.23.0", runtimeVersion: "0.16.0", sourceCommit: "0da5b0452eb0c1053d42418bf34b12cc29c7d63e", library: "standard-library-0.30", legacy: true, qualified: true },
  "0.33.0-rc.2": { languageVersion: "0.25.0", runtimeVersion: "0.18.0-rc.1", sourceCommit: "566ef0eb66c3442e189b5e2d7ae9e1b99426db26", library: "standard-library-0.33-rc.2", legacy: false },
  "0.34.0": { languageVersion: "0.26.0", runtimeVersion: "0.19.0", sourceCommit: "1f671fc27818df2b2676b3a97f85b2b821756243", library: "standard-library", legacy: false, qualified: true },
  "0.35.0-rc.1": { languageVersion: "0.27.0", runtimeVersion: "0.20.0", sourceCommit: "debb05f9414b9d1e176741c2be289bb32233f0fc", library: "standard-library-0.35-rc.1", legacy: false },
  "0.35.0": { languageVersion: "0.27.0", runtimeVersion: "0.20.0", sourceCommit: "debb05f9414b9d1e176741c2be289bb32233f0fc", library: "standard-library-0.35-rc.1", legacy: false },
} as const;
export type CompilerVersion = keyof typeof COMPILER_PROFILES;
export type SemanticProfile = `compact-${CompilerVersion}-zkir2` | typeof ZKIR3_PROFILE;
export const semanticProfile = (version: ZkirVersion = 2, compiler: CompilerVersion = "0.34.0"): SemanticProfile =>
  version === 3 ? ZKIR3_PROFILE : `compact-${compiler}-zkir2`;
export const validCompilerVersion = (value: unknown): value is CompilerVersion => typeof value === "string" && Object.hasOwn(COMPILER_PROFILES, value);
export const validSemanticProfile = (value: unknown): value is SemanticProfile => value === ZKIR3_PROFILE || Object.keys(COMPILER_PROFILES).some(version => value === `compact-${version}-zkir2`);

export function validZkirVersion(version: unknown): version is ZkirVersion {
  return version === 2 || version === 3;
}

/** Version predicates follow the pinned compiler/version.ss relation, including
 * wildcard omitted components. Strict comparisons against a wildcard compare
 * the actual component to zero (and accept either direction when nonzero). */
function versionPredicate(text: string, version: string, location: Span): boolean {
  if (text.length > 4096) fail("profile-selection-budget", "Version predicate exceeds 4096 characters", location);
  const tokens = text.match(/>=|<=|&&|\|\||[()<>!]|\d+(?:\.\d+){0,2}|\S/g) ?? [];
  if (tokens.length > 128) fail("profile-selection-budget", "Version predicate exceeds 128 tokens", location);
  let at = 0;
  const tuple = (value: string): (number | undefined)[] => {
    if (!/^\d+(?:\.\d+){0,2}$/.test(value)) fail("unsupported-version-predicate", `Unrecognized version predicate: ${text}`, location);
    const result: (number | undefined)[] = value.split(".").map(Number);
    if (result.some(part => !Number.isSafeInteger(part))) fail("unsupported-version-predicate", "Version component is outside the supported range", location);
    while (result.length < 3) result.push(undefined);
    return result;
  };
  const actual = version.replace(/-.*$/, "").split(".").map(Number);
  const atom = (depth: number): boolean => {
    if (depth > 32) fail("profile-selection-budget", "Version predicate nesting exceeds 32", location);
    if (tokens[at] === "(") { at++; const result = or(depth + 1); if (tokens[at++] !== ")") fail("unsupported-version-predicate", "Unclosed version predicate", location); return result; }
    const operator = [">=", "<=", ">", "<", "!"].includes(tokens[at]) ? tokens[at++] : "equal";
    const expected = tuple(tokens[at++] ?? "");
    const equal = (index: number) => expected[index] === undefined || actual[index] === expected[index];
    if (operator === "equal" || operator === "!") {
      const result = actual.every((_, index) => equal(index));
      return operator === "!" ? !result : result;
    }
    const index = !equal(0) ? 0 : !equal(1) ? 1 : 2;
    const target = expected[index], value = actual[index];
    if (target === undefined) return operator.length === 2 || value !== 0;
    return operator === ">=" ? value >= target : operator === "<=" ? value <= target : operator === ">" ? value > target : value < target;
  };
  const and = (depth: number): boolean => { let value = atom(depth); while (tokens[at] === "&&") { at++; const next = atom(depth); value = value && next; } return value; };
  const or = (depth: number): boolean => { let value = and(depth); while (tokens[at] === "||") { at++; const next = and(depth); value = value || next; } return value; };
  const result = or(0);
  if (at !== tokens.length) fail("unsupported-version-predicate", `Unrecognized version predicate: ${text}`, location);
  return result;
}

export function selectCompilerVersion(pragmas: readonly string[], location: Span, requested?: CompilerVersion, zkir: ZkirVersion = 2): CompilerVersion {
  if (requested !== undefined && !validCompilerVersion(requested)) fail("unsupported-compiler-version", `Unsupported compiler version ${String(requested)}; supported: ${Object.keys(COMPILER_PROFILES).join(", ")}`, location);
  const predicates = pragmas.map(pragma => {
    const text = pragma.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
    const match = /^\s*pragma\s+(language_version|compiler_version)\s+([\s\S]*?)\s*;\s*$/.exec(text);
    if (!match) fail("unsupported-pragma", `Unsupported pragma: ${text}`, location);
    return { kind: match[1], text: match[2] };
  });
  // Preserve the 0.34.0 default whenever it satisfies the source's pragmas.
  // Otherwise prefer the newest compatible stable profile; prereleases are fallbacks only when no stable profile matches.
  const versions: CompilerVersion[] = requested ? [requested] : ["0.34.0", "0.35.0", "0.31.1", "0.30.0", "0.29.0", "0.28.0", "0.35.0-rc.1", "0.33.0-rc.2"];
  const matching = versions.filter(version => predicates.map(predicate => versionPredicate(predicate.text,
    predicate.kind === "compiler_version" ? version : COMPILER_PROFILES[version].languageVersion, location)).every(Boolean));
  if (!matching.length) fail(predicates.some(predicate => predicate.kind === "compiler_version") ? "unsupported-compiler-version" : "unsupported-language-version",
    `No supported compiler profile satisfies ${predicates.map(predicate => `${predicate.kind} ${predicate.text}`).join(" and ")}${requested ? ` with compiler ${requested}` : ""}`, location);
  const version = matching[0];
  if (zkir === 3 && version !== "0.34.0") fail("unsupported-compiler-profile", "ZKIR3 is qualified only with compiler 0.34.0", location);
  return version;
}

// RC2 still declares JubjubPoint as nominal Opaque, but already uses scalar
// operands, explicit Uint-to-Field casts and native events. It is not legacy.
// Compilers 0.28.0/0.29.0 predate Opaque<'JubjubPoint'> (see nativePointProfile).
export const opaqueJubjubProfile = (version: CompilerVersion): boolean =>
  COMPILER_PROFILES[version].legacy && !nativePointProfile(version) || version === "0.33.0-rc.2";

/** Compilers 0.28.0 (language 0.20.0, tag dce2f11) and 0.29.0 (language 0.21.0,
 * tag f17a98c) export `new type NativePoint = SimplePoint` (a two-Field struct)
 * with Compact accessors instead of JubjubPoint. Their curve natives return that
 * struct-backed point; they are not modeled and diagnose instead of reusing the
 * opaque JubjubPoint transfers. */
export const nativePointProfile = (version: CompilerVersion): boolean => version === "0.29.0" || version === "0.28.0";
const NATIVE_POINT_CURVE = ["ecAdd", "ecMul", "ecMulGenerator", "hashToCurve"] as const;
export const UNMODELED_PROFILE_NATIVES: Partial<Record<CompilerVersion, readonly string[]>> = {
  "0.28.0": NATIVE_POINT_CURVE, "0.29.0": NATIVE_POINT_CURVE,
};
/** Natives that do not exist in a profile's compiler (beyond the legacy keccak256/ecNeg). */
export const ABSENT_PROFILE_NATIVES: Partial<Record<CompilerVersion, readonly string[]>> = {
  "0.28.0": ["jubjubPointX", "jubjubPointY", "constructJubjubPoint"], "0.29.0": ["jubjubPointX", "jubjubPointY", "constructJubjubPoint"],
};
/** Before 0.29.105 the compiler first tried a relative include/import path against
 * the invocation directory, then the including file's directory, then COMPACT_PATH.
 * The analyzer has no invocation directory, so it rejects include/import file lookups. */
export const workingDirectorySearchProfile = (version: CompilerVersion): boolean => version === "0.29.0" || version === "0.28.0";
/** Compilers through 0.30.0 lower `for (const i of a..b)` with literal bounds and a 1000-iteration limit. */
const literalLoopBoundProfile = (version: CompilerVersion): boolean => version === "0.30.0" || version === "0.29.0" || version === "0.28.0";
/** From 0.28.107 the library's self-addressed mint/send helpers claim their own receipt. */
export const autoReceiveProfile = (version: CompilerVersion): boolean => version !== "0.28.0";

/** RC2's scalar is a reserved language type, not a shadowable imported name.
 * Check owned binding nodes before unused generic bodies can be discarded. */
export function checkRc2Identifiers(scope: ScopeAst): void {
  let work = 0;
  const charge = (location: Span) => { if (++work > 200000) fail("profile-syntax-budget", "Compiler-profile identifier allowance exhausted", location); };
  const name = (value: string | undefined, location: Span) => {
    if (value && ["JubjubScalar", "Secp256k1Base", "Secp256k1Scalar"].includes(value)) fail("reserved-identifier", `${value} is a reserved primitive type in compiler 0.33.0-rc.2`, location);
  };
  // Explicit pre-order traversal (children pushed in reverse) in the former
  // recursive order: the same first rejection without a nesting-depth limit.
  type Item = { expression: Expr } | { statement: Statement } | { pattern: Pattern } | { parameter: Parameter };
  const walk = (roots: readonly (Item | undefined)[]): void => {
    const pending: Item[] = [];
    const push = (items: readonly (Item | undefined)[]) => { for (let index = items.length - 1; index >= 0; index--) if (items[index]) pending.push(items[index]!); };
    push(roots);
    while (pending.length) {
      const item = pending.pop()!;
      if ("parameter" in item) { name(item.parameter.name, item.parameter.span); push([item.parameter.pattern && { pattern: item.parameter.pattern }]); }
      else if ("pattern" in item) {
        const node = item.pattern;
        charge(node.span); name(node.name, node.span); node.fields?.forEach(field => name(field, node.span));
        push(node.children.map(child => ({ pattern: child })));
      } else if ("expression" in item) {
        const node = item.expression;
        charge(node.span); name(node.name, node.span); node.fields?.forEach(field => name(field, node.span));
        push([...(node.parameters ?? []).map(parameter => ({ parameter })), ...node.args.map(arg => ({ expression: arg })), node.body && { statement: node.body }]);
      } else {
        const node = item.statement;
        charge(node.span);
        if (node.kind === "block" || node.kind === "bindings") push(node.body.map(child => ({ statement: child })));
        else if (node.kind === "if") push([{ expression: node.condition }, { statement: node.then }, node.otherwise && { statement: node.otherwise }]);
        else if (node.kind === "for") { name(node.name, node.span); push([node.sequence && { expression: node.sequence }, { statement: node.body }]); }
        else {
          if (node.kind === "bind") name(node.name, node.span);
          push([node.kind === "bind" && node.pattern ? { pattern: node.pattern } : undefined, { expression: node.expr }]);
        }
      }
    }
  };
  for (const item of scope.imports) {
    if (!item.external) name(item.name, item.span); name(item.prefix, item.span);
    item.selections?.forEach(selection => { name(selection.name, item.span); name(selection.alias, item.span); });
  }
  for (const declaration of scope.declarations) {
    charge(declaration.span); name(declaration.name, declaration.span); walk(declaration.parameters.map(parameter => ({ parameter })));
    typeArguments(declaration.generics).forEach(parameter => name(parameter.replace(/^#\s*/, ""), declaration.span));
    declaration.variants?.forEach(variant => name(variant, declaration.span));
    walk([declaration.body && { statement: declaration.body }]);
  }
}

/** Shared concrete/schema legality; erased parameters are resolved by the caller. */
export function profileNumericTypeError(term: TypeTerm, version: CompilerVersion): string | undefined {
  return numericTypeError(term) ?? ((COMPILER_PROFILES[version].legacy || version === "0.33.0-rc.2") && term.name === "Uint" && term.args[0]?.name === "0"
    ? `Compiler ${version} requires Uint bit width 1..248; Uint<0..1> remains legal` : undefined);
}

/** Versioned syntax restrictions apply before generic specialization. */
export function checkLegacySyntax(body: Statement, version: CompilerVersion): void {
  // An explicit pre-order stack (children pushed in reverse) visits and rejects
  // exactly as the former recursion did, so syntax nesting needs no depth limit;
  // the node allowance still bounds the work.
  let work = 0;
  const pending: ({ expression: Expr } | { statement: Statement })[] = [{ statement: body }];
  const push = (items: readonly ({ expression: Expr } | { statement: Statement } | undefined)[]) => {
    for (let index = items.length - 1; index >= 0; index--) if (items[index]) pending.push(items[index]!);
  };
  while (pending.length) {
    const item = pending.pop()!;
    if ("expression" in item) {
      const expr = item.expression;
      if (++work > 200000) fail("profile-syntax-budget", "Compiler-profile syntax allowance exhausted", expr.span);
      if (expr.kind === "emit") fail("unsupported-profile-syntax", `emit is unavailable in compiler ${version}`, expr.span);
      push([expr.body && { statement: expr.body }]);
      push(expr.args.map(arg => ({ expression: arg })));
      continue;
    }
    const node = item.statement;
    if (++work > 200000) fail("profile-syntax-budget", "Compiler-profile syntax allowance exhausted", node.span);
    if (node.kind === "block" || node.kind === "bindings") push(node.body.map(child => ({ statement: child })));
    else if (node.kind === "if") push([{ expression: node.condition }, { statement: node.then }, node.otherwise && { statement: node.otherwise }]);
    else if (node.kind === "for") {
      if (!node.sequence && literalLoopBoundProfile(version)) {
        const start = naturalValue(String(node.start)), end = naturalValue(String(node.end));
        if (start === undefined || end === undefined || end < start || end > start + 1000n) fail("unsupported-profile-syntax", `Compiler ${version} requires literal range bounds with at most 1000 iterations`, node.span);
      }
      push([node.sequence && { expression: node.sequence }, { statement: node.body }]);
    } else push([{ expression: node.expr }]);
  }
}
