import { IdentityAccounting } from "./identity-accounting.js";
import { realpathSync } from "node:fs";
import { basename, delimiter, dirname, resolve } from "node:path";
import { Declaration, Expr, ImportAst, Parameter, Pattern, ScopeAst, SourceFile, Span, Statement, fail, spanId } from "../model.js";
import { CFG, buildCFG } from "../cfg/index.js";
import { INTRINSICS, intrinsicModel, STANDARD_TYPES, STANDARD_TYPE_MODELS, intrinsicResult, ledgerEffect, standardType, standardTypeName } from "./intrinsics.js";
import { EMPTY_ELEMENT_TYPE, FIELD_MODULUS, TUPLE_TYPE, UINT_BOUND, arithmeticType, compatible, elementType, naturalValue, numericBound, parseType, printType, sequenceLength, substituteType, typeArguments } from "./types.js";
import { genericBindings, specializeDeclaration, specializeScope } from "./specialize.js";
import { Sources } from "./sources.js";
import { TypeExportValidator } from "./type-exports.js";
import { returnFlow } from "./control-flow.js";
import { classifyCast } from "./casts.js";
import { constructionType, projectionType, sequenceElementAt } from "./sequences.js";
import { ABSENT_PROFILE_NATIVES, COMPILER_PROFILES, UNMODELED_PROFILE_NATIVES, checkLegacySyntax, checkRc2Identifiers, nativePointProfile, opaqueJubjubProfile, profileNumericTypeError, selectCompilerVersion, semanticProfile, validZkirVersion, workingDirectorySearchProfile, type CompilerVersion, type SemanticProfile, type ZkirVersion } from "./profile.js";
import { fieldModulus, foreignField } from "./fields.js";
import { externalNativeStandardLibrary, legacyStandardLibrary, nativePointStandardLibrary, prereleaseStandardLibrary, rc2StandardLibrary, standardLibrary, zkir3Library } from "./stdlib.js";
import { EVENT_VERSION, STANDARD_EVENTS } from "./events.js";
import { expressionAbortAnalysis, lowerInstructions, operationEffects } from "../ir/index.js";

export interface SymbolInfo {
  id: string;
  name: string;
  kind: Declaration["kind"] | "parameter" | "local" | "intrinsic";
  type: string;
  span: Span;
  declaration?: Declaration;
  overloads?: SymbolInfo[];
  uninitialized?: boolean;
  intrinsicProfile?: "legacy";
  /** Canonical generic callable template in its concrete module instance. */
  specializationOrigin?: string;
}

interface ScopedSymbol extends SymbolInfo {
  functionGroups?: SymbolInfo[][];
}

const callable = (symbol: SymbolInfo): boolean => ["circuit", "witness", "intrinsic"].includes(symbol.kind);

function signature(symbol: SymbolInfo): { generics?: string; parameters: string[]; result: string } {
  if (symbol.kind === "intrinsic") return intrinsicModel(symbol);
  const declaration = symbol.declaration!;
  return { generics: declaration.generics, parameters: declaration.parameters.map(parameter => parameter.type), result: declaration.type };
}

interface Scope {
  id: string;
  meteringId: string;
  ast: ScopeAst;
  file: string;
  importBase: string;
  externalBase?: string;
  names: Map<string, SymbolInfo>;
  visibleNames: Map<string, SymbolInfo>;
  exports: Set<string>;
  exportedNames: Map<string, SymbolInfo>;
  modules: Map<string, Scope>;
  linked: boolean;
  linking: boolean;
  template: boolean;
  parent?: Scope;
  declaration?: Declaration;
  ancestry: string[];
}

export interface FunctionInfo {
  symbol: SymbolInfo;
  declaration: Declaration;
  cfg: CFG;
  calls: Set<string>;
  readsState: Set<string>;
  writesState: Set<string>;
  emitsEvent?: Span;
}

export interface NominalType {
  declaration: string;
  underlying: string;
}

export class Program {
  readonly semanticProfile: SemanticProfile;
  readonly compilerVersion: CompilerVersion;
  readonly sources: Sources;
  /** Physical source captured at construction, independent of later cwd/symlink changes. */
  readonly rootSource: SourceFile;
  get files(): Map<string, SourceFile> { return this.sources.files; }
  readonly symbols = new Map<string, SymbolInfo>();
  readonly functions = new Map<string, FunctionInfo>();
  /** Resolved import edges, retaining owner scope and physical declaration identity. */
  readonly imports: { location: Span; owner: string; topLevel: boolean; target: string; declaration: Span }[] = [];
  readonly entries: string[] = [];
  private readonly scopes = new Map<string, Scope>();
  private readonly instances = new Map<string, { arguments: string[]; scope: Scope }[]>();
  private readonly specializations = new Map<string, { arguments: string[]; symbol: SymbolInfo }[]>();
  private readonly bound = new Set<string>();
  private readonly instructionGraphs = new Map<string, CFG>();
  private readonly functionScopes = new Map<string, Scope>();
  private readonly declarationSymbols = new Map<Declaration, SymbolInfo>();
  private readonly identityAccounting = new IdentityAccounting();
  private readonly reportAccounting = this.identityAccounting.reporting();
  readonly reportIdentity = this.reportAccounting.text;
  readonly meteringPath = (path: string): string => this.identityAccounting.path(path);
  readonly meteringIdentity = Object.assign(this.identityAccounting.text, { pathText: this.meteringPath, reportText: this.reportIdentity, rememberReport: this.reportAccounting.remember });

  meteringSelector(selector: string): string {
    return this.symbols.has(selector) ? this.meteringIdentity(selector) : selector;
  }

  private meteringJoin(...parts: string[]): string {
    return this.identityAccounting.register(parts.join(""), parts.map(this.meteringIdentity).join(""));
  }

  spanIdentity(span: Span): string {
    return this.identityAccounting.register(spanId(span), `${this.meteringPath(span.file)}:${span.start}`);
  }
  private bindingContext = "root";
  private bindingDepth = 0;
  readonly fieldTypes = new Map<string, Record<string, string>>();
  private readonly resolvedFields = new Map<string, Record<string, string>>();
  readonly nominalTypes = new Map<string, NominalType>();
  private readonly nominalAliases = new Map<string, string>();
  private hasNominalDeclarations = false;
  readonly mayAbortExpression: (expression: Expr) => boolean;

  constructor(readonly root: string, readonly searchPaths: string[] = (process.env.COMPACT_PATH ?? "").split(delimiter).filter(Boolean), readonly sourceRoot: string = dirname(root), sources?: Sources, readonly zkirVersion: ZkirVersion = 2, compilerVersion?: CompilerVersion) {
    if (!validZkirVersion(zkirVersion)) throw new Error("ZKIR version must be 2 or 3");
    this.sources = sources ?? new Sources(searchPaths);
    const input = this.sources.read(root);
    this.compilerVersion = selectCompilerVersion(input.ast.pragmas, input.ast.span, compilerVersion, zkirVersion);
    this.semanticProfile = semanticProfile(zkirVersion, this.compilerVersion);
    const scope = this.load(root);
    this.rootSource = this.files.get(scope.file)!;
    this.link(scope);
    for (const current of this.scopes.values()) if (!current.template) this.prepareScope(current);
    this.bindScope(scope);
    const typeExports = new TypeExportValidator((owner, name) => {
      const definingScope = this.functionScopes.get(owner.id);
      return (definingScope ? this.lexicalNames(definingScope).get(name) : undefined) ?? this.symbols.get(name);
    }, this.compilerVersion);
    const publicBindings = [...scope.exportedNames.values(), ...[...scope.names.values()].filter(symbol => symbol.kind === "constructor")];
    for (const symbol of publicBindings) {
      if (symbol.kind === "type") {
        typeExports.validate(symbol);
        if (!symbol.declaration?.generics && !STANDARD_TYPE_MODELS[standardTypeName(symbol.id) ?? ""]?.generics) this.canonicalType(symbol.id, this.lexicalNames(scope), symbol.span);
      }
      if (symbol.kind === "constructor" || symbol.kind === "circuit") {
        if (symbol.overloads) fail("overloaded-entrypoint", "Expose separately named entrypoints for overloaded library circuits", symbol.span);
        if (symbol.declaration?.generics) fail("generic-entrypoint", "Exported application circuits must be specialized", symbol.span);
        if (!this.entries.includes(symbol.id)) this.entries.push(symbol.id);
        this.bindFunction(symbol, this.functionScopes.get(symbol.id)!);
      }
    }
    this.propagateEffects();
    this.checkEmptyEventArguments();
    this.mayAbortExpression = expressionAbortAnalysis(this.symbols, this.functions, type => this.representationOf(type), (type, operation) => this.ledgerEffect(type, operation));
    for (const fn of this.functions.values()) fn.cfg.resolveAbortEdges(this.mayAbortExpression);
  }

  findCallers(id: string): FunctionInfo[] {
    return [...this.functions.values()].filter(fn => fn.calls.has(id));
  }

  instructionCFG(id: string): CFG {
    const cached = this.instructionGraphs.get(id);
    if (cached) return cached;
    const fn = this.functions.get(id);
    if (!fn) throw new Error(`No resolved circuit ${id}`);
    const graph = lowerInstructions(fn.cfg, id, this.symbols, 50000, this.functions, type => this.representationOf(type), (type, operation) => this.ledgerEffect(type, operation));
    this.instructionGraphs.set(id, graph);
    return graph;
  }

  instructionNodeCount(): number {
    return [...this.instructionGraphs.values()].reduce((total, graph) => total + graph.nodes.length, 0);
  }

  findStateWriters(id: string): FunctionInfo[] {
    return [...this.functions.values()].filter(fn => fn.writesState.has(id));
  }

  activeSymbols(): SymbolInfo[] {
    return [...this.symbols.values()].filter(symbol => this.isActiveSymbol(symbol));
  }

  isActiveSymbol(symbol: SymbolInfo): boolean {
    const scope = this.functionScopes.get(symbol.id);
    return !!scope && !scope.template && !symbol.declaration?.generics;
  }

  ensureFunction(id: string): FunctionInfo | undefined {
    const symbol = this.symbols.get(id);
    const scope = this.functionScopes.get(id);
    if (symbol?.kind === "circuit" && scope && !symbol.declaration?.generics) {
      this.bindFunction(symbol, scope);
      this.propagateEffects();
      this.checkEmptyEventArguments();
    }
    return this.functions.get(id);
  }

  private load(path: string, template = false): Scope {
    const canonical = realpathSync(path);
    this.meteringPath(path);
    this.meteringPath(canonical);
    const identity = template ? path : canonical;
    const prior = this.scopes.get(identity);
    if (prior) return prior;
    const source = this.sources.read(canonical);
    const included = this.sources.inclusions.length;
    const expanded = this.sources.expand(source.ast, [], dirname(identity));
    for (const file of this.files.keys()) this.meteringPath(file);
    for (const inclusion of this.sources.inclusions.slice(included)) this.checkSearchOrder(basename(inclusion.source), inclusion.site, "include");
    return this.makeScope(identity, expanded, canonical, template, undefined, [], dirname(identity), this.meteringPath(identity));
  }

  /** Compilers before 0.29.105 look for include/import files in the invocation
   * directory first; that working-directory-dependent choice is unknown here. */
  private checkSearchOrder(name: string, site: Span, kind: "include" | "import"): void {
    if (workingDirectorySearchProfile(this.compilerVersion))
      fail("unsupported-profile-search-order", `Compiler ${this.compilerVersion} searches the invocation directory before the including file's directory for ${kind} ${JSON.stringify(name)}; that file lookup is not modeled`, site);
  }

  private makeScope(id: string, ast: ScopeAst, file: string, template = false, parent?: Scope, ancestry: string[] = [], importBase = dirname(file), meteringId = this.meteringIdentity(id)): Scope {
    selectCompilerVersion(ast.pragmas, ast.span, this.compilerVersion, this.zkirVersion);
    if (this.compilerVersion === "0.33.0-rc.2") checkRc2Identifiers(ast);
    if (this.scopes.size >= 2048) fail("module-budget", "Module instances exceed 2048 scopes", ast.span);
    const scope: Scope = { id, meteringId, ast, file, importBase, names: new Map(), visibleNames: new Map(), exports: new Set(ast.exports), exportedNames: new Map(), modules: new Map(), linked: false, linking: false, template, parent, ancestry };
    this.scopes.set(id, scope);
    for (const declaration of ast.declarations) {
      if (COMPILER_PROFILES[this.compilerVersion].legacy && declaration.body) checkLegacySyntax(declaration.body, this.compilerVersion);
      if (declaration.body) returnFlow(declaration.body);
      const symbol: SymbolInfo = { id: id === "standard-library" && declaration.exported && declaration.kind === "type" ? `standard-type::${declaration.name}` : `${id}::${declaration.name}`, name: declaration.name, kind: declaration.kind, type: declaration.type, span: declaration.span, declaration };
      if (scope.names.has(symbol.name)) symbol.id += `::overload:${declaration.span.start}`;
      this.identityAccounting.register(symbol.id, symbol.id.startsWith(id + "::") ? meteringId + symbol.id.slice(id.length) : symbol.id);
      this.insert(scope.names, symbol.name, symbol);
      this.declarationSymbols.set(declaration, symbol);
      this.functionScopes.set(symbol.id, scope);
      if (declaration.typeKind === "struct") this.fieldTypes.set(symbol.id, Object.fromEntries(declaration.parameters.map(parameter => [parameter.name, parameter.type])));
      if (declaration.nominal) this.hasNominalDeclarations = true;
      if (declaration.exported) scope.exports.add(symbol.name);
      if (declaration.scope) {
        const module = this.makeScope(symbol.id, declaration.scope, file, true, scope, ancestry, importBase);
        module.declaration = declaration;
        scope.modules.set(symbol.name, module);
      }
    }
    return scope;
  }

  private insert(names: Map<string, SymbolInfo>, name: string, symbol: SymbolInfo): void {
    const previous = names.get(name);
    if (previous?.id === symbol.id && !previous.overloads && !symbol.overloads) return;
    if (previous && callable(previous) && callable(symbol)) {
      const candidates = [...new Map([...(previous.overloads ?? [previous]), ...(symbol.overloads ?? [symbol])].map(candidate => [candidate.id, candidate])).values()];
      // Equal signatures may coexist. Only a call selecting more than one
      // binding is ambiguous; an explicit exported declaration selects itself.
      names.set(name, candidates.length === 1 ? candidates[0] : { ...previous, overloads: candidates });
      for (const candidate of candidates) this.symbols.set(candidate.id, candidate);
      return;
    }
    if (previous) fail("duplicate-symbol", `Duplicate binding: ${name}`, symbol.span);
    names.set(name, symbol);
    if (symbol.overloads) for (const candidate of symbol.overloads) this.symbols.set(candidate.id, candidate);
    else this.symbols.set(symbol.id, symbol);
  }

  private link(scope: Scope): void {
    if (scope.linked) return;
    if (scope.linking) fail("import-cycle", "Cyclic module imports are not supported", scope.ast.span);
    scope.linking = true;
    const elements = [
      ...scope.ast.declarations.map(value => ({ kind: "declaration" as const, value })),
      ...scope.ast.imports.map(value => ({ kind: "import" as const, value })),
    ].sort((first, second) => first.value.order! - second.value.order!);
    const insertImported = (name: string, symbol: SymbolInfo): void => {
      this.insert(scope.names, name, symbol);
      this.insert(scope.visibleNames, name, symbol);
    };
    for (const element of elements) {
      if (element.kind === "declaration") {
        this.insert(scope.visibleNames, element.value.name, this.declarationSymbols.get(element.value)!);
        continue;
      }
      const imported = element.value;
      const template = this.importScope(scope, imported);
      if (template === "standard-library") {
        if (imported.generics) fail("generic-arity", "CompactStandardLibrary has no generic parameters", imported.span);
        if (imported.selections?.length === 0) continue;
        const library = this.standardLibraryScope();
        for (const selection of imported.selections ?? [...library.exports].map(name => ({ name, alias: name }))) {
          const symbol = library.exportedNames.get(selection.name);
          if (!symbol) fail("unsupported-stdlib-export", `No model for standard-library export ${selection.name}`, imported.span);
          insertImported(imported.prefix + selection.alias, symbol);
        }
        continue;
      }
      if (scope.ancestry.includes(template.id)) fail("import-cycle", "Cyclic module instantiation", imported.span);
      const argumentsText = imported.generics ? `<${typeArguments(imported.generics).map(type => this.canonicalArgument(type, this.lexicalNames(scope), imported.span)).join(",")}>` : undefined;
      const bindings = genericBindings(template.declaration?.generics, argumentsText, imported.span);
      const argumentsList = [...bindings.values()];
      const instances = this.instances.get(template.id) ?? [];
      let target = instances.find(instance => this.sameGenericArguments(instance.arguments, argumentsList))?.scope;
      if (!target) {
        const site = this.spanIdentity(imported.span);
        const id = this.identityAccounting.register(`${scope.id}::import:${imported.order}:${site}`,
          `${scope.meteringId}::import:${imported.order}:${this.meteringIdentity(site)}`);
        target = this.makeScope(id, specializeScope(template.ast, bindings), template.file, false, template.parent, [...scope.ancestry, template.id], template.externalBase ?? scope.importBase);
        instances.push({ arguments: argumentsList, scope: target });
        this.instances.set(template.id, instances);
      }
      this.imports.push({ location: imported.span, owner: scope.id, topLevel: !scope.template && !scope.parent && !scope.ancestry.length, target: target.id, declaration: template.declaration!.span });
      this.link(target);
      for (const selection of imported.selections ?? [...target.exports].map(name => ({ name, alias: name }))) {
        const symbol = target.exportedNames.get(selection.name);
        if (!symbol) fail("missing-export", `Module does not export ${selection.name}`, imported.span);
        insertImported(imported.prefix + selection.alias, symbol);
      }
    }
    for (const declaration of scope.ast.declarations) if (declaration.exported) {
      this.insert(scope.exportedNames, declaration.name, this.declarationSymbols.get(declaration)!);
    }
    for (const name of scope.ast.exports) {
      const symbol = this.lookupBinding(scope, name);
      if (!symbol) fail("missing-export", `Exported binding does not exist: ${name}`, scope.ast.span);
      this.insert(scope.exportedNames, name, symbol);
    }
    scope.linking = false;
    scope.linked = true;
  }

  private standardLibraryScope(): Scope {
    const existing = this.scopes.get("standard-library");
    if (existing) return existing;
    const legacy = COMPILER_PROFILES[this.compilerVersion].legacy;
    const library = COMPILER_PROFILES[this.compilerVersion].library === "standard-library-0.35-rc.1" ? prereleaseStandardLibrary
      : this.compilerVersion === "0.33.0-rc.2" ? rc2StandardLibrary : this.compilerVersion === "0.28.0" ? externalNativeStandardLibrary : nativePointProfile(this.compilerVersion) ? nativePointStandardLibrary : legacy ? legacyStandardLibrary : standardLibrary;
    const ast = structuredClone(library.ast);
    if (this.zkirVersion === 3) ast.declarations.push(...structuredClone(zkir3Library.ast.declarations));
    // Preserve the qualified constructor/hash/witness transfer overrides.
    ast.declarations = ast.declarations.filter(declaration => !Object.hasOwn(INTRINSICS, declaration.name));
    // Builtins are library templates, not application declarations. Unused
    // helpers must not become application inventory or constructor storage.
    const scope = this.makeScope("standard-library", ast, library.path, true);
    this.sources.files.set(library.path, library);
    this.meteringPath(library.path);
    if (this.zkirVersion === 3) this.sources.files.set(zkir3Library.path, zkir3Library);
    if (this.zkirVersion === 3) this.meteringPath(zkir3Library.path);
    const native = (symbol: SymbolInfo): void => {
      this.insert(scope.names, symbol.name, symbol);
      this.insert(scope.visibleNames, symbol.name, symbol);
      scope.exports.add(symbol.name);
      this.insert(scope.exportedNames, symbol.name, symbol);
    };
    const absent = new Set([...(legacy ? ["keccak256", "ecNeg"] : []), ...ABSENT_PROFILE_NATIVES[this.compilerVersion] ?? [], ...UNMODELED_PROFILE_NATIVES[this.compilerVersion] ?? []]);
    for (const [key, model] of Object.entries(INTRINSICS)) if ((!model.zkir3 || this.zkirVersion === 3) && !absent.has(key)) native({ id: `intrinsic::${key}`, name: key.split(":")[0], kind: "intrinsic", type: model.kind, span: ast.span, ...(legacy ? { intrinsicProfile: "legacy" as const } : {}) });
    for (const [name, model] of Object.entries(STANDARD_TYPE_MODELS)) if ((!model.zkir3 || this.zkirVersion === 3) && !scope.names.has(name) && !(legacy && (name === "JubjubScalar" || name === "JubjubSchnorrSignature" || Object.hasOwn(STANDARD_EVENTS, name))) && !(name === "JubjubPoint" && nativePointProfile(this.compilerVersion))) native({ id: `standard-type::${name}`, name, kind: "type", type: `standard-type::${name}`, span: ast.span });
    this.link(scope);
    this.prepareScope(scope);
    return scope;
  }

  private lookupBinding(scope: Scope, name: string, charge?: () => boolean): SymbolInfo | undefined {
    for (let current: Scope | undefined = scope; current; current = current.parent) {
      if (charge && !charge()) return;
      const binding = (current.linking ? current.visibleNames : current.names).get(name);
      if (binding) return binding;
    }
    return undefined;
  }

  private importScope(scope: Scope, imported: ImportAst): Scope | "standard-library" {
    if (!imported.external) {
      const binding = this.lookupBinding(scope, imported.name);
      if (binding) {
        if (binding.kind !== "module") fail("invalid-import", `${imported.name} is bound to a ${binding.kind}, not a module`, imported.span);
        return this.scopes.get(binding.id)!;
      }
      if (imported.name === "CompactStandardLibrary") return "standard-library";
    }
    this.checkSearchOrder(`${imported.name}.compact`, imported.span, "import");
    const path = this.sources.locate(`${imported.name}.compact`, imported.span, "import", scope.importBase);
    const external = this.load(path, true);
    const moduleName = basename(imported.name);
    const module = external.modules.get(moduleName);
    if (!module || external.ast.declarations.length !== 1 || external.ast.imports.length || external.ast.exports.length) fail("invalid-module-file", `Import file must contain only the definition of module ${moduleName}`, imported.span);
    module.parent = undefined;
    module.externalBase = dirname(path);
    return module;
  }

  private bindScope(scope: Scope): void {
    this.link(scope);
    for (const declaration of scope.ast.declarations) {
      if (!declaration.body || declaration.generics) continue;
      const symbol = this.declarationSymbols.get(declaration)!;
      this.bindFunction(symbol, scope);
    }
  }

  private prepareScope(scope: Scope): void {
    const names = this.lexicalNames(scope);
    for (const declaration of scope.ast.declarations) {
      const symbol = this.declarationSymbols.get(declaration)!;
      if (declaration.typeKind === "contract") {
        const members = new Set<string>();
        for (const circuit of declaration.circuits ?? []) {
          if (members.has(circuit.name)) fail("unsupported-contract-call", `No unique declared circuit ${circuit.name} on contract ${symbol.name}`, circuit.span);
          members.add(circuit.name);
          circuit.type = this.ordinaryType(circuit.type, names, circuit.span);
          const parameters = new Set<string>();
          for (const parameter of circuit.parameters) {
            if (parameters.has(parameter.name)) fail("duplicate-symbol", `Duplicate parameter ${parameter.name}`, parameter.span);
            parameters.add(parameter.name);
            parameter.type = this.ordinaryType(parameter.type, names, parameter.span);
          }
        }
      }
      if (this.functionScopes.get(symbol.id) !== scope || symbol.declaration?.generics || !["ledger", "circuit", "witness", "constructor"].includes(symbol.kind)) continue;
      symbol.type = this.canonicalType(symbol.type, names, symbol.span);
      if (symbol.kind !== "ledger") this.requireOrdinary(symbol.type, symbol.span);
      symbol.declaration!.type = symbol.type;
      for (const parameter of symbol.declaration!.parameters) parameter.type = this.ordinaryType(parameter.type, names, parameter.span);
    }
  }

  private canonicalType(text: string, names: Map<string, ScopedSymbol>, location: Span, depth = 0): string {
    if (depth > 32) fail("type-depth", "Recursive or excessively deep type alias", location);
    if (text === EMPTY_ELEMENT_TYPE) return text;
    const term = parseType(text);
    const error = profileNumericTypeError(term, this.compilerVersion);
    if (error) fail("invalid-numeric-type", error, location);
    // In RC2 the scalar is a language type, before 0.34 moved it to native imports.
    if (this.compilerVersion === "0.33.0-rc.2" && term.name === "JubjubScalar") {
      if (term.args.length) fail("generic-arity", "JubjubScalar takes no generic arguments", location);
      return "standard-type::JubjubScalar";
    }
    if (["Field", "Boolean", "Uint", "Bytes", "Vector", TUPLE_TYPE].includes(term.name)) {
      if (["Field", "Boolean"].includes(term.name) && term.args.length) fail("generic-arity", `${term.name} takes no generic arguments`, location);
      if (term.name === "Vector") term.args[1] = parseType(this.ordinaryType(printType(term.args[1]), names, location, depth + 1));
      if (term.name === TUPLE_TYPE) term.args = term.args.map(arg => parseType(this.ordinaryType(printType(arg), names, location, depth + 1)));
      return printType(term);
    }
    if (term.name === "Opaque") {
      if (term.args.length !== 1) fail("generic-arity", "Opaque requires one string argument", location);
      const kind = /^(["'])(string|Uint8Array|JubjubPoint)\1$/.exec(printType(term.args[0]))?.[2];
      if (!kind || kind === "JubjubPoint" && !opaqueJubjubProfile(this.compilerVersion)) fail("unsupported-opaque-type", "Only Opaque string and Uint8Array kinds are supported", location);
      return `Opaque<"${kind}">`;
    }
    term.args = term.args.map(arg => parseType(this.canonicalArgument(printType(arg), names, location, depth + 1)));
    const symbol = names.get(term.name) ?? this.symbols.get(term.name);
    const nativeName = standardTypeName(symbol?.id ?? term.name);
    const args = term.args.length ? `<${term.args.map(printType).join(",")}>` : undefined;
    if (nativeName) {
      const model = STANDARD_TYPE_MODELS[nativeName];
      if (model.zkir3 && this.zkirVersion !== 3) fail("unsupported-profile-type", `${nativeName} requires the Compact 0.34.0 ZKIR3 profile`, location);
      genericBindings(model.generics, args, location);
      for (const index of model.ordinaryArguments ?? []) this.requireOrdinary(printType(term.args[index]), location);
      if (["MerkleTree", "HistoricMerkleTree"].includes(nativeName)) {
        const depth = naturalValue(term.args[0]?.name ?? "");
        if (depth === undefined || depth < 2n || depth > 32n) fail("invalid-merkle-depth", "Merkle tree depth must be between 2 and 32", location);
      }
      if (model.ledger && term.args.some(arg => this.representationOf(printType(arg)) === "Kernel")) fail("nested-kernel-type", "Kernel cannot be nested within a ledger ADT", location);
      term.name = `standard-type::${nativeName}`;
      const identity = printType(term);
      if (opaqueJubjubProfile(this.compilerVersion) && nativeName === "JubjubPoint") {
        this.nominalTypes.set(identity, { declaration: identity, underlying: "Opaque<\"JubjubPoint\">" });
      }
      if (STANDARD_TYPES[nativeName] && !this.resolvedFields.has(identity)) {
        this.cacheFields(identity, Object.fromEntries(Object.entries(STANDARD_TYPES[nativeName]).map(([field, type]) => [field, this.ordinaryType(standardType(type).replace(/\$(\d+)/g, (_, index) => printType(term.args[Number(index)])), names, location, depth + 1)])), location);
      }
      return identity;
    }
    if (!symbol) fail("unresolved-type", `Unknown type ${term.name}`, location);
    if (symbol.kind !== "type") fail("invalid-type-context", `${term.name} is bound to a ${symbol.kind}, not a type`, location);
    if (!symbol.declaration) fail("unresolved-type", `No type model for ${term.name}`, location);
    const bindings = genericBindings(symbol.declaration.generics, args, location);
    if (symbol.declaration.typeKind === "alias") {
      const scope = this.functionScopes.get(symbol.id)!;
      const specialization = symbol.id + (args ?? "");
      const cached = this.nominalAliases.get(specialization);
      if (cached) return cached;
      const underlying = this.canonicalType(substituteType(symbol.type, bindings), this.lexicalNames(scope), location, depth + 1);
      if (!symbol.declaration.nominal) return underlying;
      if (this.nominalAliases.size >= 4096) fail("type-budget", "Nominal specializations exceed 4096 types", location);
      const equivalent = [...this.nominalTypes].find(([, type]) => type.declaration === symbol.id && this.sameType(type.underlying, underlying));
      const identity = equivalent?.[0] ?? specialization;
      if (!equivalent) this.nominalTypes.set(identity, { declaration: symbol.id, underlying });
      this.nominalAliases.set(specialization, identity);
      return identity;
    }
    term.name = symbol.id;
    const identity = printType(term);
    if (symbol.declaration.typeKind === "struct" && !this.resolvedFields.has(identity)) {
      const lexical = this.lexicalNames(this.functionScopes.get(symbol.id)!);
      this.cacheFields(identity, Object.fromEntries(symbol.declaration.parameters.map(parameter => [parameter.name, this.ordinaryType(substituteType(parameter.type, bindings), lexical, parameter.span, depth + 1)])), location);
    }
    return identity;
  }

  private cacheFields(identity: string, fields: Record<string, string>, location: Span): void {
    if (this.resolvedFields.size >= 4096) fail("type-budget", "Aggregate specializations exceed 4096 types", location);
    this.resolvedFields.set(identity, fields);
  }

  private canonicalArgument(text: string, names: Map<string, ScopedSymbol>, location: Span, depth = 0): string {
    const natural = naturalValue(text);
    if (natural === undefined) return this.canonicalType(text, names, location, depth);
    if (natural >= FIELD_MODULUS) fail("literal-range", "Natural value exceeds the Compact Field range", location);
    return natural.toString();
  }

  private requireOrdinary(type: string, location: Span): void {
    const name = standardTypeName(parseType(this.underlyingType(type)).name);
    if (name && STANDARD_TYPE_MODELS[name].ledger) fail("ledger-type-context", `Ledger ADT ${name} is not an ordinary value type`, location);
  }

  private ordinaryType(text: string, names: Map<string, ScopedSymbol>, location: Span, depth = 0): string {
    const type = this.canonicalType(text, names, location, depth);
    this.requireOrdinary(type, location);
    return type;
  }

  /** Canonical defining module instance, independent of imported aliases. */
  definingScope(symbol: string): { id: string; module: boolean } | undefined {
    const scope = this.functionScopes.get(symbol);
    return scope ? { id: scope.id, module: !!scope.parent || !!scope.ancestry.length } : undefined;
  }

  /** Defining lexical environment, retaining imported aliases and nearest scopes.
   * The returned map is detached; consumers must not infer scope from symbol IDs. */
  lexicalBindings(circuit: string): ReadonlyMap<string, SymbolInfo> {
    const scope = this.functionScopes.get(circuit);
    return scope ? this.lexicalNames(scope) : new Map();
  }

  /** Nearest defining-scope binding, retaining aliases and non-callable blockers.
   * Scalar lookup avoids copying unrelated names; charge every visited scope.
   * This returns binding identity, not an overload-resolution group. */
  lexicalBinding(circuit: string, name: string, charge?: () => boolean): SymbolInfo | undefined {
    const scope = this.functionScopes.get(circuit);
    return scope ? this.lookupBinding(scope, name, charge) : undefined;
  }

  /** Natural parameters of an unbound callable/template are value bindings;
   * specialization replaces their references with literals, not outer storage. */
  lexicalNaturalParameters(circuit: string, charge?: () => boolean): Set<string> {
    const names = new Set<string>();
    const add = (generics?: string): void => {
      for (const parameter of typeArguments(generics)) {
        if (charge && !charge()) return;
        if (parameter.startsWith("#")) names.add(parameter.replace(/^#\s*/, ""));
      }
    };
    add(this.symbols.get(circuit)?.declaration?.generics);
    for (let scope = this.functionScopes.get(circuit); scope; scope = scope.parent) {
      if (charge && !charge()) break;
      if (scope.template) add(scope.declaration?.generics);
    }
    return names;
  }

  /** Resolved public APIs include explicit export lists and imported aliases. */
  *exportedSymbols(): IterableIterator<SymbolInfo> {
    for (const scope of this.scopes.values()) for (const name of scope.exports) {
      // Unimported library modules have declared APIs but are not linked yet.
      const symbol = scope.exportedNames.get(name) ?? this.lookupBinding(scope, name);
      if (symbol) yield* symbol.overloads ?? [symbol];
    }
  }

  private lexicalNames(scope: Scope): Map<string, ScopedSymbol> {
    const names = scope.parent ? this.lexicalNames(scope.parent) : new Map<string, ScopedSymbol>();
    for (const [name, symbol] of scope.linking ? scope.visibleNames : scope.names) {
      const outer = names.get(name);
      names.set(name, outer && callable(symbol) && callable(outer) ? { ...symbol, functionGroups: [symbol.overloads ?? [symbol], ...(outer.functionGroups ?? [outer.overloads ?? [outer]])] } : symbol);
    }
    return names;
  }

  private underlyingType(type: string): string {
    while (this.nominalTypes.has(type)) type = this.nominalTypes.get(type)!.underlying;
    return type;
  }

  /** Canonical native identity through imported and nominal aliases. */
  nativeTypeOf(type: string): string | undefined {
    return standardTypeName(parseType(this.underlyingType(type)).name);
  }

  representationOf(type: string): string {
    const underlying = this.underlyingType(type);
    if (!underlying.startsWith("standard-type::")) return underlying;
    const term = parseType(underlying);
    term.name = standardTypeName(term.name) ?? term.name;
    return printType(term);
  }

  private sameGenericArguments(first: string[], second: string[]): boolean {
    return first.length === second.length && first.every((type, index) => {
      const natural = naturalValue(type);
      return natural !== undefined ? natural === naturalValue(second[index]) : this.sameType(type, second[index]);
    });
  }

  sameType(left: string, right: string, depth = 0): boolean {
    if (left === right) return true;
    if (depth > 32) fail("type-depth", "Type comparison exceeds 32 nested levels", this.rootSource.ast.span);
    const firstNominal = this.nominalTypes.get(left);
    const secondNominal = this.nominalTypes.get(right);
    if (firstNominal || secondNominal) return Boolean(firstNominal && secondNominal && this.symbols.get(firstNominal.declaration)?.name === this.symbols.get(secondNominal.declaration)?.name && this.sameType(firstNominal.underlying, secondNominal.underlying, depth + 1));
    const first = parseType(left);
    const second = parseType(right);
    if (first.name === "Uint" && second.name === "Uint") return numericBound(left) !== undefined && numericBound(left) === numericBound(right);
    if (first.name === "Vector" && second.name === "Vector") return sequenceLength(left) !== undefined && sequenceLength(left) === sequenceLength(right) && this.sameType(elementType(left), elementType(right), depth + 1);
    if ([TUPLE_TYPE, "Vector"].includes(first.name) && [TUPLE_TYPE, "Vector"].includes(second.name)) {
      const length = sequenceLength(left);
      if (length === undefined || length !== sequenceLength(right) || length > 256) return false;
      return Array.from({ length }, (_, index) => this.sameType(elementType(left, index), elementType(right, index), depth + 1)).every(Boolean);
    }
    const firstDeclaration = this.symbols.get(first.name)?.declaration;
    const secondDeclaration = this.symbols.get(second.name)?.declaration;
    const structName = (name: string, declaration?: Declaration): string | undefined => declaration?.typeKind === "struct" ? declaration.name
      : STANDARD_TYPES[standardTypeName(name) ?? ""] ? standardTypeName(name) : undefined;
    const firstStruct = structName(first.name, firstDeclaration), secondStruct = structName(second.name, secondDeclaration);
    if (firstStruct || secondStruct) {
      if (!firstStruct || firstStruct !== secondStruct) return false;
      const firstFields = Object.entries(this.fieldsOf(left)!);
      const secondFields = Object.entries(this.fieldsOf(right)!);
      return firstFields.length === secondFields.length && firstFields.every(([name, type], index) => name === secondFields[index][0] && this.sameType(type, secondFields[index][1], depth + 1));
    }
    if (firstDeclaration?.typeKind === "enum" || secondDeclaration?.typeKind === "enum") {
      return firstDeclaration?.typeKind === "enum" && secondDeclaration?.typeKind === "enum" && firstDeclaration.name === secondDeclaration.name
        && firstDeclaration.variants!.length === secondDeclaration.variants!.length && firstDeclaration.variants!.every((name, index) => name === secondDeclaration.variants![index]);
    }
    if (first.name !== second.name) return false;
    return first.args.length === second.args.length && first.args.every((arg, index) => this.sameType(printType(arg), printType(second.args[index]), depth + 1));
  }

  assignable(actual: string, expected: string): boolean {
    if (actual === "unknown" || expected === "unknown") return false;
    if (actual === EMPTY_ELEMENT_TYPE) return true;
    if (this.sameType(actual, expected)) return true;
    if (this.nominalTypes.has(actual) || this.nominalTypes.has(expected)) return false;
    const first = parseType(actual);
    const second = parseType(expected);
    if (COMPILER_PROFILES[this.compilerVersion].legacy && first.name === "Uint" && expected === "Field") return true;
    if (first.name === "Vector" && second.name === "Vector") return sequenceLength(actual) !== undefined && sequenceLength(actual) === sequenceLength(expected) && this.assignable(elementType(actual), elementType(expected));
    if ([TUPLE_TYPE, "Vector"].includes(first.name) && [TUPLE_TYPE, "Vector"].includes(second.name)) {
      const length = sequenceLength(actual);
      if (length === undefined || length !== sequenceLength(expected) || length > 256) return false;
      return Array.from({ length }, (_, index) => this.assignable(elementType(actual, index), elementType(expected, index))).every(Boolean);
    }
    return compatible(actual, expected);
  }

  commonType(types: string[]): string | undefined {
    if (types.includes("unknown")) return undefined;
    let result = EMPTY_ELEMENT_TYPE;
    for (const type of types) {
      if (this.assignable(type, result)) continue;
      if (!this.assignable(result, type)) return undefined;
      result = type;
    }
    return result;
  }

  private sequenceType(type: string, location: Span): { length: number; element: string } {
    const representation = this.representationOf(type);
    const term = parseType(representation);
    const length = sequenceLength(representation);
    if (length === undefined || !Number.isSafeInteger(length)) fail("unknown-higher-order-size", "Operation requires a statically sized sequence", location);
    if (length > 256) fail("sequence-budget", "Sequence operation exceeds 256 elements", location);
    const element = term.name === TUPLE_TYPE ? this.commonType(term.args.map(printType)) : elementType(representation);
    if (!element) fail("incompatible-sequence-elements", "Sequence element types have no comparable common type", location);
    return { length, element };
  }

  private checkArgument(actual: string, expected: string, location: Span): void {
    if (actual === "unknown" || expected === "unknown") fail("unknown-call-type", "Cannot establish the type of a call argument", location);
    this.checkNominal(actual, expected, location);
    if (!this.assignable(actual, expected)) fail("call-type-mismatch", `Cannot pass ${actual} as ${expected}`, location);
  }

  private selectOverload(symbol: ScopedSymbol, expr: Expr, actual: string[], fold: boolean): SymbolInfo {
    if (actual.includes("unknown")) fail("unknown-call-type", "Cannot establish the type of a call argument", expr.span);
    const args = typeArguments(expr.generics);
    const visited = new Set<string>();
    for (const group of symbol.functionGroups ?? [symbol.overloads ?? [symbol]]) {
      const candidates = group.filter(candidate => {
        if (visited.has(candidate.id)) return false;
        visited.add(candidate.id);
        const shape = signature(candidate);
        const parameters = typeArguments(shape.generics);
        if (parameters.length !== args.length || shape.parameters.length !== actual.length || parameters.some((parameter, index) => parameter.startsWith("#") !== (naturalValue(args[index]) !== undefined))) return false;
        const bindings = genericBindings(shape.generics, expr.generics, expr.span);
        const scope = this.functionScopes.get(candidate.id);
        const names = scope ? this.lexicalNames(scope) : undefined;
        const specialize = (type: string): string => names ? this.ordinaryType(substituteType(type, bindings), names, expr.span) : substituteType(standardType(type), bindings);
        const types = shape.parameters.map(specialize);
        const result = candidate.kind === "intrinsic" ? standardType(intrinsicResult(candidate, expr.generics, actual)) : specialize(shape.result);
        return types.every((type, index) => this.assignable(actual[index], type)) && (!fold || this.sameType(types[0], result));
      });
      if (candidates.length > 1) fail("overload-resolution", `Call to ${expr.name} has ${candidates.length} compatible overloads in its nearest compatible scope`, expr.span);
      if (candidates.length === 1) return candidates[0];
    }
    fail("overload-resolution", `Call to ${expr.name} has no compatible overloads in scope`, expr.span);
  }

  private containsNominal(type: string, seen = new Set<string>()): boolean {
    if (!this.hasNominalDeclarations || seen.has(type)) return false;
    if (this.nominalTypes.has(type)) return true;
    seen.add(type);
    const term = parseType(type);
    return term.args.some(arg => this.containsNominal(printType(arg), seen)) || Object.values(this.fieldsOf(type) ?? {}).some(field => this.containsNominal(field, seen));
  }

  private checkNominal(actual: string, expected: string, location: Span): void {
    if ((this.containsNominal(actual) || this.containsNominal(expected)) && (actual === "unknown" || expected === "unknown" || !this.assignable(actual, expected))) fail("nominal-type-mismatch", `Cannot use ${actual} as ${expected} without a compatible explicit cast`, location);
  }

  private checkValue(actual: string, expected: string, location: Span, context: string): void {
    if (actual === "unknown" || expected === "unknown") fail("unknown-value-type", `Cannot establish ${context} type compatibility`, location);
    this.checkNominal(actual, expected, location);
    if (!this.assignable(actual, expected)) fail(`${context}-type-mismatch`, `Cannot use ${actual} as ${expected} in ${context}`, location);
  }

  private checkBoolean(expression: Expr): void {
    if (this.representationOf(expression.inferredType ?? "unknown") !== "Boolean") fail("boolean-type-mismatch", "Condition requires Boolean or a nominal Boolean type", expression.span);
  }

  private bodyResultType(statement: Statement, continuation = "[]"): string {
    if (statement.kind === "return") return statement.expr.inferredType ?? "unknown";
    if (statement.kind === "block" || statement.kind === "bindings") return statement.body.reduceRight((type, child) => this.bodyResultType(child, type), continuation);
    if (statement.kind !== "if") return continuation;
    const first = this.bodyResultType(statement.then, continuation);
    const second = statement.otherwise ? this.bodyResultType(statement.otherwise, continuation) : continuation;
    const common = this.commonType([first, second]);
    if (!common) fail("return-branch-type-mismatch", "Circuit return branches must have comparable result types before declared-result widening", statement.span);
    return common;
  }

  private orderedTypes(left: string, right: string): boolean {
    const first = this.nominalTypes.get(left);
    const second = this.nominalTypes.get(right);
    if (first || second) return Boolean(first && second && this.symbols.get(first.declaration)?.name === this.symbols.get(second.declaration)?.name && this.orderedTypes(first.underlying, second.underlying));
    return numericBound(left) !== undefined && numericBound(right) !== undefined;
  }

  private checkCast(expression: Expr): void {
    const source = expression.args[0].inferredType ?? "unknown";
    const target = expression.type!;
    expression.castKind = classifyCast(source, target, {
      representationOf: type => this.representationOf(type),
      assignable: (actual, expected) => this.assignable(actual, expected),
      enumeration: type => this.symbols.get(type)?.declaration?.typeKind === "enum",
      zkirVersion: this.zkirVersion,
    });
    if (!expression.castKind) fail(this.containsNominal(source) || this.containsNominal(target) ? "nominal-type-mismatch" : "cast-type-mismatch", `Cannot cast ${source} to ${target}`, expression.span);
  }

  private intrinsicParameters(expr: Expr, symbol: SymbolInfo): string[] {
    const intrinsic = intrinsicModel(symbol);
    const bindings = genericBindings(intrinsic.generics, expr.generics, expr.span);
    return intrinsic.parameters.map(type => substituteType(standardType(type), bindings));
  }

  private checkIntrinsicArguments(expr: Expr, symbol: SymbolInfo): void {
    const expected = this.intrinsicParameters(expr, symbol);
    expr.args.forEach((arg, index) => this.checkArgument(arg.inferredType ?? "unknown", expected[index], arg.span));
    this.checkIntrinsicTypes(symbol, expected, expr.span);
  }

  private containsOpaque(type: string, seen = new Set<string>(), kind?: string): boolean {
    const underlying = this.underlyingType(type);
    if (seen.has(underlying)) return false;
    seen.add(underlying);
    const term = parseType(underlying);
    if (term.name === "Opaque") return kind === undefined || term.args[0]?.name === JSON.stringify(kind);
    if (term.name === "Vector") return this.containsOpaque(printType(term.args[1]), seen, kind);
    if (term.name === TUPLE_TYPE) return term.args.some(element => this.containsOpaque(printType(element), seen, kind));
    return Object.values(this.fieldsOf(underlying) ?? {}).some(field => this.containsOpaque(field, seen, kind));
  }

  private checkIntrinsicTypes(symbol: SymbolInfo, parameters: string[], location: Span): void {
    if (intrinsicModel(symbol).requiresNonOpaqueInput && this.containsUnsupportedOpaque(parameters[0])) fail("unsupported-opaque-intrinsic", `Opaque-containing inputs to ${symbol.name} are outside the qualified native model`, location);
  }

  /** Opaque JubjubPoint is a compiler-defined nominal value in 0.31's
   * standard library. Its canonical hash/commit encodings are stable and the
   * dataflow transfer preserves the point identity, so composed roots may
   * safely include it. Host-only string/Uint8Array opaques remain unavailable
   * because their runtime bytes are not represented by the analyzer. */
  private containsUnsupportedOpaque(type: string, seen = new Set<string>()): boolean {
    const underlying = this.underlyingType(type);
    if (seen.has(underlying)) return false;
    seen.add(underlying);
    const term = parseType(underlying);
    if (term.name === "Opaque") return term.args[0]?.name !== '"JubjubPoint"' || !opaqueJubjubProfile(this.compilerVersion);
    if (term.name === "Vector") return this.containsUnsupportedOpaque(printType(term.args[1]), seen);
    if (term.name === TUPLE_TYPE) return term.args.some(element => this.containsUnsupportedOpaque(printType(element), seen));
    return Object.values(this.fieldsOf(underlying) ?? {}).some(field => this.containsUnsupportedOpaque(field, seen));
  }

  private storageType(expr: Expr): string | undefined {
    if (expr.kind === "ref") {
      const symbol = this.symbols.get(expr.symbol ?? "");
      return symbol?.kind === "ledger" ? symbol.type : undefined;
    }
    if (expr.kind !== "member" || expr.value !== "call") return undefined;
    const receiver = this.storageType(expr.args[0]);
    const result = expr.ledgerType;
    const native = result ? standardTypeName(parseType(this.underlyingType(result)).name) : undefined;
    return receiver && this.ledgerEffect(receiver, expr.name!)?.region && native && STANDARD_TYPE_MODELS[native].ledger ? result : undefined;
  }

  ledgerEffect(type: string, operation: string): ReturnType<typeof ledgerEffect> {
    const representation = this.representationOf(type);
    const term = parseType(representation);
    const stored = term.name === "Map" ? printType(term.args[1]) : ["Set", "List"].includes(term.name) ? printType(term.args[0]) : type;
    const qualifiesCoin = ["writeCoin", "insertCoin", "pushFrontCoin"].includes(operation)
      && this.sameType(stored, standardType("QualifiedShieldedCoinInfo"));
    const effect = ledgerEffect(representation, operation, qualifiesCoin);
    // Compact 0.35 adds the authenticated invocation caller query. Its value
    // is intentionally unknown to static analysis, but the operation itself
    // is a read-only native effect and can be transferred conservatively.
    const caller = this.compilerVersion === "0.35.0" || this.compilerVersion === "0.35.0-rc.1"
      ? representation === "Kernel" && operation === "caller" ? { reads: true, writes: false, arity: 0, parameters: [], result: "Maybe<Either<ContractAddress,UserAddress>>", region: false } : undefined
      : undefined;
    if (caller) return { ...caller, result: standardType(caller.result) };
    return effect ? { ...effect, parameters: operation === "write" ? [type] : effect.parameters.map(standardType), result: operation === "read" && this.representationOf(type) !== "Counter" ? type : standardType(effect.result) } : undefined;
  }

  private bindFunction(symbol: SymbolInfo, scope: Scope): void {
      if (this.bound.has(symbol.id)) return;
      if (this.bound.size >= 4096 || this.bindingDepth >= 64) fail("specialization-budget", "Circuit specialization exceeds the 4096-function or 64-depth budget", symbol.span);
      this.bound.add(symbol.id);
      const declaration = symbol.declaration!;
      const flow = declaration.body ? returnFlow(declaration.body) : undefined;
      const names = this.lexicalNames(scope);
      symbol.type = this.ordinaryType(symbol.type, names, symbol.span);
      declaration.type = symbol.type;
      for (const parameter of declaration.parameters) parameter.type = this.ordinaryType(parameter.type, names, parameter.span);
      if (!declaration.body) return;
      const previousContext = this.bindingContext;
      this.bindingDepth++;
      this.bindingContext = symbol.id;
      this.bindParameters(declaration.parameters, names, symbol.id);
      const effects = { calls: new Set<string>(), readsState: new Set<string>(), writesState: new Set<string>() };
      this.bindStatement(declaration.body, names, effects, symbol.id);
      if (flow?.fallsThrough) this.checkValue("[]", declaration.type, declaration.span, "return");
      this.checkValue(this.bodyResultType(declaration.body), declaration.type, declaration.span, "return");
      this.functions.set(symbol.id, { symbol, declaration, cfg: buildCFG(declaration.body), ...effects });
      this.bindingContext = previousContext;
      this.bindingDepth--;
  }

  private bindStatement(statement: Statement, names: Map<string, ScopedSymbol>, effects: Pick<FunctionInfo, "calls" | "readsState" | "writesState" | "emitsEvent">, functionId: string): void {
    if (statement.kind === "block" || statement.kind === "bindings") {
      const inner = statement.kind === "block" ? new Map(names) : names;
      const declared = new Set<string>();
      if (statement.kind === "block") {
        const patternNames = (pattern: Pattern): { name: string; span: Span }[] => [...(pattern.kind === "name" ? [{ name: pattern.name!, span: pattern.span }] : []), ...pattern.children.flatMap(patternNames)];
        const locals = statement.body.flatMap(child => child.kind === "bindings" ? child.body : [child]).flatMap(child => child.kind === "bind" ? child.pattern ? patternNames(child.pattern) : [{ name: child.name, span: child.span }] : []);
        const seen = new Set<string>();
        for (const local of locals) {
          if (seen.has(local.name)) fail("duplicate-symbol", `Duplicate local ${local.name}`, local.span);
          seen.add(local.name);
          inner.set(local.name, { id: this.meteringJoin(functionId, "::pending:", this.spanIdentity(local.span)), name: local.name, kind: "local", type: "unknown", span: local.span, uninitialized: true });
        }
      }
      for (const child of statement.body) {
        if (child.kind === "bind") {
          if (declared.has(child.name)) fail("duplicate-symbol", `Duplicate local ${child.name}`, child.span);
          declared.add(child.name);
        }
        this.bindStatement(child, inner, effects, functionId);
      }
    } else if (statement.kind === "bind") {
      this.bindExpr(statement.expr, names, effects);
      if (statement.type) statement.type = this.canonicalType(statement.type, names, statement.span);
      if (statement.type) this.checkValue(statement.expr.inferredType ?? "unknown", statement.type, statement.span, "binding");
      const symbol: SymbolInfo = { id: this.meteringJoin(functionId, "::local:", this.spanIdentity(statement.span)), name: statement.name, kind: "local", type: statement.type ?? statement.expr.inferredType ?? "unknown", span: statement.span };
      statement.symbol = symbol.id;
      names.set(symbol.name, symbol);
      this.symbols.set(symbol.id, symbol);
      if (statement.pattern) {
        if (statement.pattern.kind === "name") statement.pattern.symbol = symbol.id;
        else this.bindPattern(statement.pattern, symbol.type, names, functionId);
      }
    } else if (statement.kind === "if") {
      this.bindExpr(statement.condition, names, effects);
      this.checkBoolean(statement.condition);
      this.bindStatement(statement.then, new Map(names), effects, functionId);
      if (statement.otherwise) this.bindStatement(statement.otherwise, new Map(names), effects, functionId);
    } else if (statement.kind === "for") {
      const inner = new Map(names);
      let sequenceElement: string | undefined;
      if (statement.sequence) {
        this.bindExpr(statement.sequence, names, effects);
        const { length, element } = this.sequenceType(statement.sequence.inferredType ?? "unknown", statement.sequence.span);
        sequenceElement = element;
        statement.start = 0;
        statement.end = length;
      }
      for (const key of ["start", "end"] as const) if (typeof statement[key] === "string") {
        const value = naturalValue(statement[key]);
        if (value !== undefined) {
          if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail("loop-range", "Loop bounds exceed exact integer representation", statement.span);
          statement[key] = Number(value);
        }
      }
      if (typeof statement.start !== "number" || typeof statement.end !== "number") fail("unsupported-generics", "Loop bounds require natural-parameter specialization", statement.span);
      const symbol: SymbolInfo = { id: this.meteringJoin(functionId, "::loop:", this.spanIdentity(statement.span)), name: statement.name, kind: "local", type: sequenceElement ?? (statement.end > statement.start ? `Uint<0..${statement.end}>` : EMPTY_ELEMENT_TYPE), span: statement.span };
      statement.symbol = symbol.id;
      this.symbols.set(symbol.id, symbol);
      inner.set(symbol.name, symbol);
      if (statement.sequence) {
        statement.sequenceSymbol = this.meteringJoin(symbol.id, ":sequence");
        this.symbols.set(statement.sequenceSymbol, { id: statement.sequenceSymbol, name: "$sequence", kind: "local", type: statement.sequence.inferredType!, span: statement.span });
      }
      this.bindStatement(statement.body, inner, effects, functionId);
    } else {
      this.bindExpr(statement.expr, names, effects);
      if (statement.kind === "return" && this.symbols.get(functionId)!.type !== "unknown") this.checkValue(statement.expr.inferredType ?? "unknown", this.symbols.get(functionId)!.type, statement.span, "return");
    }
  }

  private bindExpr(expr: Expr, names: Map<string, ScopedSymbol>, effects: Pick<FunctionInfo, "calls" | "readsState" | "writesState" | "emitsEvent">, writeTarget = false, application?: { arguments: string[]; fold: boolean }, typeReceiver = false): void {
    if (expr.type) expr.type = this.canonicalType(expr.type, names, expr.span);
    if (expr.kind === "lambda" && expr.type) this.requireOrdinary(expr.type, expr.span);
    if (expr.kind === "default" && this.representationOf(expr.type!) === "Kernel") fail("invalid-default-type", "Kernel has no default value", expr.span);
    if (expr.generics) expr.generics = `<${typeArguments(expr.generics).map(type => this.canonicalArgument(type, names, expr.span)).join(",")}>`;
    if (expr.kind === "cast" && this.representationOf(expr.type!) === "Field" && expr.args[0].kind === "literal") {
      const value = naturalValue(expr.args[0].value ?? "");
      if (value !== undefined && value >= UINT_BOUND) {
        if (value >= FIELD_MODULUS) fail("literal-range", "Natural value exceeds the Compact Field range", expr.args[0].span);
        expr.args[0].inferredType = "Field";
        expr.inferredType = expr.type;
        this.checkCast(expr);
        return;
      }
    }
    if (expr.kind === "lambda") {
      const flow = returnFlow(expr.body!);
      const id = this.meteringJoin(this.bindingContext, "::lambda:", this.spanIdentity(expr.span));
      const declaration: Declaration = { kind: "circuit", name: expr.name!, span: expr.span, exported: false, type: expr.type ?? "unknown", parameters: expr.parameters!, body: expr.body };
      const symbol: SymbolInfo = { id, name: expr.name!, kind: "circuit", type: declaration.type, span: expr.span, declaration };
      this.symbols.set(id, symbol);
      expr.symbol = id;
      const local = new Map(names);
      for (const parameter of declaration.parameters) {
        if (!parameter.inferred) parameter.type = this.ordinaryType(parameter.type, names, parameter.span);
        else this.requireOrdinary(parameter.type, parameter.span);
      }
      this.bindParameters(declaration.parameters, local, id);
      const ownEffects = { calls: new Set<string>(), readsState: new Set<string>(), writesState: new Set<string>() };
      this.bindStatement(declaration.body!, local, ownEffects, id);
      const results = flow.returns;
      if (declaration.type === "unknown") {
        declaration.type = this.bodyResultType(declaration.body!);
        if (declaration.type === "unknown") fail("unknown-lambda-type", "Cannot infer a common anonymous-circuit result type", expr.span);
        symbol.type = declaration.type;
        expr.type = declaration.type;
      } else results.forEach(result => this.checkArgument(result.inferredType ?? "unknown", declaration.type, result.span));
      if (flow.fallsThrough) this.checkValue("[]", declaration.type, expr.span, "return");
      this.checkValue(this.bodyResultType(declaration.body!), declaration.type, expr.span, "return");
      this.functions.set(id, { symbol, declaration, cfg: buildCFG(declaration.body!), ...ownEffects });
      expr.inferredType = declaration.type;
      return;
    }
    if (expr.kind === "call" && expr.name === "$anonymous") {
      const argumentsExpr = expr.args.slice(1);
      for (const arg of argumentsExpr) this.bindExpr(arg, names, effects);
      expr.args[0].parameters?.forEach((parameter, index) => { if (parameter.inferred) parameter.type = argumentsExpr[index]?.inferredType ?? "unknown"; });
      this.bindExpr(expr.args[0], names, effects);
      expr.symbol = expr.args[0].symbol;
      expr.args = expr.args.slice(1);
      const symbol = this.symbols.get(expr.symbol!)!;
      if (symbol.declaration!.parameters.length !== expr.args.length) fail("call-arity", `Anonymous circuit expects ${symbol.declaration!.parameters.length} arguments`, expr.span);
      symbol.declaration!.parameters.forEach((parameter, index) => this.checkArgument(expr.args[index].inferredType ?? "unknown", parameter.type, expr.args[index].span));
      effects.calls.add(expr.symbol!);
      expr.inferredType = symbol.type;
      return;
    }
    if (expr.kind === "map" || expr.kind === "fold") {
      for (const arg of expr.args.slice(1)) this.bindExpr(arg, names, effects);
      const sequenceStart = expr.kind === "fold" ? 2 : 1;
      const sequences = expr.args.slice(sequenceStart).map(arg => this.sequenceType(arg.inferredType ?? "unknown", arg.span));
      if (!sequences.length || sequences.some(sequence => sequence.length !== sequences[0].length)) fail("unknown-higher-order-size", "Map/fold requires equally sized sequences", expr.span);
      const argumentTypes = [...(expr.kind === "fold" ? [expr.args[1].inferredType ?? "unknown"] : []), ...sequences.map(sequence => sequence.element)];
      const target = expr.args[0];
      target.parameters?.forEach((parameter, index) => {
        if (parameter.inferred) parameter.type = expr.kind === "fold" && index === 0 && target.type ? this.ordinaryType(target.type, names, target.span) : argumentTypes[index] ?? "unknown";
      });
      this.bindExpr(target, names, effects, false, { arguments: argumentTypes, fold: expr.kind === "fold" });
      effects.calls.add(expr.args[0].symbol!);
      const symbol = this.symbols.get(expr.args[0].symbol!);
      if (!symbol || !["circuit", "witness", "intrinsic"].includes(symbol.kind)) fail("invalid-higher-order-call", "Map/fold target must be a circuit or witness", expr.span);
      const parameters = symbol.kind === "intrinsic" ? this.intrinsicParameters(target, symbol) : symbol.declaration!.parameters.map(parameter => parameter.type);
      if (parameters.length !== argumentTypes.length) fail("call-arity", `Map/fold target expects ${parameters.length} arguments`, expr.span);
      parameters.forEach((type, index) => this.checkArgument(argumentTypes[index], type, expr.span));
      const result = symbol.kind === "intrinsic" ? standardType(intrinsicResult(symbol, expr.args[0].generics, argumentTypes)) : symbol.type;
      if (expr.kind === "fold" && !this.sameType(result, parameters[0])) {
        if (this.containsNominal(result) || this.containsNominal(parameters[0])) fail("nominal-type-mismatch", "Fold requires the same nominal type for its accumulator and result", expr.span);
        fail("fold-type-mismatch", "Fold requires the same accumulator and result type", expr.span);
      }
      if (symbol.kind === "intrinsic") this.checkIntrinsicTypes(symbol, parameters, target.span);
      target.inferredType = result;
      expr.inferredType = expr.kind === "map" ? `Vector<${sequences[0].length},${result}>` : result;
      return;
    }
    if (expr.kind === "ref" || expr.kind === "call") {
      let symbol = names.get(expr.name!);
      if (!symbol && UNMODELED_PROFILE_NATIVES[this.compilerVersion]?.includes(expr.name!))
        fail("unsupported-profile-native", `${expr.name} returns the struct-backed NativePoint of compiler ${this.compilerVersion}; its curve semantics are not modeled`, expr.span);
      if (!symbol) fail("unresolved-symbol", `Cannot resolve ${expr.name}`, expr.span);
      if (symbol.uninitialized) fail("use-before-binding", `Local ${expr.name} is referenced before its initializer`, expr.span);
      if (expr.kind === "ref" && !application && !["ledger", "local", "parameter"].includes(symbol.kind) && !(typeReceiver && symbol.kind === "type")) fail("invalid-value-reference", `${expr.name} is a ${symbol.kind}, not an ordinary value reference`, expr.span);
      if (expr.kind === "call") {
        for (const arg of expr.args) this.bindExpr(arg, names, effects);
        if (symbol.overloads || symbol.functionGroups) symbol = this.selectOverload(symbol, expr, expr.args.map(arg => arg.inferredType ?? "unknown"), false);
      } else if (symbol.overloads || symbol.functionGroups) {
        if (!application) fail("unsupported-overloaded-reference", "Overloaded targets require argument-driven resolution", expr.span);
        symbol = this.selectOverload(symbol, expr, application.arguments, application.fold);
      }
      if ((expr.kind === "call" || expr.kind === "ref" && (expr.generics || application) && ["circuit", "witness"].includes(symbol.kind)) && symbol.kind !== "intrinsic" && (expr.generics || symbol.declaration?.generics)) {
        const genericArgs = typeArguments(expr.generics).map(type => this.canonicalArgument(type, names, expr.span));
        const bindings = genericBindings(symbol.declaration?.generics, genericArgs.length ? `<${genericArgs.join(",")}>` : undefined, expr.span);
        const argumentsList = [...bindings.values()];
        const specializations = this.specializations.get(symbol.id) ?? [];
        let specialized = specializations.find(candidate => this.sameGenericArguments(candidate.arguments, argumentsList))?.symbol;
        const scope = this.functionScopes.get(symbol.id)!;
        if (!specialized) {
          const id = this.meteringJoin(symbol.id, "<", ...argumentsList.flatMap((argument, index) => [index ? "," : "", argument]), ">");
          const declaration = specializeDeclaration(symbol.declaration!, bindings);
          specialized = { ...symbol, id, type: declaration.type, declaration, specializationOrigin: symbol.id };
          specializations.push({ arguments: argumentsList, symbol: specialized });
          this.specializations.set(symbol.id, specializations);
          this.symbols.set(id, specialized);
          this.functionScopes.set(id, scope);
        }
        this.bindFunction(specialized, scope);
        symbol = specialized;
      }
      expr.symbol = symbol.id;
      if (symbol.kind === "circuit" && !symbol.declaration?.generics) this.bindFunction(symbol, this.functionScopes.get(symbol.id)!);
      expr.inferredType = symbol.kind === "ledger" && this.representationOf(symbol.type) === "Counter" ? "Uint<64>" : symbol.type;
      if (symbol.kind === "ledger") { expr.ledgerRoot = symbol.id; expr.ledgerType = symbol.type; }
      if (expr.kind === "call") {
        if (!["circuit", "witness", "intrinsic"].includes(symbol.kind)) fail("invalid-call", `${expr.name} is not callable`, expr.span);
        effects.calls.add(symbol.id);
        const expected = symbol.kind === "intrinsic" ? intrinsicModel(symbol).arity : symbol.declaration!.parameters.length;
        if (expr.args.length !== expected) fail("call-arity", `Expected ${expected} arguments for ${expr.name}`, expr.span);
        if (symbol.kind !== "intrinsic") symbol.declaration!.parameters.forEach((parameter, index) => this.checkArgument(expr.args[index].inferredType ?? "unknown", parameter.type, expr.args[index].span));
        else this.checkIntrinsicArguments(expr, symbol);
      } else if (symbol.kind === "ledger") {
        (writeTarget ? effects.writesState : effects.readsState).add(symbol.id);
      }
    }
    if (expr.kind === "assign") {
      this.bindExpr(expr.args[0], names, effects, true);
      const target = this.symbols.get(expr.args[0].ledgerRoot ?? "");
      const storageType = this.storageType(expr.args[0]);
      if (target?.kind !== "ledger" || !storageType) fail("invalid-assignment", "Assignment target must be a live ledger ADT, not a projected value or snapshot", expr.span);
      const operation = this.ledgerEffect(storageType, expr.name === "=" ? "write" : expr.name === "+=" ? "increment" : "decrement");
      if (!operation) fail("unsupported-state-operation", `No ${expr.name} operation for ${storageType}`, expr.span);
      expr.ledgerRoot = target.id;
      effects.writesState.add(target.id);
      if (operation.reads) effects.readsState.add(target.id);
      this.bindExpr(expr.args[1], names, effects);
      this.checkValue(expr.args[1].inferredType ?? "unknown", operation.parameters[0], expr.args[1].span, "assignment");
      expr.inferredType = "[]";
      return;
    }
    if (expr.kind !== "call") for (let index = 0; index < expr.args.length; index++) {
      const arg = expr.args[index];
      const receiver = index === 0 && expr.kind === "member" && expr.value === "call" && arg.kind === "ref" ? names.get(arg.name!) : undefined;
      const operation = receiver?.kind === "ledger" ? this.ledgerEffect(receiver.type, expr.name!) : undefined;
      this.bindExpr(arg, names, effects, operation?.writes === true && operation.reads === false, undefined, index === 0 && expr.kind === "member" && expr.value !== "call");
    }
    // Like compactc, a ledger ADT operation of the same name takes precedence;
    // otherwise a contract-typed receiver selects its declared interface circuit.
    const storedType = expr.kind === "member" && expr.value === "call" ? this.storageType(expr.args[0]) : undefined;
    const contract = expr.kind === "member" && expr.value === "call" && !(storedType && this.ledgerEffect(storedType, expr.name!))
      ? this.symbols.get(this.representationOf(expr.args[0].inferredType ?? "unknown")) : undefined;
    if (contract?.kind === "type" && contract.declaration?.typeKind === "contract") {
      // A declared external-contract interface types the call. Its callee
      // effects remain unmodeled: dataflow marks every reaching entry incomplete.
      const circuits = contract.declaration.circuits?.filter(circuit => circuit.name === expr.name) ?? [];
      if (circuits.length !== 1) fail("unsupported-contract-call", `No unique declared circuit ${expr.name} on contract ${contract.name}`, expr.span);
      const lexical = this.lexicalNames(this.functionScopes.get(contract.id)!);
      if (expr.args.length !== circuits[0].parameters.length + 1) fail("call-arity", `Expected ${circuits[0].parameters.length} arguments for ${contract.name}.${expr.name}`, expr.span);
      circuits[0].parameters.forEach((parameter, index) => this.checkArgument(expr.args[index + 1].inferredType ?? "unknown", this.ordinaryType(parameter.type, lexical, parameter.span), expr.args[index + 1].span));
      expr.inferredType = this.ordinaryType(circuits[0].type, lexical, circuits[0].span);
      expr.contractCall = { contract: contract.id, circuit: circuits[0].name };
    } else if (expr.kind === "member" && expr.value === "call") {
      const receiver = this.symbols.get(expr.args[0].ledgerRoot ?? "");
      const receiverType = this.storageType(expr.args[0]);
      const operation = receiverType ? this.ledgerEffect(receiverType, expr.name!) : undefined;
      if (!receiver || !operation) fail("unsupported-state-operation", `No effect model for ${receiverType ?? "unknown"}.${expr.name}`, expr.span);
      if (expr.args.length !== operation.arity + 1) fail("call-arity", `Unexpected arguments to ${receiverType}.${expr.name}`, expr.span);
      expr.args.slice(1).forEach((arg, index) => this.checkValue(arg.inferredType ?? "unknown", operation.parameters[index], arg.span, "state-argument"));
      expr.ledgerType = operation.region ? operation.result : undefined;
      expr.inferredType = operation.region && this.representationOf(operation.result) === "Counter" ? "Uint<64>" : operation.result;
      expr.ledgerRoot = receiver.id;
      if (operation.writes) effects.writesState.add(receiver.id);
      if (operation.reads) effects.readsState.add(receiver.id);
    } else if (expr.kind === "member") {
      const receiver = this.symbols.get(expr.args[0].symbol ?? "");
      const receiverType = receiver?.kind === "type" ? this.canonicalType(receiver.id + (expr.args[0].generics ?? ""), names, expr.span) : undefined;
      const enumeration = receiverType ? this.symbols.get(this.representationOf(receiverType)) : undefined;
      if (enumeration?.declaration?.typeKind === "enum" && !enumeration.declaration.variants?.includes(expr.name!)) fail("unknown-enum-member", `Enum ${receiver!.name} has no member ${expr.name}`, expr.span);
      if (enumeration?.declaration?.typeKind === "enum") expr.symbol = enumeration.id;
      expr.inferredType = enumeration?.declaration?.typeKind === "enum" ? receiverType : this.fieldType(expr.args[0].inferredType ?? "unknown", expr.name!);
      if (expr.inferredType === "unknown") fail("unknown-field", `No field ${expr.name} on ${expr.args[0].inferredType ?? "unknown"}`, expr.span);
      expr.ledgerRoot = expr.args[0].ledgerRoot;
    } else if (expr.kind === "struct") {
      const type = parseType(this.underlyingType(expr.type!));
      const expected = this.fieldsOf(expr.type!);
      if (!expected) fail("invalid-struct", `${type.name} is not a struct type`, expr.span);
      expr.symbol = type.name;
      expr.inferredType = expr.type;
      const fields = Object.keys(expected);
      expr.fields = expr.fields!.map((field, index) => field || fields[index] || "");
      if (expr.fields.some(field => !field)) fail("invalid-struct", "Cannot resolve positional struct fields", expr.span);
      const supplied = new Set<string>();
      let spread = false;
      expr.args.forEach((arg, index) => {
        const field = expr.fields![index];
        if (field === "...") {
          if (spread || !this.sameType(arg.inferredType ?? "unknown", expr.type!)) fail("invalid-struct-spread", "Struct spread requires exactly the target struct type and at most one spread", arg.span);
          spread = true;
        } else {
          if (!Object.hasOwn(expected, field) || supplied.has(field)) fail("invalid-struct-field", `Unknown or repeated struct field ${field}`, arg.span);
          supplied.add(field);
          this.checkValue(arg.inferredType ?? "unknown", expected[field], arg.span, "field");
        }
      });
      if (!spread && fields.some(field => !supplied.has(field))) fail("missing-struct-field", "Struct initializer omits required fields", expr.span);
    } else if (expr.kind === "call") {
      const symbol = this.symbols.get(expr.symbol!)!;
      expr.inferredType = symbol.kind === "intrinsic" ? standardType(intrinsicResult(symbol, expr.generics, expr.args.map(arg => arg.inferredType ?? "unknown"))) : symbol.type;
    } else if (expr.kind === "literal") {
      const natural = naturalValue(expr.value ?? "");
      if (natural !== undefined && natural >= FIELD_MODULUS) fail("literal-range", "Natural value exceeds the Compact Field range", expr.span);
      if (natural !== undefined && natural >= UINT_BOUND) fail("literal-type", "A literal above the largest Uint requires a direct cast to Field", expr.span);
      expr.inferredType = ["true", "false"].includes(expr.value!) ? "Boolean" : expr.name === "str" ? `Bytes<${Buffer.byteLength(expr.literalString!)}>` : expr.name === "pad" ? `Bytes<${expr.paddingSize}>` : natural !== undefined ? `Uint<0..${natural + 1n}>` : "unknown";
      if (["str", "pad"].includes(expr.name!)) expr.inferredType = this.canonicalType(expr.inferredType, names, expr.span);
      if (expr.name === "pad" && BigInt(Buffer.byteLength(expr.literalString!)) > naturalValue(expr.paddingSize!)!) fail("invalid-padding", "Decoded UTF-8 string exceeds the requested padding length", expr.span);
    } else if (expr.kind === "bytes") {
      let length = 0;
      for (const arg of expr.args) {
        const type = this.representationOf(arg.inferredType ?? "unknown");
        const term = parseType(type);
        const size = arg.kind === "spread" ? sequenceLength(type) : 1;
        const elements = arg.kind !== "spread" ? [type] : term.name === TUPLE_TYPE ? term.args.map(printType) : [elementType(type)];
        if (size === undefined || elements.some(element => {
          const bound = numericBound(this.representationOf(element));
          return bound === undefined || bound > 256n;
        })) fail("bytes-argument-type", "Bytes construction requires unsigned byte-sized values or sequences of them", arg.span);
        length += size;
      }
      expr.inferredType = this.canonicalType(`Bytes<${length}>`, names, expr.span);
    } else if (expr.kind === "tuple") {
      expr.inferredType = constructionType(expr, this.sequenceTypes());
    } else if (expr.kind === "emit") {
      if (COMPILER_PROFILES[this.compilerVersion].legacy) fail("unsupported-profile-syntax", `emit is unavailable in compiler ${this.compilerVersion}`, expr.span);
      // infer-types.ss strips outer aliases, then compares the event's struct
      // name and exact ordered field types. Same-named user structs can qualify.
      const type = this.underlyingType(expr.args[0].inferredType!);
      const identity = parseType(type).name;
      const name = standardTypeName(identity) ?? this.symbols.get(identity)?.declaration?.name;
      const event = name && Object.hasOwn(STANDARD_EVENTS, name) ? STANDARD_EVENTS[name] : undefined;
      if (!event || !this.sameType(type, this.canonicalType(standardType(name!), names, expr.span))) fail("invalid-event-type", "emit requires a declared standard event with its exact field types", expr.span);
      expr.event = { name: name!, version: EVENT_VERSION, tag: event.tag };
      expr.inferredType = "[]";
      effects.emitsEvent ??= expr.span;
    } else if (["disclose", "spread"].includes(expr.kind)) expr.inferredType = expr.args[0].inferredType;
    else if (["cast", "default"].includes(expr.kind)) {
      if (expr.kind === "cast") this.checkCast(expr);
      expr.inferredType = expr.type;
    }
    else if (["assert", "assign"].includes(expr.kind)) {
      if (expr.kind === "assert") this.checkBoolean(expr.args[0]);
      expr.inferredType = "[]";
    }
    else if (expr.kind === "index" || expr.kind === "slice") expr.inferredType = projectionType(expr, this.sequenceTypes());
    else if (expr.kind === "sequence") expr.inferredType = expr.args.at(-1)?.inferredType ?? "[]";
    else if (expr.kind === "conditional") {
      this.checkBoolean(expr.args[0]);
      const types = expr.args.slice(1).map(arg => arg.inferredType ?? "unknown");
      const common = this.commonType(types);
      if (!common) this.checkNominal(types[0], types[1], expr.span);
      if (!common) fail("conditional-type-mismatch", "Conditional branches must have comparable types", expr.span);
      expr.inferredType = common;
    }
    else if (expr.kind === "unary") {
      this.checkBoolean(expr.args[0]);
      expr.inferredType = "Boolean";
    }
    else if (expr.kind === "binary") {
      const left = expr.args[0].inferredType ?? "unknown";
      const right = expr.args[1].inferredType ?? "unknown";
      if (!["&&", "||", "<", "<=", ">", ">="].includes(expr.name!) && !this.assignable(right, left)) this.checkNominal(left, right, expr.span);
      if (["&&", "||"].includes(expr.name!)) expr.args.forEach(arg => this.checkBoolean(arg));
      if (["==", "!="].includes(expr.name!)) {
        this.requireOrdinary(left, expr.span);
        this.requireOrdinary(right, expr.span);
        if (!this.commonType([left, right])) fail("comparison-type-mismatch", "Equality operands must have comparable ordinary types", expr.span);
        if (this.compilerVersion === "0.30.0" && this.containsOpaque(left, new Set(), "JubjubPoint"))
          fail("unsupported-profile-point-equality", "Compiler 0.30.0 emits reference equality for Jubjub points; this historical evaluation difference is outside the component-equality model", expr.span);
      }
      if (["<", "<=", ">", ">="].includes(expr.name!)) {
        if (!this.orderedTypes(left, right)) fail("comparison-type-mismatch", "Ordering requires unsigned operands with compatible nominal declaration chains", expr.span);
        const first = this.representationOf(left), second = this.representationOf(right);
        // Ordering produces Boolean, but its operands retain integer semantics.
        // A common unsigned domain must include both widths/ranges and strip
        // nominal wrappers only after the compatibility check above.
        expr.numericType = numericBound(first)! >= numericBound(second)! ? first : second;
      }
      if (["+", "-", "*"].includes(expr.name!)) {
        const nominal = this.nominalTypes.has(left) || this.nominalTypes.has(right);
        if (nominal && (!this.sameType(left, right) || !(fieldModulus(this.representationOf(left)) || parseType(this.representationOf(left)).name === "Uint"))) fail("nominal-type-mismatch", "Nominal arithmetic requires the same numeric nominal type on both operands", expr.span);
        const first = this.representationOf(left);
        const second = this.representationOf(right);
        if (![first, second].every(type => fieldModulus(type) || parseType(type).name === "Uint")
          || (foreignField(first) || foreignField(second)) && first !== second) fail("arithmetic-type-mismatch", "Arithmetic requires compatible numeric domains", expr.span);
        const result = foreignField(first) ? standardType(first) : arithmeticType(expr.name!, first, second);
        if ((numericBound(result) ?? 0n) > UINT_BOUND) fail("arithmetic-range", "Arithmetic result might exceed the largest Uint; use an explicit Field operand for Field semantics", expr.span);
        expr.inferredType = nominal ? left : result;
        expr.numericType = this.representationOf(nominal ? left : result);
        expr.checkedArithmetic = nominal && parseType(expr.numericType).name === "Uint";
      } else expr.inferredType = "Boolean";
    }
  }

  private fieldType(type: string, field: string): string {
    return this.fieldsOf(type)?.[field] ?? "unknown";
  }

  fieldsOf(type: string): Record<string, string> | undefined {
    const underlying = this.underlyingType(type);
    const cached = this.resolvedFields.get(underlying);
    if (cached) return cached;
    const term = parseType(underlying);
    const name = standardTypeName(term.name);
    const fields = name ? STANDARD_TYPES[name] : undefined;
    return fields ? Object.fromEntries(Object.entries(fields).map(([field, value]) => [field, standardType(value).replace(/\$(\d+)/g, (_, index) => term.args[Number(index)] ? printType(term.args[Number(index)]) : "unknown")])) : undefined;
  }

  private sequenceTypes() {
    return {
      representationOf: (type: string) => this.representationOf(type),
      commonType: (types: string[]) => this.commonType(types),
      requireOrdinary: (type: string, location: Span) => this.requireOrdinary(type, location),
    };
  }

  private bindParameters(parameters: Parameter[], names: Map<string, SymbolInfo>, functionId: string): void {
    const declared = new Set<string>();
    for (const parameter of parameters) {
      if (declared.has(parameter.name)) fail("duplicate-symbol", `Duplicate parameter ${parameter.name}`, parameter.span);
      declared.add(parameter.name);
      parameter.symbol = this.meteringJoin(functionId, "::parameter:", parameter.name);
      const symbol: SymbolInfo = { id: parameter.symbol, name: parameter.name, kind: "parameter", type: parameter.type, span: parameter.span };
      names.set(parameter.name, symbol);
      this.symbols.set(symbol.id, symbol);
      if (parameter.pattern?.kind === "name") parameter.pattern.symbol = symbol.id;
    }
    const projected = new Set<string>();
    for (const parameter of parameters) if (parameter.pattern && parameter.pattern.kind !== "name") this.bindPattern(parameter.pattern, parameter.type, names, functionId, projected);
  }

  private bindPattern(pattern: Pattern, type: string, names: Map<string, SymbolInfo>, functionId: string, declared = new Set<string>()): void {
    if (pattern.kind === "name") {
      if (declared.has(pattern.name!)) fail("duplicate-symbol", `Duplicate pattern binding ${pattern.name}`, pattern.span);
      declared.add(pattern.name!);
      const id = this.meteringJoin(functionId, "::pattern:", this.spanIdentity(pattern.span), ":", pattern.name!);
      pattern.symbol = id;
      const symbol: SymbolInfo = { id, name: pattern.name!, kind: "local", type, span: pattern.span };
      names.set(symbol.name, symbol);
      this.symbols.set(id, symbol);
    }
    pattern.children.forEach((child, index) => {
      if (child.kind === "skip") return;
      const projected = pattern.kind === "struct" ? this.fieldType(type, pattern.fields![index]) : sequenceElementAt(type, index, child.span, this.sequenceTypes());
      if (projected === "unknown") fail("unknown-field", `No field ${pattern.fields![index]} on ${type}`, child.span);
      this.bindPattern(child, projected, names, functionId, declared);
    });
  }

  private checkEmptyEventArguments(): void {
    // 0.34.0's serializer erases evaluation of zero-byte payload expressions,
    // including their assertions/writes/emissions. Do not silently choose source
    // semantics or the compiler's erased history when they can differ.
    const calls = new Map<string, boolean>();
    const observable = (expr: Expr): boolean => {
      if (expr.args.some(observable)) return true;
      if (expr.kind === "call" && this.functions.has(expr.symbol!)) {
        if (calls.has(expr.symbol!)) return calls.get(expr.symbol!)!;
        calls.set(expr.symbol!, true);
        const fn = this.functions.get(expr.symbol!)!;
        const reachable = fn.cfg.reachableFrom(fn.cfg.entry);
        const result = fn.cfg.nodes.some(node => reachable.has(node.id) && node.expr && observable(node.expr));
        calls.set(expr.symbol!, result);
        return result;
      }
      return operationEffects(expr, this.symbols, false, type => this.representationOf(type), (type, op) => this.ledgerEffect(type, op))
        .some(effect => !["call", "disclosure-permission", "state-address"].includes(effect));
    };
    const check = (expr: Expr): void => {
      if (expr.event && !Object.keys(STANDARD_EVENTS[expr.event.name].fields).length && observable(expr.args[0])) {
        fail("unsupported-empty-event-effects", `compactc ${this.compilerVersion} erases evaluation of empty event payloads; potentially observable argument effects are not qualified`, expr.span);
      }
      expr.args.forEach(check);
    };
    for (const fn of this.functions.values()) if (fn.emitsEvent) for (const node of fn.cfg.nodes) if (node.expr) check(node.expr);
  }

  private propagateEffects(): void {
    let changed = true;
    while (changed) {
      changed = false;
      for (const fn of this.functions.values()) {
        for (const call of fn.calls) {
          const callee = this.functions.get(call);
          if (!callee) continue;
          if (callee.emitsEvent && !fn.emitsEvent) { fn.emitsEvent = callee.emitsEvent; changed = true; }
          for (const key of ["readsState", "writesState"] as const) {
            for (const state of callee[key]) {
              if (!fn[key].has(state)) { fn[key].add(state); changed = true; }
            }
          }
        }
      }
    }
    for (const fn of this.functions.values()) if (fn.emitsEvent) {
      if (fn.declaration.kind === "constructor") fail("constructor-event", "Constructors cannot emit events, directly or through a callee", fn.emitsEvent);
      if (fn.declaration.pure) fail("pure-event", "Pure circuits cannot emit events, directly or through a callee", fn.emitsEvent);
    }
  }
}
