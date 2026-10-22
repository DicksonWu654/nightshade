import { Span, fail } from "../model.js";
import type { SymbolInfo } from "./index.js";
import { STANDARD_TYPES, STANDARD_TYPE_MODELS, standardType, standardTypeName } from "./intrinsics.js";
import { FIELD_MODULUS, TUPLE_TYPE, naturalValue, parseType, printType, typeArguments } from "./types.js";

import { opaqueJubjubProfile, profileNumericTypeError, type CompilerVersion } from "./profile.js";

interface SchemaType {
  ledger?: string;
}

type Binding =
  | { kind: "free" }
  | { kind: "natural"; value: bigint }
  | { kind: "type"; type: SchemaType };

interface Environment {
  owner: SymbolInfo;
  bindings: Map<string, Binding>;
}

export class TypeExportValidator {
  private steps = 0;

  constructor(private readonly lookup: (owner: SymbolInfo, name: string) => SymbolInfo | undefined, private readonly compilerVersion: CompilerVersion = "0.34.0") {}

  validate(symbol: SymbolInfo): void {
    const native = standardTypeName(symbol.id);
    if (native && !Object.hasOwn(STANDARD_TYPES, native) && !(native === "JubjubPoint" && opaqueJubjubProfile(this.compilerVersion))) fail("invalid-type-export", `Cannot export native or ledger type ${symbol.name} directly from an application`, symbol.span);
    const parameters = typeArguments(native ? STANDARD_TYPE_MODELS[native].generics : symbol.declaration?.generics);
    this.ordinary(this.apply(symbol, parameters.map(() => ({ kind: "free" })), symbol.span, 0), symbol.span);
  }

  private ordinary(type: SchemaType, location: Span): SchemaType {
    if (type.ledger) fail("ledger-type-context", `Ledger ADT ${type.ledger} is not an ordinary exported value type`, location);
    return type;
  }

  private budget(location: Span, depth: number): void {
    if (depth > 32) fail("type-depth", "Recursive or excessively deep exported type schema", location);
    if (++this.steps > 4096) fail("type-budget", "Exported type schemas exceed 4096 validation steps", location);
  }

  private apply(symbol: SymbolInfo, args: Binding[], location: Span, depth: number): SchemaType {
    this.budget(location, depth);
    const native = standardTypeName(symbol.id);
    const model = native ? STANDARD_TYPE_MODELS[native] : undefined;
    const parameters = typeArguments(model ? model.generics : symbol.declaration?.generics);
    if (parameters.length !== args.length) fail("generic-arity", `Expected ${parameters.length} generic arguments, received ${args.length}`, location);
    const bindings = new Map<string, Binding>();
    parameters.forEach((parameter, index) => {
      const name = parameter.replace(/^#\s*/, "");
      if (bindings.has(name)) fail("duplicate-generic-parameter", `Duplicate generic parameter ${name}`, symbol.span);
      const argument = args[index];
      if (argument.kind !== "free" && parameter.startsWith("#") !== (argument.kind === "natural")) fail("generic-kind", `Generic argument for ${parameter} must be ${parameter.startsWith("#") ? "a natural number" : "a type"}`, location);
      bindings.set(name, argument);
    });
    const environment = { owner: symbol, bindings };
    if (native && model) {
      for (const index of model.ordinaryArguments ?? []) {
        const argument = args[index];
        if (argument.kind === "type") this.ordinary(argument.type, location);
      }
      if (model.ledger && args.some(argument => argument.kind === "type" && argument.type.ledger === "Kernel")) fail("nested-kernel-type", "Kernel cannot be nested within a ledger ADT", location);
      if (["MerkleTree", "HistoricMerkleTree"].includes(native)) {
        const argument = args[0];
        if (argument.kind !== "natural" || argument.value < 2n || argument.value > 32n) fail("invalid-merkle-depth", "Merkle tree depth must be between 2 and 32", location);
      }
      args.forEach((argument, index) => bindings.set(`$${index}`, argument));
      for (const field of Object.values(STANDARD_TYPES[native] ?? {})) this.ordinary(this.type(standardType(field), environment, location, depth + 1), location);
      return model.ledger ? { ledger: native } : {};
    }
    const declaration = symbol.declaration;
    if (!declaration) fail("unresolved-type", `No type model for ${symbol.name}`, location);
    if (declaration.typeKind === "alias") return this.type(declaration.type, environment, location, depth + 1);
    if (declaration.typeKind === "struct") {
      for (const field of declaration.parameters) this.ordinary(this.type(field.type, environment, field.span, depth + 1), field.span);
      return {};
    }
    if (declaration.typeKind === "enum") return {};
    fail("unsupported-type-export", `No export schema model for ${symbol.name}`, location);
  }

  private size(text: string, environment: Environment, location: Span, erased: bigint): bigint {
    const natural = naturalValue(text);
    if (natural !== undefined) return natural;
    const binding = environment.bindings.get(text);
    if (binding?.kind === "natural") return binding.value;
    if (binding?.kind === "free") return erased;
    fail("invalid-numeric-type", `Expected a natural size or a free export parameter, received ${text}`, location);
  }

  private argument(text: string, environment: Environment, location: Span, depth: number): Binding {
    const natural = naturalValue(text);
    if (natural !== undefined) {
      if (natural >= FIELD_MODULUS) fail("literal-range", "Natural value exceeds the Compact Field range", location);
      return { kind: "natural", value: natural };
    }
    const bound = environment.bindings.get(text);
    if (bound?.kind === "natural") return bound;
    return { kind: "type", type: this.type(text, environment, location, depth) };
  }

  private type(text: string, environment: Environment, location: Span, depth: number): SchemaType {
    this.budget(location, depth);
    const term = parseType(text);
    if (["Field", "Boolean"].includes(term.name) || this.compilerVersion === "0.33.0-rc.2" && term.name === "JubjubScalar") {
      if (term.args.length) fail("generic-arity", `${term.name} takes no generic arguments`, location);
      return {};
    }
    if (["Uint", "Bytes", "Vector", TUPLE_TYPE].includes(term.name)) {
      const sized = structuredClone(term);
      if (sized.args[0] && term.name !== TUPLE_TYPE) {
        const size = printType(sized.args[0]);
        const range = term.name === "Uint" ? /^([^.]*)\.\.([^.]*)$/.exec(size) : undefined;
        sized.args[0] = parseType(range
          ? `${this.size(range[1], environment, location, 0n)}..${this.size(range[2], environment, location, 1n)}`
          : this.size(size, environment, location, 1n).toString());
      }
      const error = profileNumericTypeError(sized, this.compilerVersion);
      if (error) fail("invalid-numeric-type", error, location);
      const elements = term.name === "Vector" ? term.args.slice(1) : term.name === TUPLE_TYPE ? term.args : [];
      for (const element of elements) this.ordinary(this.type(printType(element), environment, location, depth + 1), location);
      return {};
    }
    if (term.name === "Opaque") {
      if (term.args.length !== 1) fail("generic-arity", "Opaque requires one string argument", location);
      if (!/^"(string|Uint8Array)"$/.test(printType(term.args[0])) && !(opaqueJubjubProfile(this.compilerVersion) && printType(term.args[0]) === '"JubjubPoint"')) fail("unsupported-opaque-type", "Only Opaque string and Uint8Array kinds are supported", location);
      return {};
    }
    const args = term.args.map(argument => this.argument(printType(argument), environment, location, depth + 1));
    const bound = environment.bindings.get(term.name);
    if (bound) {
      if (args.length) fail("generic-arity", `${term.name} takes no generic arguments`, location);
      if (bound.kind === "natural") fail("invalid-type-context", `${term.name} is a natural value, not a type`, location);
      return bound.kind === "free" ? {} : bound.type;
    }
    const native = standardTypeName(term.name);
    const symbol = native ? { id: term.name, name: native, kind: "type" as const, type: term.name, span: location } : this.lookup(environment.owner, term.name);
    if (!symbol) fail("unresolved-type", `Unknown type ${term.name}`, location);
    if (symbol.kind !== "type") fail("invalid-type-context", `${term.name} is bound to a ${symbol.kind}, not a type`, location);
    return this.apply(symbol, args, location, depth);
  }
}
