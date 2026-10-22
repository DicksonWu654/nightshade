import type { Expr } from "../model.js";
import { TUPLE_TYPE, elementType, numericBound, parseType, printType, sequenceLength } from "./types.js";
import { foreignField } from "./fields.js";
import type { ZkirVersion } from "./profile.js";

interface CastTypes {
  representationOf(type: string): string;
  assignable(actual: string, expected: string): boolean;
  enumeration(type: string): boolean;
  zkirVersion?: ZkirVersion;
}

export function classifyCast(source: string, target: string, types: CastTypes): Expr["castKind"] {
  const sourceType = types.representationOf(source);
  const targetType = types.representationOf(target);
  if (sourceType === "unknown" || targetType === "unknown") return undefined;
  if (types.assignable(sourceType, targetType)) return "identity";
  const first = parseType(sourceType);
  const second = parseType(targetType);
  if (foreignField(sourceType) || foreignField(targetType)) {
    if (first.name === "Bytes" && sequenceLength(sourceType) === 32 && foreignField(targetType)
      || foreignField(sourceType) && second.name === "Bytes" && sequenceLength(targetType) === 32) return "scalar";
    if (foreignField(targetType) && (first.name === "Boolean" || types.enumeration(sourceType))
      || foreignField(sourceType) && second.name === "Boolean") return "scalar";
    return undefined;
  }
  // ZKIR2 emits identity here; ZKIR3 reduces to a smaller field. Compact's
  // Uint maximum (248 bits) is already below the Jubjub scalar modulus, so
  // Uint conversions remain value preserving in both profiles.
  if (types.zkirVersion === 3 && first.name === "Field" && second.name === "JubjubScalar") return "scalar";
  const numeric = (name: string): boolean => ["Field", "Uint", "JubjubScalar"].includes(name);
  if (numeric(first.name) && numeric(second.name)) return "numeric";
  if (first.name === "Boolean" && numeric(second.name) || numeric(first.name) && second.name === "Boolean") return "scalar";
  if (types.enumeration(sourceType) && numeric(second.name) || numeric(first.name) && types.enumeration(targetType)) return "scalar";
  if (["Field", "Uint"].includes(first.name) && second.name === "Bytes" && sequenceLength(targetType)! > 0 || first.name === "Bytes" && sequenceLength(sourceType)! > 0 && ["Field", "Uint"].includes(second.name)) return "scalar";
  const elementsSatisfy = (type: string, predicate: (element: string) => boolean): boolean => {
    const term = parseType(type);
    return term.name === TUPLE_TYPE ? term.args.every(element => predicate(types.representationOf(printType(element)))) : term.name === "Vector" && predicate(types.representationOf(elementType(type)));
  };
  if (sequenceLength(sourceType) !== sequenceLength(targetType)) return undefined;
  if (first.name === "Bytes" && elementsSatisfy(targetType, element => ["Field", "JubjubScalar"].includes(element) || numericBound(element) !== undefined && numericBound(element)! >= 256n)) return "bytes-to-sequence";
  if (second.name === "Bytes" && elementsSatisfy(sourceType, element => numericBound(element) !== undefined && numericBound(element)! <= 256n)) return "sequence-to-bytes";
  return undefined;
}
