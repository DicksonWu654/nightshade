import { createHash } from "node:crypto";
import type { Span } from "../model.js";
import { fieldModulus, JUBJUB_SCALAR_MODULUS } from "../semantic/fields.js";
import type { AbstractValue } from "./index.js";
import { assumeScalar, binaryValue, combine, constantOf, refineScalar, step, valueIdentity, type ScalarConstraints } from "./transfers.js";

/** Native point identity is an atom, not a user-visible struct layout. */
export function pointIdentity(type: string): AbstractValue {
  return { flows: [], ledger: new Set(), type, constantKind: "point", constant: `${type}:identity` };
}

/** Only deterministic native/cast/arithmetic operations use this key. hashToCurve is excluded. */
export function nativeIdentity(operation: string, values: AbstractValue[], fresh: () => string): string {
  const keys = values.map(value => {
    const constant = constantOf(value);
    return constant ? ["constant", constant.kind, constant.value] : valueIdentity(value) ? ["value", valueIdentity(value)] : undefined;
  });
  return keys.every(key => key !== undefined)
    ? `native:${createHash("sha256").update(JSON.stringify([operation, keys])).digest("hex")}` : fresh();
}

function inverse(value: bigint, modulus: bigint): bigint {
  // All supported moduli are prime; bounded by the 256-bit exponent.
  let result = 1n, power = value, exponent = modulus - 2n;
  while (exponent) {
    if (exponent & 1n) result = result * power % modulus;
    power = power * power % modulus;
    exponent >>= 1n;
  }
  return result;
}

/** Shared by both execution engines. Undefined is a definite native rejection.
 * Unknown crypto outputs remain abstract; this is not curve execution/proving. */
export function nativeValue(key: string, type: string, inputs: AbstractValue[], location: Span, state: ScalarConstraints, fresh: () => string, observePointIdentity = false, observeNonidentityOutput = false): AbstractValue | undefined {
  const values = inputs.map(value => refineScalar(value, state));
  const name = key.split(":")[0];
  let result: AbstractValue = { ...step(combine(values), "transform", name, location, "derived"), ledger: new Set(), type,
    identity: name === "hashToCurve" ? fresh() : nativeIdentity(key, values, fresh) };
  const integer = (value: bigint): AbstractValue => ({ flows: [], ledger: new Set(), constantKind: "integer", constant: String(value) });
  const isEqual = (first: AbstractValue, second: AbstractValue): boolean | undefined => {
    const compared = refineScalar(binaryValue([first, second], "==", location, "Boolean")!, state);
    return compared.constantKind === "boolean" ? compared.constant === "true" : undefined;
  };
  const requireUnequal = (first: AbstractValue, second: AbstractValue): boolean => assumeScalar(binaryValue([first, second], "!=", location, "Boolean")!, true, state);
  const copyAtom = (value: AbstractValue): AbstractValue => ({ ...result, identity: value.identity, constant: value.constant, constantKind: value.constantKind });
  if (name === "inv" || name === "neg") {
    const modulus = fieldModulus(type)!;
    if (name === "inv" && !requireUnequal(values[0], integer(0n))) return undefined;
    if (values[0].constantKind === "integer") {
      const value = BigInt(values[0].constant!);
      result = { ...result, constantKind: "integer", constant: String(name === "neg" ? (modulus - value) % modulus : inverse(value, modulus)) };
    }
    if (name === "inv" && !requireUnequal(result, integer(0n))) return undefined;
  } else if (["secp256k1PointX", "secp256k1PointY"].includes(name)) {
    if (!requireUnequal(values[0], pointIdentity("Secp256k1Point"))) return undefined;
  } else if (["jubjubPointX", "jubjubPointY"].includes(name)) {
    if (isEqual(values[0], pointIdentity("JubjubPoint")) === true) result = { ...result, constantKind: "integer", constant: name === "jubjubPointX" ? "0" : "1" };
  } else if (name === "constructJubjubPoint") {
    // Only the known neutral point is classified. Arbitrary coordinates do not
    // establish curve membership, even though the JS runtime packages them.
    if (isEqual(values[0], integer(0n)) === true && isEqual(values[1], integer(1n)) === true) result = copyAtom(pointIdentity("JubjubPoint"));
  } else if (name === "ecNeg") {
    const identity = pointIdentity(type);
    if (isEqual(values[0], identity) === true) result = copyAtom(identity);
  } else if (name === "ecAdd") {
    const identity = pointIdentity(type);
    if (isEqual(values[0], identity) === true) result = copyAtom(values[1]);
    else if (isEqual(values[1], identity) === true) result = copyAtom(values[0]);
  } else if (name === "ecMul" || name === "ecMulGenerator") {
    const identity = pointIdentity(type), scalar = values.at(-1)!;
    const reduced = scalar.constantKind === "integer" && type === "JubjubPoint" ? integer(BigInt(scalar.constant!) % JUBJUB_SCALAR_MODULUS) : scalar;
    const zero = isEqual(reduced, integer(0n));
    if (zero === true || name === "ecMul" && isEqual(values[0], identity) === true) result = copyAtom(identity);
    else if (name === "ecMul" && isEqual(reduced, integer(1n)) === true) result = copyAtom(values[0]);
    else if (name === "ecMulGenerator" && zero === false && (type === "Secp256k1Point" || scalar.constantKind === "integer")) {
      if (!requireUnequal(result, identity)) return undefined;
      if (observeNonidentityOutput) result = { ...result, pointIdentityExcluded: true };
    }
  }
  if (observePointIdentity && ["ecMul", "ecNeg"].includes(name) && ["JubjubPoint", "Secp256k1Point"].includes(type)) {
    const depth = (values[0].pointIdentityDepth ?? 0) + 1;
    result = values[0].pointIdentityEvidenceLost || depth > 32
      ? { ...result, pointIdentityEvidenceLost: true }
      : { ...result, pointIdentityInput: values[0], pointIdentityDepth: depth };
  }
  return refineScalar(result, state);
}
