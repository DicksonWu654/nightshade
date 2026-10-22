import { FIELD_MODULUS } from "./types.js";

// compactc-v0.34.0 compiler/field.ss (max-* definitions plus one).
export const SECP256K1_BASE_MODULUS = (1n << 256n) - (1n << 32n) - 977n;
export const SECP256K1_SCALAR_MODULUS = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const JUBJUB_SCALAR_MODULUS = 0xe7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7n;

export const foreignField = (type: string): boolean => ["Secp256k1Base", "Secp256k1Scalar"].includes(type.replace(/^standard-type::/, ""));

/** Arithmetic fields only: binary arithmetic on JubjubScalar is illegal. */
export function fieldModulus(type: string): bigint | undefined {
  switch (type.replace(/^standard-type::/, "")) {
    case "Field": return FIELD_MODULUS;
    case "Secp256k1Base": return SECP256K1_BASE_MODULUS;
    case "Secp256k1Scalar": return SECP256K1_SCALAR_MODULUS;
    default: return undefined;
  }
}
