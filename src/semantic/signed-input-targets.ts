import type { Program } from "./index.js";

export const SIGNED_COIN_SEND = "standard-library::sendShielded";
export const ECDSA_VERIFIER = "standard-library::secp256k1EcdsaVerify";

/** Generic observations retain canonical send operands without recognizing
 * application namesakes or introducing another transfer implementation. */
export function signedInputTargets(program: Program): Set<string> {
  return new Set([SIGNED_COIN_SEND, ECDSA_VERIFIER].filter(id => program.functions.has(id)));
}
