import type { Program } from "./index.js";
import { parseType, printType } from "./types.js";
export const MEMBERSHIP_IDENTITY_RULE = "membership-identity-binding-review";

type Charge = (work: number, values: number) => boolean;

/** Native identity follows imported/nominal aliases. Representation supplies
 * arguments only after that identity is established; user lookalikes cannot
 * supply a native collection identity merely through their spelling. */
function nativeArguments(program: Program, type: string | undefined, native: string, charge: Charge): string[] | undefined {
  if (!type) return;
  if (!charge(1, 1 + Math.ceil(program.meteringIdentity(type).length / 64))) return;
  if (program.nativeTypeOf(type) !== native) return;
  const represented = program.representationOf(type);
  if (!charge(1, 2 + Math.ceil(program.meteringIdentity(represented).length / 64))) return;
  const args = parseType(represented).args;
  if (!charge(args.length, args.length)) return;
  return args.map(printType);
}
function bytes32(program: Program, type: string, charge: Charge): boolean {
  if (!charge(1, 1 + Math.ceil(program.meteringIdentity(type).length / 64))) return false;
  const represented = program.representationOf(type);
  if (!charge(1, 1 + Math.ceil(program.meteringIdentity(represented).length / 64))) return false;
  return represented === "Bytes<32>";
}
export function membershipIdentityList(program: Program, type: string | undefined, charge: Charge): boolean {
  const args = nativeArguments(program, type, "List", charge);
  return !!args && args.length === 1 && bytes32(program, args[0], charge);
}
export function membershipIdentitySet(program: Program, type: string | undefined, charge: Charge): boolean {
  const args = nativeArguments(program, type, "Set", charge);
  return !!args && args.length === 1 && bytes32(program, args[0], charge);
}
export function membershipIdentityMap(program: Program, ledger: string, beforeType: string | undefined, charge: Charge): boolean {
  const args = nativeArguments(program, program.symbols.get(ledger)?.type, "Map", charge);
  return !!args && args.length === 2 && bytes32(program, args[0], charge)
    && membershipIdentityList(program, args[1], charge) && membershipIdentityList(program, beforeType, charge);
}
