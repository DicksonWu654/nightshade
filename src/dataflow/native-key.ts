import type { AbstractValue, PrivateSource } from "./index.js";
import { rawWitnessSources } from "./predicates.js";
import { OWN_PUBLIC_KEY } from "../semantic/native-key-targets.js";
/** Traverse represented exact input snapshots, never dependency unions. */
export function nativeKeyIngredients(value: AbstractValue, charge: (work?: number) => void) {
  const native: PrivateSource[] = [], secret: PrivateSource[] = [];
  let complete = true;
  const visit = (value: AbstractValue, depth: number) => {
    charge();
    if (depth > 64) { complete = false; return; }
    if (value.fields || value.items) {
      for (const part of value.items ?? Object.values(value.fields!)) visit(part, depth + 1);
      return;
    }
    for (const source of rawWitnessSources(value)) {
      charge();
      if (source.symbol === OWN_PUBLIC_KEY && value.type === "Bytes<32>") native.push(source);
      else if (source.symbol && !source.symbol.startsWith("intrinsic::")) secret.push(source);
    }
  };
  visit(value, 0);
  return { native, secret, complete };
}
