import type { AbstractValue } from "./index.js";
import type { Span } from "../model.js";

/** Receiver-specific selections; dependencies alone never prove a receiver tag. */
export interface EitherPayloadRead {
  id: string;
  arm: "left" | "right";
  tag: AbstractValue;
  location: Span;
  callPath: string[];
  callSites: Span[];
}

export const MAX_EITHER_READS = 256;

/** Evidence is optional and bounded separately from ordinary provenance. */
export function payloadDependencies(values: readonly AbstractValue[]): Pick<AbstractValue, "eitherPayloads" | "eitherControls" | "eitherEvidenceLost"> {
  if (!values.some(value => value.eitherPayloads || value.eitherControls || value.eitherEvidenceLost)) return {};
  const ids = new Set<string>(), controls = new Map<string, NonNullable<AbstractValue["eitherControls"]>[number]>();
  for (const value of values) {
    for (const id of value.eitherPayloads ?? []) { ids.add(id); if (ids.size > MAX_EITHER_READS) return { eitherEvidenceLost: true }; }
    for (const control of value.eitherControls ?? []) {
      controls.set(JSON.stringify(control), control);
      if (controls.size > MAX_EITHER_READS) return { eitherEvidenceLost: true };
    }
  }
  return { ...(ids.size ? { eitherPayloads: [...ids] } : {}), ...(controls.size ? { eitherControls: [...controls.values()] } : {}),
    ...(values.some(value => value.eitherEvidenceLost) ? { eitherEvidenceLost: true as const } : {}) };
}

/** Selecting an aggregate arm also selects its descendants. Charge every node. */
export function markPayload(value: AbstractValue, id: string, charge: () => boolean, depth = 0): AbstractValue {
  if (depth > 64 || !charge()) return { ...value, eitherEvidenceLost: true };
  const marked: AbstractValue = { ...value, ...payloadDependencies([value, { flows: [], ledger: new Set(), eitherPayloads: [id] }]),
    eitherSelection: id,
    ...(value.items ? { items: value.items.map(item => markPayload(item, id, charge, depth + 1)) } : {}),
    ...(value.fields ? { fields: Object.fromEntries(Object.entries(value.fields).map(([key, field]) => [key, markPayload(field, id, charge, depth + 1)])) } : {}) };
  if (marked.items?.some(item => item.eitherEvidenceLost) || marked.fields && Object.values(marked.fields).some(field => field.eitherEvidenceLost)) marked.eitherEvidenceLost = true;
  return marked;
}

/** An untransformed arm copied into an explicit native Either construction is
 * a new receiver choice. Remove only that direct selection, not dependencies
 * from computations or other selections. The original snapshot stays intact. */
export function reconstructedPayload(value: AbstractValue, charge: () => boolean): AbstractValue {
  const id = value.eitherSelection;
  if (!id) return value;
  const remove = (part: AbstractValue, depth: number): AbstractValue => {
    if (depth > 64 || !charge()) return { ...part, eitherEvidenceLost: true };
    return { ...part, eitherPayloads: part.eitherPayloads?.filter(item => item !== id), eitherSelection: undefined,
      ...(part.items ? { items: part.items.map(item => remove(item, depth + 1)) } : {}),
      ...(part.fields ? { fields: Object.fromEntries(Object.entries(part.fields).map(([key, field]) => [key, remove(field, depth + 1)])) } : {}) };
  };
  return remove(value, 0);
}
