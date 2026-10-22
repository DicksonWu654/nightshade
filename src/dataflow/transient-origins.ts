import type { AbstractValue } from "./index.js";
import { spanId, type Span } from "../model.js";

/** Syntactic data derivation, never scalar equality or control dependence. */
export interface TransientOrigin {
  primitive: "transientHash" | "transientCommit";
  location: Span;
}
export const MAX_TRANSIENT_ORIGINS = 128;

export function transientDependencies(values: readonly AbstractValue[]): Pick<AbstractValue, "transientOrigins" | "transientOriginsUnavailable"> {
  if (!values.some(value => value.transientOrigins?.length || value.transientOriginsUnavailable)) return {};
  const origins = new Map<string, TransientOrigin>();
  for (const value of values) {
    if (value.transientOriginsUnavailable) return { transientOriginsUnavailable: true };
    for (const origin of value.transientOrigins ?? []) {
      origins.set(`${origin.primitive}:${spanId(origin.location)}`, origin);
      if (origins.size > MAX_TRANSIENT_ORIGINS) return { transientOriginsUnavailable: true };
    }
  }
  return { transientOrigins: [...origins.values()] };
}

/** A may-alias/alternative value cannot establish an exact data derivation. */
export function uncertainTransientDependencies(values: readonly AbstractValue[]): Pick<AbstractValue, "transientOriginsUnavailable"> {
  return values.some(value => value.transientOrigins?.length || value.transientOriginsUnavailable) ? { transientOriginsUnavailable: true } : {};
}
