/** Identity accounting uses compilation-local pathname tokens. The original
 * identity remains the equality/cache key and the original Span is reported. */
export type IdentityText = ((identity: string) => string) & {
  pathText?: (path: string) => string;
  reportText?: (identity: string) => string;
  rememberReport?: (raw: string, companion: string) => string;
};

/** Companion recipes visit only owned identity slots. Constants and labels
 * must be supplied literally by the constructor, never searched/replaced. */
export function reportIdentity(identity: string, text?: IdentityText): string {
  return text?.reportText?.(identity) ?? text?.(identity) ?? identity;
}
export function rememberReportIdentity(raw: string, companion: string, text?: IdentityText): string {
  return text?.rememberReport?.(raw, companion) ?? raw;
}

export type IdentityMeter<R = boolean> = ((work: number, values: number) => R) & {
  identityText?: IdentityText;
};

export function identityText(identity: string, meter?: IdentityMeter<any>): string {
  return meter?.identityText?.(identity) ?? identity;
}

export function identityLength(identity: string | undefined, meter?: IdentityMeter<any>): number {
  return identityText(identity ?? "", meter).length;
}

export function withIdentityMeter<T extends (...args: any[]) => any>(
  identityText: ((identity: string) => string) | undefined, meter: T,
): T & Pick<IdentityMeter, "identityText"> {
  return Object.assign(meter, { identityText });
}

/** Adapt a callback without discarding the accounting context carried by its
 * parent. Use this for wrappers passed to identity-aware downstream helpers. */
export function wrapIdentityMeter<T extends (...args: any[]) => any>(
  parent: IdentityMeter<any> | undefined, meter: T,
): T & Pick<IdentityMeter, "identityText"> {
  return withIdentityMeter(parent?.identityText, meter);
}

/** File positions are explicit, including when a physical filename spells an
 * entire unrelated compiler symbol identity. */
export function pathLength(path: string, meter?: IdentityMeter<any>): number {
  return (meter?.identityText?.pathText?.(path) ?? path).length;
}
