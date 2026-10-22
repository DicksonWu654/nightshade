export type GuardProfile = readonly ReadonlySet<string>[];

export function guardsCover(weaker: GuardProfile, stronger: GuardProfile): boolean {
  return weaker.length === stronger.length && weaker.every((guards, index) => guards.size <= stronger[index].size && [...guards].every(guard => stronger[index].has(guard)));
}

export class GuardCover {
  private readonly profiles = new Map<string, GuardProfile[]>();
  private entries = 0;
  private facts = 0;

  constructor(readonly maxEntries = 256, readonly maxFacts = 4096) {}

  covered(key: string, candidate: GuardProfile): boolean {
    const previous = this.profiles.get(key) ?? [];
    if (previous.some(profile => guardsCover(profile, candidate))) return true;
    const retained = previous.filter(profile => !guardsCover(candidate, profile));
    const weight = (profile: GuardProfile): number => profile.reduce((total, guards) => total + 1 + guards.size, 0);
    const entries = this.entries - previous.length + retained.length + 1;
    const facts = this.facts - previous.reduce((total, profile) => total + weight(profile), 0) + retained.reduce((total, profile) => total + weight(profile), 0) + weight(candidate);
    if (entries <= this.maxEntries && facts <= this.maxFacts) {
      this.profiles.set(key, [...retained, candidate.map(guards => new Set(guards))]);
      this.entries = entries;
      this.facts = facts;
    }
    return false;
  }
}
