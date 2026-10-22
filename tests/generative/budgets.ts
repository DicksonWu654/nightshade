export interface CheckBudgets { maxSteps: number; maxPaths: number; maxValues: number }

// Pin the harness limits independently of future Dataflow constructor defaults.
// Replay always supplies every value, including comparisons with another build.
export const DEFAULT_CHECK_BUDGETS: Readonly<CheckBudgets> = Object.freeze({ maxSteps: 20000, maxPaths: 256, maxValues: 50000 });

export function effectiveBudgets(value: Partial<CheckBudgets> = {}): CheckBudgets {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(key => !Object.hasOwn(DEFAULT_CHECK_BUDGETS, key))) throw new Error("Invalid generated-test analysis budgets");
  const result = { ...DEFAULT_CHECK_BUDGETS, ...value };
  for (const budget of Object.values(result)) if (!Number.isSafeInteger(budget) || budget < 1 || budget > 1_000_000) throw new Error("Invalid generated-test analysis budget");
  return result;
}
