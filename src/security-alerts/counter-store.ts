/**
 * Fixed-window counter scoped by key. Returns the value after the increment so
 * "fire once per window" needs a single round trip (`count === threshold`).
 */
export interface CounterStore {
  incr(key: string, windowSeconds: number): Promise<number>;
}

export const COUNTER_STORE = Symbol('COUNTER_STORE');
