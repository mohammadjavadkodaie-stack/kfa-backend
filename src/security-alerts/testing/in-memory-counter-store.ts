import type { CounterStore } from '../counter-store';

interface Bucket {
  windowStart: number;
  count: number;
}

/**
 * Test double only: per-process state, no locking, no eviction. The application
 * uses a shared (Redis) store so limits hold across instances.
 */
export class InMemoryCounterStore implements CounterStore {
  private readonly buckets = new Map<string, Bucket>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  async incr(key: string, windowSeconds: number): Promise<number> {
    const windowMs = windowSeconds * 1000;
    const nowMs = this.now();
    const bucket = this.buckets.get(key);

    if (!bucket || nowMs - bucket.windowStart >= windowMs) {
      this.buckets.set(key, { windowStart: nowMs, count: 1 });
      return 1;
    }

    bucket.count += 1;
    return bucket.count;
  }
}
