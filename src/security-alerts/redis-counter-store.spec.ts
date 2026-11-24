import { INCREMENT_SECURITY_ALERT_COUNTER_SCRIPT, RedisCounterStore } from './redis-counter-store';

describe('RedisCounterStore', () => {
  it('increments with one script call', async () => {
    const evalCall = jest.fn().mockResolvedValue('3');
    const store = new RedisCounterStore({ eval: evalCall } as never);

    await expect(store.incr('user-1', 60)).resolves.toBe(3);

    expect(evalCall).toHaveBeenCalledTimes(1);
    expect(evalCall).toHaveBeenCalledWith(
      INCREMENT_SECURITY_ALERT_COUNTER_SCRIPT,
      1,
      expect.stringMatching(/^kfa:rl:security-alert:/),
      '60',
    );
  });

  it('rejects an invalid window', async () => {
    const evalCall = jest.fn();
    const store = new RedisCounterStore({ eval: evalCall } as never);

    await expect(store.incr('key', 0)).rejects.toThrow('positive integer');
    expect(evalCall).not.toHaveBeenCalled();
  });

  it('propagates Redis errors', async () => {
    const error = new Error('redis down');
    const store = new RedisCounterStore({ eval: jest.fn().mockRejectedValue(error) } as never);

    await expect(store.incr('key', 60)).rejects.toBe(error);
  });
});
