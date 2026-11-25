import { RECORD_KNOWN_COUNTRY_SCRIPT, RedisKnownCountryStore } from './redis-known-country-store';

describe('RedisKnownCountryStore', () => {
  it('records and checks with one atomic script call', async () => {
    const evalCall = jest.fn().mockResolvedValue(['1', '0']);
    const store = new RedisKnownCountryStore({ eval: evalCall } as never);

    await expect(store.recordAndCheck('user-1', 'DE')).resolves.toEqual({
      isNew: true,
      hadAny: false,
    });

    expect(evalCall).toHaveBeenCalledWith(
      RECORD_KNOWN_COUNTRY_SCRIPT,
      1,
      'known-countries:user-1',
      'DE',
      String(400 * 24 * 60 * 60),
      '20',
    );
  });

  it('propagates Redis errors', async () => {
    const error = new Error('redis down');
    const store = new RedisKnownCountryStore({ eval: jest.fn().mockRejectedValue(error) } as never);

    await expect(store.recordAndCheck('user-1', 'DE')).rejects.toBe(error);
  });
});
