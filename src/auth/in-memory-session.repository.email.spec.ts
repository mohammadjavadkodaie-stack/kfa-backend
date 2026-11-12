import { Role } from './roles';
import { InMemorySessionRepository } from './in-memory-session.repository';

describe('InMemorySessionRepository email account contract', () => {
  it('stores email identity fields and returns the account projection', async () => {
    const repository = new InMemorySessionRepository();
    const now = new Date('2026-03-01T00:00:00.000Z');

    const created = await repository.createAccountWithEmail({
      userId: 'user-1',
      phone: null,
      email: 'ivan@example.com',
      username: 'ivan',
      passwordHash: 'scrypt-hash',
      emailVerifiedAt: now,
      deviceKeyHash: 'device-hash',
      deviceBound: true,
      deviceLabel: 'Phone',
      now,
      sessionExpiresAt: new Date(now.getTime() + 86_400_000),
      refreshTokenHash: 'refresh-hash',
      refreshExpiresAt: new Date(now.getTime() + 86_400_000),
    });

    expect('outcome' in created).toBe(false);
    expect(await repository.findUserByEmail('ivan@example.com')).toEqual({
      id: 'user-1',
      username: 'ivan',
      role: Role.USER,
      status: 'ACTIVE',
      passwordHash: 'scrypt-hash',
      emailVerifiedAt: now,
    });
    expect(await repository.isKnownDevice('user-1', 'device-hash')).toBe(true);

    await repository.updatePasswordHash('user-1', 'new-hash');
    expect((await repository.findUserByEmail('ivan@example.com'))?.passwordHash).toBe('new-hash');
  });

  it('returns one generic conflict result for email or username uniqueness', async () => {
    const repository = new InMemorySessionRepository();
    repository.seedUser({ id: 'user-1', phone: null, email: 'ivan@example.com', username: 'ivan' });
    const input = {
      userId: 'user-2',
      phone: null,
      email: 'ivan@example.com',
      username: 'ivan',
      passwordHash: 'hash',
      emailVerifiedAt: new Date(),
      deviceKeyHash: 'device-2',
      deviceBound: true,
      deviceLabel: null,
      now: new Date(),
      sessionExpiresAt: new Date(Date.now() + 1_000),
      refreshTokenHash: 'refresh-2',
      refreshExpiresAt: new Date(Date.now() + 1_000),
    };

    expect(await repository.createAccountWithEmail(input)).toEqual({ outcome: 'conflict' });
  });
});
