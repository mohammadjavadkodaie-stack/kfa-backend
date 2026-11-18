import { randomUUID } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import { InMemorySessionRepository } from '../auth/in-memory-session.repository';
import { Role } from '../auth/roles';
import { BOOTSTRAP_ACTOR, bootstrapOwner, parseBootstrapArgs, scriptEnv } from './bootstrap-owner';

const SCRIPT_ENV: Record<string, string> = {
  NODE_ENV: 'test',
  DATABASE_URL: 'postgresql://kfa_app:app-secret@127.0.0.1:5432/kfa?schema=public',
  MIGRATION_DATABASE_URL: 'postgresql://kfa_migrator:mig-secret@127.0.0.1:5432/kfa?schema=public',
  AUDIT_HMAC_KEY: 'unit-test-audit-hmac-key-0123456789',
  RATE_LIMIT_HMAC_KEY: 'unit-test-rate-limit-hmac-key-0123456789',
  EMAIL_CODE_HMAC_KEY: 'unit-test-email-code-hmac-key-0123456789',
  ACCESS_TOKEN_SECRET: 'unit-test-access-token-secret-0123456789abcdef',
  DOCUMENT_VIEW_TOKEN_SECRET: 'unit-test-view-token-secret-0123456789abcdef',
  EMAIL_PROVIDER: 'fake',
};

/** Sets env values for the duration of `run`, restoring the previous ones. */
function withEnv(values: Record<string, string | undefined>, run: () => void): void {
  const previous: Record<string, string | undefined> = {};

  for (const [key, value] of Object.entries(values)) {
    previous[key] = process.env[key];

    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }

  try {
    run();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function stubAudit(): { readonly audit: AuditService; readonly records: unknown[] } {
  const records: unknown[] = [];
  const audit = {
    record: async (input: unknown): Promise<object> => {
      records.push(input);
      return {};
    },
  } as unknown as AuditService;

  return { audit, records };
}

/** Seeds one email-verified account through the ordinary sign-up repo path. */
async function seedEmailAccount(
  repo: InMemorySessionRepository,
  email: string,
  username: string,
): Promise<string> {
  const now = new Date('2026-01-01T00:00:00.000Z');
  const created = await repo.createAccountWithEmail({
    userId: randomUUID(),
    phone: null,
    email,
    passwordHash: 'test-only-password-hash',
    emailVerifiedAt: now,
    username,
    deviceKeyHash: 'test-only-device-hash',
    deviceBound: false,
    deviceLabel: null,
    now,
    sessionExpiresAt: new Date(now.getTime() + 3_600_000),
    refreshTokenHash: 'test-only-refresh-hash',
    refreshExpiresAt: new Date(now.getTime() + 7_200_000),
  });

  if ('outcome' in created) throw new Error('seeding the account failed');

  return created.userId;
}

describe('bootstrapOwner', () => {
  it('promotes the account that signed up through the email flow and audits it', async () => {
    const repo = new InMemorySessionRepository();
    const { audit, records } = stubAudit();
    const userId = await seedEmailAccount(repo, 'ops@example.com', 'ops');

    await expect(bootstrapOwner({ sessions: repo, audit }, 'Ops@Example.com')).resolves.toBe(
      'promoted',
    );

    await expect(repo.countUsersByRole(Role.OWNER)).resolves.toBe(1);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      action: 'owner.bootstrapped',
      actorRole: BOOTSTRAP_ACTOR,
      targetType: 'user',
      targetId: userId,
      metadata: { account: 'o***@example.com', from: Role.USER, to: Role.OWNER },
    });
  });

  it('refuses once any OWNER exists and leaves the other account untouched', async () => {
    const repo = new InMemorySessionRepository();
    const { audit, records } = stubAudit();
    const firstId = await seedEmailAccount(repo, 'first@example.com', 'first');
    const secondId = await seedEmailAccount(repo, 'second@example.com', 'second');

    await expect(bootstrapOwner({ sessions: repo, audit }, 'first@example.com')).resolves.toBe(
      'promoted',
    );
    await expect(bootstrapOwner({ sessions: repo, audit }, 'second@example.com')).resolves.toBe(
      'owner_exists',
    );

    await expect(repo.countUsersByRole(Role.OWNER)).resolves.toBe(1);
    expect(records).toHaveLength(1);
    expect((await repo.findSelfProfile(secondId))?.role).toBe(Role.USER);
    expect((await repo.findSelfProfile(firstId))?.role).toBe(Role.OWNER);
  });

  it('answers unknown or unusable addresses generically and records nothing', async () => {
    const repo = new InMemorySessionRepository();
    const { audit, records } = stubAudit();

    await expect(bootstrapOwner({ sessions: repo, audit }, 'nobody@example.com')).resolves.toBe(
      'unknown_account',
    );
    await expect(bootstrapOwner({ sessions: repo, audit }, 'not-an-address')).resolves.toBe(
      'unknown_account',
    );

    expect(records).toHaveLength(0);
    await expect(repo.countUsersByRole(Role.OWNER)).resolves.toBe(0);
  });
});

describe('parseBootstrapArgs', () => {
  it('requires --email with a value and --confirm, and nothing else', () => {
    expect(parseBootstrapArgs(['--email', 'ops@example.com', '--confirm'])).toEqual({
      email: 'ops@example.com',
    });
    expect('error' in parseBootstrapArgs([])).toBe(true);
    expect('error' in parseBootstrapArgs(['--confirm'])).toBe(true);
    expect('error' in parseBootstrapArgs(['--email', 'ops@example.com'])).toBe(true);
    expect('error' in parseBootstrapArgs(['--email'])).toBe(true);
    expect(
      'error' in parseBootstrapArgs(['--email', 'ops@example.com', '--confirm', '--force']),
    ).toBe(true);
  });
});

describe('scriptEnv', () => {
  it('points Prisma at the break-glass role and keeps the object frozen', () => {
    withEnv(SCRIPT_ENV, () => {
      const env = scriptEnv();

      expect(env.DATABASE_URL).toBe(SCRIPT_ENV.MIGRATION_DATABASE_URL);
      expect(Object.isFrozen(env)).toBe(true);
    });
  });

  it('falls back to DATABASE_URL when no break-glass URL is configured', () => {
    withEnv({ ...SCRIPT_ENV, MIGRATION_DATABASE_URL: undefined }, () => {
      expect(scriptEnv().DATABASE_URL).toBe(SCRIPT_ENV.DATABASE_URL);
    });
  });
});
