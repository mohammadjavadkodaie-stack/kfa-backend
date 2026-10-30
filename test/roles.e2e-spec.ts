import type { NestExpressApplication } from '@nestjs/platform-express';
import { createHmac } from 'node:crypto';
import request from 'supertest';
import { InMemorySessionRepository } from '../src/auth/in-memory-session.repository';
import { ProofTokenService, type ProofNonceStore } from '../src/auth/otp/proof-token';
import { ALL_ROLES, Role } from '../src/auth/roles';
import type { RateLimitDecision, RateLimitService } from '../src/rate-limit/rate-limit.service';
import { createTestApp } from './helpers/create-test-app';
import { TEST_ENV } from './helpers/test-env';

/**
 * Role-based route protection over HTTP, with no database and no Redis: the
 * session store is in memory, so a spec can change a stored role the way an
 * admin would and then replay the very same access token.
 *
 * What must hold:
 * - a route marked with `@Roles(...)` admits exactly the listed roles,
 * - a route marked with `@Authenticated()` admits any signed-in role,
 * - a non-public route with no marker at all is refused for every role,
 * - the role and the verifier flag always come from the database, never from
 *   the token, so a forged or stale claim changes nothing,
 * - every refusal looks the same from outside.
 */

const FORBIDDEN = { statusCode: 403, message: 'Forbidden' } as const;

class InMemoryNonceStore implements ProofNonceStore {
  private readonly nonces = new Map<string, { phone: string; expiresAt: number }>();

  async put(jti: string, phoneE164: string, ttlSeconds: number): Promise<boolean> {
    this.nonces.set(jti, { phone: phoneE164, expiresAt: Date.now() + ttlSeconds * 1_000 });

    return true;
  }

  async take(jti: string): Promise<string | null> {
    const stored = this.nonces.get(jti);
    this.nonces.delete(jti);

    return stored === undefined || stored.expiresAt <= Date.now() ? null : stored.phone;
  }
}

/** The explicit limiter is out of scope here: always admit. */
class PermissiveRateLimit {
  async consume(): Promise<RateLimitDecision> {
    return { allowed: true, remaining: 99, retryAfterSeconds: 0 };
  }

  async reset(): Promise<void> {}
}

/**
 * Re-signs a token with an extra `role` claim, using the real secret, to model
 * a client that controls its own token contents. The signature is valid; the
 * claim simply has no meaning for the guard.
 */
function withRoleClaim(token: string, role: Role): string {
  const [header, payload] = token.split('.') as [string, string, string];
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  const body = Buffer.from(JSON.stringify({ ...claims, role }), 'utf8').toString('base64url');
  const signingInput = `${header}.${body}`;
  const signature = createHmac('sha256', TEST_ENV.ACCESS_TOKEN_SECRET)
    .update(signingInput)
    .digest('base64url');

  return `${signingInput}.${signature}`;
}

describe('Role-based route protection (e2e)', () => {
  let app: NestExpressApplication;
  let sessions: InMemorySessionRepository;
  let proofs: ProofTokenService;
  let sequence = 0;

  const server = () => request(app.getHttpServer());
  const get = (path: string, token: string) =>
    server().get(path).set('Authorization', `Bearer ${token}`);

  const isStaff = (role: Role | undefined): boolean => role === Role.ADMIN || role === Role.OWNER;

  /**
   * Registers a fresh account through the real endpoint and returns its token
   * plus the id of the stored user, so a test can change the stored access
   * level without touching the token.
   */
  async function signUp(
    access: { role?: Role; identityVerifier?: boolean } = {},
  ): Promise<{ token: string; userId: string; sessionId: string }> {
    sequence += 1;
    const username = `role_user_${sequence}`;
    const phone = `+1415555${String(2_000 + sequence).padStart(4, '0')}`;

    const response = await server()
      .post('/auth/register')
      .send({ proof: await proofs.issue(phone, 'register'), username });

    expect(response.status).toBe(200);

    const stored = [...sessions.users.values()].find((user) => user.username === username);

    if (stored === undefined) throw new Error(`user ${username} was not stored`);

    sessions.setUserRole(stored.id, access);

    const session = [...sessions.sessions.values()].find((row) => row.userId === stored.id);

    if (session === undefined) throw new Error(`session of ${username} was not stored`);

    // A staff session has to sit past the second-factor gate to be tested here.
    if (isStaff(access.role)) await sessions.markStepUp(session.id, stored.id);

    return {
      token: (response.body as { accessToken: string }).accessToken,
      userId: stored.id,
      sessionId: session.id,
    };
  }

  beforeAll(async () => {
    sessions = new InMemorySessionRepository();
    app = await createTestApp(
      {},
      {
        sessionRepository: sessions,
        proofNonceStore: new InMemoryNonceStore(),
        rateLimit: new PermissiveRateLimit() as unknown as RateLimitService,
      },
    );
    proofs = app.get(ProofTokenService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('admits exactly the listed roles and refuses everyone else identically', async () => {
    const tokens = new Map<Role, string>();

    for (const role of ALL_ROLES) {
      tokens.set(role, (await signUp({ role })).token);
    }

    const routes = [
      { path: '/test/admin', allowed: [Role.ADMIN] },
      { path: '/test/owner', allowed: [Role.OWNER] },
      { path: '/test/staff', allowed: [Role.ADMIN, Role.OWNER] },
      { path: '/test/verifier', allowed: [] },
    ] as const;

    const refusals: unknown[] = [];

    for (const route of routes) {
      for (const role of ALL_ROLES) {
        const response = await get(route.path, tokens.get(role) ?? '');

        if ((route.allowed as readonly Role[]).includes(role)) {
          expect(response.status).toBe(200);
        } else {
          expect(response.status).toBe(403);
          refusals.push(response.body);
        }
      }
    }

    // 12 refusals: nothing but the listed roles and the verifier permission.
    expect(refusals).toHaveLength(12);

    for (const body of refusals) {
      expect(body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
    }

    // Same bytes apart from the request id: no hint of the allowed roles, no
    // hint of the caller's own role or verifier flag.
    const normalised = new Set(
      refusals.map((body) => JSON.stringify({ ...(body as object), requestId: '-' })),
    );
    expect(normalised.size).toBe(1);
  });

  it('keeps a route without @Roles open to every authenticated user', async () => {
    for (const role of ALL_ROLES) {
      const { token } = await signUp({ role });

      await get('/test/protected', token).expect(200);
    }
  });

  it('applies a promotion and a demotion on the next request with the old token', async () => {
    const { token, userId, sessionId } = await signUp({ role: Role.USER });

    await get('/test/admin', token).expect(403);

    sessions.setUserRole(userId, { role: Role.ADMIN });
    // A promoted session still needs its second factor before anything is open.
    await sessions.markStepUp(sessionId, userId);
    await get('/test/admin', token).expect(200);
    await get('/test/owner', token).expect(403);

    sessions.setUserRole(userId, { role: Role.OWNER });
    await get('/test/owner', token).expect(200);
    await get('/test/admin', token).expect(403);

    sessions.setUserRole(userId, { role: Role.USER });
    const refusal = await get('/test/admin', token);

    expect(refusal.status).toBe(403);
    expect(refusal.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
  });

  it('ignores the role claim of a token the client re-signed itself', async () => {
    const { token } = await signUp({ role: Role.USER });
    const forged = withRoleClaim(token, Role.OWNER);

    // Still authenticated: the signature and the session are genuine.
    await get('/test/protected', forged).expect(200);

    const refusal = await get('/test/owner', forged);

    expect(refusal.status).toBe(403);
    expect(refusal.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
  });

  it('never lets a forged claim hide a real role either', async () => {
    const { token, userId, sessionId } = await signUp({ role: Role.USER });
    sessions.setUserRole(userId, { role: Role.OWNER });
    await sessions.markStepUp(sessionId, userId);

    const forged = withRoleClaim(token, Role.USER);

    await get('/test/owner', forged).expect(200);
    await get('/test/admin', forged).expect(403);
  });

  it('treats the identity-verifier permission as separate from the role', async () => {
    const verifier = await signUp({ role: Role.USER, identityVerifier: true });

    await get('/test/verifier', verifier.token).expect(200);
    await get('/test/admin', verifier.token).expect(403);

    const admin = await signUp({ role: Role.ADMIN });

    await get('/test/admin', admin.token).expect(200);
    await get('/test/verifier', admin.token).expect(403);

    // Revoking only the permission keeps the role and applies immediately.
    sessions.setUserRole(verifier.userId, { identityVerifier: false });

    await get('/test/verifier', verifier.token).expect(403);
    await get('/test/protected', verifier.token).expect(200);
  });

  it('refuses a blocked account even though its session is still live', async () => {
    const { token, userId } = await signUp({ role: Role.ADMIN });
    const user = sessions.users.get(userId);

    if (user === undefined) throw new Error('missing user');
    user.status = 'BLOCKED';

    const refused = await get('/test/admin', token);

    expect(refused.status).toBe(401);
    expect(refused.body).toEqual({
      statusCode: 401,
      message: 'Unauthorized',
      requestId: expect.any(String),
    });

    await get('/test/protected', token).expect(401);
  });

  it('keeps @Public routes public and refuses anonymous calls elsewhere', async () => {
    await server().get('/test/echo').expect(200);

    await server().get('/test/admin').expect(401);
    await server().get('/test/protected').expect(401);
  });

  it('refuses an unmarked route for a normal user and for an admin', async () => {
    const user = await signUp({ role: Role.USER });
    const admin = await signUp({ role: Role.ADMIN });

    // The admin is past the second-factor gate, so only the marker decides here.
    for (const token of [user.token, admin.token]) {
      const refusal = await get('/test/unmarked', token);

      expect(refusal.status).toBe(403);
      expect(refusal.body).toEqual({ ...FORBIDDEN, requestId: expect.any(String) });
    }
  });

  it('gives an unmarked route the same refusal as a wrong role', async () => {
    const { token } = await signUp({ role: Role.USER });

    const unmarked = await get('/test/unmarked', token);
    const wrongRole = await get('/test/admin', token);
    const normalise = (body: object): string => JSON.stringify({ ...body, requestId: '-' });

    expect(normalise(unmarked.body)).toBe(normalise(wrongRole.body));
  });

  it('still asks for authentication on an unmarked route', async () => {
    await server().get('/test/unmarked').expect(401);
  });
});
