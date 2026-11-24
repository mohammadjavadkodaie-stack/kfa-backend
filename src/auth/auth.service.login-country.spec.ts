import type { PinoLogger } from 'nestjs-pino';
import type { AuditService } from '../audit/audit.service';
import { AuthService } from './auth.service';
import { Role } from './roles';
import {
  TEST_CONTEXT,
  TEST_EMAIL,
  createHarness,
  issued,
  type Harness,
} from '../../test/helpers/auth-service-harness';
import type { SecurityAlertService } from '../security-alerts/security-alert.service';

function serviceWithAlerts(harness: Harness, securityAlerts: SecurityAlertService): AuthService {
  return new AuthService(
    {
      ACCESS_TOKEN_SECRET: 'unit-test-access-token-secret-0123456789abcdef',
      ACCESS_TOKEN_TTL_SECONDS: 600,
      REFRESH_TTL_DAYS: 14,
      SESSION_ABSOLUTE_DAYS: 30,
      STAFF_SESSION_ABSOLUTE_HOURS: 12,
      STAFF_SESSION_IDLE_MINUTES: 30,
      SESSIONS_MAX_PER_USER: 10,
    },
    harness.sessions,
    harness.rateLimit as unknown as import('../rate-limit/rate-limit.service').RateLimitService,
    harness.audit as unknown as AuditService,
    harness.logger as unknown as PinoLogger,
    securityAlerts,
  );
}

describe('AuthService email login country alert', () => {
  async function loginWithCountry(country: string | null | undefined, alert: SecurityAlertService) {
    const harness = createHarness();
    const service = serviceWithAlerts(harness, alert);
    const user = harness.sessions.seedUser({
      phone: null,
      email: TEST_EMAIL,
      passwordHash: 'hash',
      emailVerifiedAt: new Date(),
      username: 'ivan',
      status: 'ACTIVE',
      role: Role.USER,
    });
    const result = await service.issueEmailLoginSession({
      email: TEST_EMAIL,
      account: { id: user.id, role: Role.USER },
      context: TEST_CONTEXT,
      country,
    });
    return { result, userId: user.id };
  }

  it('does not alert when country is null', async () => {
    const alert = { loginCountry: jest.fn() } as unknown as SecurityAlertService;
    await loginWithCountry(null, alert);
    expect(alert.loginCountry).not.toHaveBeenCalled();
  });

  it('alerts with only the user id and country', async () => {
    const alert = {
      loginCountry: jest.fn().mockResolvedValue(null),
    } as unknown as SecurityAlertService;
    const { result, userId } = await loginWithCountry('TR', alert);
    expect(issued(result)).toBeDefined();
    expect(alert.loginCountry).toHaveBeenCalledTimes(1);
    expect(alert.loginCountry).toHaveBeenCalledWith(userId, 'TR');
  });

  it('keeps login successful when the alert service throws', async () => {
    const alert = {
      loginCountry: jest.fn().mockRejectedValue(new Error('alert failure')),
    } as unknown as SecurityAlertService;
    const { result } = await loginWithCountry('TR', alert);
    expect(result.outcome).toBe('issued');
  });
});
