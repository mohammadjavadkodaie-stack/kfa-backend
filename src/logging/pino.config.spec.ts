import pino, { type DestinationStream } from 'pino';
import type { Env } from '../config/env';
import { buildPinoParams, buildRedactPaths } from './pino.config';

const REDACTED = '[REDACTED]';

/** Collects pino's JSON lines so assertions can inspect the real output. */
function createCapturingLogger(): { logger: pino.Logger; lines: string[] } {
  const lines: string[] = [];
  const stream = {
    write: (line: string): void => {
      lines.push(line);
    },
  } as unknown as DestinationStream;

  const logger = pino({ redact: { paths: buildRedactPaths(), censor: REDACTED } }, stream);

  return { logger, lines };
}

describe('buildRedactPaths', () => {
  it('covers every connection string and secret in the environment', () => {
    const paths = buildRedactPaths();

    for (const name of [
      'DATABASE_URL',
      'MIGRATION_DATABASE_URL',
      'REDIS_URL',
      'AUDIT_HMAC_KEY',
      'RATE_LIMIT_HMAC_KEY',
    ]) {
      expect(paths).toContain(name);
      expect(paths).toContain(`env.${name}`);
    }
  });

  it('still covers credentials, whole bodies and nested secret fields', () => {
    const paths = buildRedactPaths();

    expect(paths).toContain('req.headers.authorization');
    expect(paths).toContain('req.headers.cookie');
    expect(paths).toContain('res.headers["set-cookie"]');
    expect(paths).toContain('req.body');
    expect(paths).toContain('password');
    expect(paths).toContain('*.otp');
    expect(paths).toContain('*.*.*.refreshToken');
  });

  it('returns no duplicates', () => {
    const paths = buildRedactPaths();

    expect(new Set(paths).size).toBe(paths.length);
  });
});

describe('pino redaction', () => {
  it('never emits an environment secret value', () => {
    const { logger, lines } = createCapturingLogger();

    logger.info(
      {
        DATABASE_URL: 'postgresql://kfa_app:db-password@db.internal:5432/kfa',
        REDIS_URL: 'rediss://:redis-password@redis.internal:6380/0',
        AUDIT_HMAC_KEY: 'audit-hmac-secret-0123456789abcdef',
        RATE_LIMIT_HMAC_KEY: 'rate-limit-hmac-secret-0123456789abcdef',
        env: {
          DATABASE_URL: 'postgresql://kfa_app:db-password@db.internal:5432/kfa',
          REDIS_URL: 'rediss://:redis-password@redis.internal:6380/0',
        },
      },
      'boot',
    );

    const output = lines.join('');

    expect(output).not.toContain('db-password');
    expect(output).not.toContain('redis-password');
    expect(output).not.toContain('audit-hmac-secret');
    expect(output).not.toContain('rate-limit-hmac-secret');
    expect(output).toContain(REDACTED);
    expect(output).toContain('boot');
  });

  it('redacts request credentials while keeping the request id', () => {
    const { logger, lines } = createCapturingLogger();

    logger.info(
      {
        req: {
          id: 'request-id-1234',
          headers: {
            authorization: 'Bearer super-secret-token',
            cookie: 'session=super-secret-cookie',
            'x-api-key': 'super-secret-api-key',
          },
        },
        password: 'p@ssw0rd',
        otp: '123456',
      },
      'request rejected',
    );

    const output = lines.join('');

    expect(output).not.toContain('super-secret');
    expect(output).not.toContain('p@ssw0rd');
    expect(output).not.toContain('123456');
    expect(output).toContain('request-id-1234');
  });
});

describe('buildPinoParams', () => {
  it('applies the configured level and the shared redaction list', () => {
    const params = buildPinoParams({ LOG_LEVEL: 'debug' } as Env);
    const pinoHttp = params.pinoHttp;

    expect(pinoHttp).toMatchObject({
      level: 'debug',
      redact: { censor: REDACTED, remove: false },
    });

    const paths = (pinoHttp as { redact: { paths: string[] } }).redact.paths;

    expect(paths).toEqual(buildRedactPaths());
    expect(paths).toContain('REDIS_URL');
    expect(paths).toContain('env.RATE_LIMIT_HMAC_KEY');
  });

  it('keeps query strings and bodies out of the request/response serializers', () => {
    const params = buildPinoParams({ LOG_LEVEL: 'info' } as Env);
    const serializers = (
      params.pinoHttp as {
        serializers: { req: (value: unknown) => unknown; res: (value: unknown) => unknown };
      }
    ).serializers;

    const request = serializers.req({
      id: 'request-id-1234',
      method: 'POST',
      url: '/auth/login?token=super-secret-token',
      ip: '203.0.113.9',
      socket: { remoteAddress: '203.0.113.9' },
      body: { password: 'p@ssw0rd' },
    });

    expect(request).toEqual({
      id: 'request-id-1234',
      method: 'POST',
      url: '/auth/login',
      remoteAddress: '203.0.113.9',
    });
    expect(serializers.res({ statusCode: 401 })).toEqual({ statusCode: 401 });
  });
});
