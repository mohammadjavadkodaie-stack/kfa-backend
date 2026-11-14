import { readFileSync } from 'node:fs';
import path from 'node:path';

type Service = { ports?: unknown; cap_drop?: unknown; security_opt?: unknown; env_file?: unknown };
const root = path.resolve(__dirname, '..');
const compose = readFileSync(path.join(root, 'deploy/docker-compose.prod.yml'), 'utf8');
const dockerfile = readFileSync(path.join(root, 'Dockerfile'), 'utf8');
const dockerignore = readFileSync(path.join(root, '.dockerignore'), 'utf8');
const envExample = readFileSync(path.join(root, 'deploy/.env.production.example'), 'utf8');

function serviceBlock(name: string): string {
  const lines = compose.split(/\r?\n/);
  const start = lines.findIndex((line) => line === `  ${name}:`);
  const end = lines.findIndex((line, index) => index > start && /^  [a-z][a-z0-9-]*:$/.test(line));
  return lines.slice(start, end < 0 ? lines.length : end).join('\n');
}

describe('production deployment guard', () => {
  it('publishes host ports only from caddy', () => {
    expect(serviceBlock('caddy')).toMatch(/ports:/);
    for (const name of ['frontend', 'backend', 'migrate', 'postgres', 'redis', 'clamav']) {
      expect(serviceBlock(name)).not.toMatch(/^\s+ports:/m);
    }
  });

  it('hardens every app service', () => {
    for (const name of ['caddy', 'frontend', 'backend', 'migrate']) {
      const block = serviceBlock(name);
      expect(block).toMatch(/cap_drop: \[ALL\]/);
      expect(block).toMatch(/no-new-privileges:true/);
    }
  });

  it('does not use env_file in production compose', () => {
    expect(compose).not.toMatch(/env_file:/);
  });

  it('contains no obvious secret material in deploy files', () => {
    expect(envExample).not.toMatch(/-----BEGIN (RSA |EC )?PRIVATE KEY-----/);
    expect(envExample).not.toMatch(/(?:re_|sk_)[A-Za-z0-9_-]{12,}/);
    expect(compose).not.toMatch(/(?:re_|sk_)[A-Za-z0-9_-]{12,}/);
  });

  it('uses a non-root Docker user and healthcheck', () => {
    expect(dockerfile).toMatch(/USER kfa/);
    expect(dockerfile).toMatch(/HEALTHCHECK/);
  });

  it('ignores environment files in Docker builds', () => {
    expect(dockerignore).toMatch(/^\.env\*$/m);
  });

  it('keeps data services on the internal network and uses only caddy ports', () => {
    expect(compose).toMatch(/internal:\s*true/);
    expect(compose).toMatch(/443:443\/udp/);
    expect(compose).toMatch(/TRUSTED_PROXY_COUNT/);
  });

  it('gives the frontend its whole runtime contract plus the build argument', () => {
    const frontend = serviceBlock('frontend');

    for (const name of [
      'NODE_ENV',
      'APP_URL',
      'SESSION_SECRET',
      'LOG_LEVEL',
      'CAPTCHA_PROVIDER',
      'TURNSTILE_SITE_KEY',
    ]) {
      expect(frontend).toMatch(new RegExp(`^\\s+${name}:`, 'm'));
    }

    // Every runtime value comes from the env file: none is pinned inline here.
    expect(frontend).toMatch(/^\s+NODE_ENV: \$\{NODE_ENV:-production\}$/m);
    expect(frontend).toMatch(/^\s+TRUSTED_PROXY_COUNT: \$\{TRUSTED_PROXY_COUNT:-1\}$/m);
    expect(frontend).toMatch(/^\s+args:$/m);
    expect(frontend).toMatch(/^\s+BACKEND_INTERNAL_URL:/m);
    expect(frontend).not.toContain('FRONTEND_PUBLIC_URL');
  });

  it('never references the removed frontend URL variable', () => {
    expect(compose).not.toContain('FRONTEND_PUBLIC_URL');
    expect(envExample).not.toContain('FRONTEND_PUBLIC_URL');
  });

  it('wires no OTP provider in production', () => {
    expect(compose).not.toContain('OTP_PROVIDER');
    expect(envExample).not.toMatch(/^OTP_PROVIDER=/m);
  });

  it('gives the backend every document and TOTP key, and the migrate service none', () => {
    const backend = serviceBlock('backend');

    for (const name of [
      'TOTP_ENC_KEY',
      'DOCUMENT_MASTER_KEY',
      'DOCUMENT_MASTER_KEY_ID',
      'DOCUMENT_VIEW_TOKEN_SECRET',
    ]) {
      expect(backend).toMatch(new RegExp(`^\\s+${name}:`, 'm'));
    }

    // The break-glass URL stays on the backend so the owner bootstrap can use
    // the one role the owner-protection trigger allows to create an OWNER.
    expect(backend).toMatch(/^\s+MIGRATION_DATABASE_URL:/m);

    // Migrations only need the two database URLs; a stray key line after its
    // block would also make the file invalid YAML.
    const migrate = serviceBlock('migrate');

    expect(migrate).toMatch(/^\s+DATABASE_URL:/m);
    expect(migrate).not.toContain('TOTP_ENC_KEY');
    expect(migrate).not.toContain('DOCUMENT_MASTER_KEY');
    expect(migrate).not.toContain('DOCUMENT_VIEW_TOKEN_SECRET');
  });
});
