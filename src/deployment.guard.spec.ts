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
});
