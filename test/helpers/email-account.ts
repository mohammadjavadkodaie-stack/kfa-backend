import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import type { EmailCodePurpose } from '../../src/auth/email/email.provider';
import { EmailProofService } from '../../src/auth/email/email-proof';

/**
 * Account fixtures over the real email endpoints.
 *
 * A suite that only needs a signed-in user should not walk the code flow: the
 * proof is minted in-process by the real service, and the account is then
 * created (or opened) through `POST /auth/signup` / `POST /auth/signin`, so the
 * password policy, the device binding and the session issuance are all real.
 */

/** Long enough for the policy and carrying no fixture identity. */
export const TEST_ACCOUNT_PASSWORD = 'Correct-horse-battery-42';

export interface EmailAccountInput {
  readonly email: string;
  readonly username: string;
  readonly password?: string;
}

/** A fresh proof for one address, signed by the service the app is using. */
export async function issueEmailProof(
  app: NestExpressApplication,
  email: string,
  purpose: EmailCodePurpose,
): Promise<string> {
  return app.get(EmailProofService).issueEmailProof({ email, purpose });
}

/** Creates the account and returns the response, cookie included. */
export async function signUpByEmail(
  app: NestExpressApplication,
  account: EmailAccountInput,
): Promise<request.Response> {
  const proof = await issueEmailProof(app, account.email, 'register');

  return request(app.getHttpServer())
    .post('/auth/signup')
    .send({
      proof,
      username: account.username,
      password: account.password ?? TEST_ACCOUNT_PASSWORD,
    });
}

/**
 * Opens a session for an existing account.
 *
 * The caller has no known device, so the proof stands in for the emailed code
 * that a real client would need on a new device.
 */
export async function signInByEmail(
  app: NestExpressApplication,
  account: EmailAccountInput,
): Promise<request.Response> {
  const proof = await issueEmailProof(app, account.email, 'login_device');

  return request(app.getHttpServer())
    .post('/auth/signin')
    .send({
      email: account.email,
      password: account.password ?? TEST_ACCOUNT_PASSWORD,
      proof,
    });
}
