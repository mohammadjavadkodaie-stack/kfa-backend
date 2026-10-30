import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service';
import type { TotpCredentialRecord, TotpRepository } from './totp.repository';

/** Row shape of the single statements below; only the id is read back. */
interface UpdatedRow {
  readonly id: string;
}

@Injectable()
export class PrismaTotpRepository implements TotpRepository {
  constructor(private readonly prisma: PrismaService) {}

  async getCredential(userId: string): Promise<TotpCredentialRecord | null> {
    const credential = await this.prisma.totpCredential.findUnique({
      where: { userId },
      select: { userId: true, secretEnc: true, confirmedAt: true, lastUsedStep: true },
    });

    if (credential === null) return null;

    // The column is BIGINT; steps stay far below 2^53, so a number is exact.
    return {
      userId: credential.userId,
      secretEnc: credential.secretEnc,
      confirmedAt: credential.confirmedAt,
      lastUsedStep: Number(credential.lastUsedStep),
    };
  }

  /**
   * One statement: the `WHERE` on the conflict branch is what keeps a confirmed
   * credential from being replaced, without a read that a race could invalidate.
   */
  async saveUnconfirmed(userId: string, secretEnc: string): Promise<boolean> {
    const rows = await this.prisma.$queryRaw<UpdatedRow[]>`
      INSERT INTO totp_credentials AS tc (user_id, secret_enc)
      VALUES (${userId}::uuid, ${secretEnc})
      ON CONFLICT (user_id) DO UPDATE
         SET secret_enc = EXCLUDED.secret_enc,
             confirmed_at = NULL,
             last_used_step = 0,
             updated_at = now()
       WHERE tc.confirmed_at IS NULL
      RETURNING tc.id
    `;

    return rows.length === 1;
  }

  /** The update and the code replacement commit together or not at all. */
  async confirm(userId: string, step: number, codeHashes: readonly string[]): Promise<boolean> {
    return this.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<UpdatedRow[]>`
        UPDATE totp_credentials
           SET confirmed_at = now(), last_used_step = ${step}::bigint, updated_at = now()
         WHERE user_id = ${userId}::uuid
           AND confirmed_at IS NULL
        RETURNING id
      `;

      // Only fires once: a second confirm or a vanished pending row is a no-op.
      if (rows.length === 0) return false;

      await tx.recoveryCode.deleteMany({ where: { userId } });

      if (codeHashes.length > 0) {
        await tx.recoveryCode.createMany({
          data: codeHashes.map((codeHash) => ({ userId, codeHash })),
        });
      }

      return true;
    });
  }

  /**
   * One transaction: the conditional swap decides, the code replacement
   * follows. A vanished or changed credential rolls the whole rotation back.
   */
  async rotate(
    userId: string,
    expectedSecretEnc: string,
    nextSecretEnc: string,
    step: number,
    codeHashes: readonly string[],
  ): Promise<boolean> {
    return this.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<UpdatedRow[]>`
        UPDATE totp_credentials
           SET secret_enc = ${nextSecretEnc},
               confirmed_at = now(),
               last_used_step = ${step}::bigint,
               updated_at = now()
         WHERE user_id = ${userId}::uuid
           AND confirmed_at IS NOT NULL
           AND secret_enc = ${expectedSecretEnc}
        RETURNING id
      `;

      if (rows.length === 0) return false;

      await tx.recoveryCode.deleteMany({ where: { userId } });

      if (codeHashes.length > 0) {
        await tx.recoveryCode.createMany({
          data: codeHashes.map((codeHash) => ({ userId, codeHash })),
        });
      }

      return true;
    });
  }

  /** Replay guard: only a strictly newer step can win, in one statement. */
  async advanceStep(userId: string, step: number): Promise<boolean> {
    const rows = await this.prisma.$queryRaw<UpdatedRow[]>`
      UPDATE totp_credentials
         SET last_used_step = ${step}::bigint, updated_at = now()
       WHERE user_id = ${userId}::uuid
         AND confirmed_at IS NOT NULL
         AND last_used_step < ${step}::bigint
      RETURNING id
    `;

    return rows.length === 1;
  }

  async consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean> {
    const rows = await this.prisma.$queryRaw<UpdatedRow[]>`
      UPDATE recovery_codes
         SET used_at = now()
       WHERE user_id = ${userId}::uuid
         AND code_hash = ${codeHash}
         AND used_at IS NULL
      RETURNING id
    `;

    return rows.length === 1;
  }

  async countUnusedRecoveryCodes(userId: string): Promise<number> {
    return this.prisma.recoveryCode.count({ where: { userId, usedAt: null } });
  }

  /**
   * Both deletes commit together. Codes go first because the credential row may
   * be referenced by them; only that row says whether anything was removed.
   */
  async deleteCredential(userId: string): Promise<boolean> {
    return this.prisma.$transaction(async (tx) => {
      await tx.recoveryCode.deleteMany({ where: { userId } });

      const rows = await tx.$queryRaw<UpdatedRow[]>`
        DELETE FROM totp_credentials
         WHERE user_id = ${userId}::uuid
        RETURNING id
      `;

      return rows.length === 1;
    });
  }
}
