import { Module, type MiddlewareConsumer, type NestModule } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import {
  PROOF_NONCE_STORE,
  RedisProofNonceStore,
  type ProofNonceStore,
  type ProofRedisClient,
} from '../auth/otp/proof-token';
import { PrismaSessionRepository } from '../auth/prisma-session.repository';
import { SESSION_REPOSITORY } from '../auth/session.repository';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { REDIS_CLIENT } from '../rate-limit/redis-throttler.storage';
import { DocumentCryptoService } from './document-crypto.service';
import { DOCUMENT_STORAGE, type DocumentStorage } from './document-storage';
import { DocumentUploadController } from './document-upload.controller';
import { EnvKeyWrapper } from './env-key-wrapper';
import { ClamdScanner } from './ingest/clamd-scanner';
import { DocumentIngestService } from './ingest/document-ingest.service';
import { DocumentIngestError } from './ingest/ingest.errors';
import type { VirusScanner } from './ingest/virus-scanner';
import { KEY_WRAPPER, type KeyWrapper, type WrappedDataKey } from './key-wrapper';
import { DocumentUploadService } from './records/document-upload.service';
import { IDENTITY_DOCUMENT_REPOSITORY } from './records/identity-document.repository';
import { PrismaIdentityDocumentRepository } from './records/prisma-identity-document.repository';
import { S3DocumentStorage } from './s3-document-storage';
import { DocumentViewLinkController } from './view/document-view-link.controller';
import { DocumentViewFileController } from './view/document-view-file.controller';
import { DocumentViewService } from './view/document-view.service';
import { StaffDocumentViewLinkController } from './view/staff-document-view-link.controller';

/** DI token for the antivirus scanner; the specs replace it with a fake daemon. */
export const VIRUS_SCANNER = Symbol('VIRUS_SCANNER');

const STORAGE_UNAVAILABLE = 'document storage is not configured';

/**
 * The key wrapper for a deployment with no master key - which the environment
 * validator only allows outside production.
 *
 * Every wrap fails, so an upload ends as a generic 503 and nothing is ever
 * written unencrypted. It exists instead of a nullable provider so the module
 * graph is complete either way; boot is not refused, because a development
 * machine has no key and the rest of the API must still run.
 */
class UnavailableKeyWrapper implements KeyWrapper {
  async wrap(_dek: Buffer): Promise<WrappedDataKey> {
    throw new Error('DOCUMENT_MASTER_KEY is not configured');
  }

  async unwrap(_keyId: string, _wrapped: Buffer): Promise<Buffer> {
    throw new Error('DOCUMENT_MASTER_KEY is not configured');
  }
}

/**
 * The store for a deployment with no bucket configured.
 *
 * Every call fails, so an upload ends as a generic 503 before a row is written.
 * It is never the in-memory store: production must not quietly keep identity
 * documents inside the process, and a failure is the honest answer.
 */
class UnavailableDocumentStorage implements DocumentStorage {
  async put(_objectKey: string, _bytes: Buffer): Promise<void> {
    throw new Error(STORAGE_UNAVAILABLE);
  }

  async get(_objectKey: string): Promise<Buffer> {
    throw new Error(STORAGE_UNAVAILABLE);
  }

  async delete(_objectKey: string): Promise<void> {
    throw new Error(STORAGE_UNAVAILABLE);
  }

  async exists(_objectKey: string): Promise<boolean> {
    throw new Error(STORAGE_UNAVAILABLE);
  }
}

/**
 * The scanner for a deployment with no clamd: nothing passes.
 *
 * It refuses exactly the way `DocumentIngestService.fromEnv` does when no daemon
 * is configured, so a missing scanner is one generic 422 either way and never an
 * unscanned file in the bucket.
 */
class RefusingScanner implements VirusScanner {
  async scan(_bytes: Buffer): Promise<void> {
    throw new DocumentIngestError();
  }
}

/** The master key, or a wrapper that refuses to wrap anything. */
export function buildKeyWrapper(
  env: Pick<
    Env,
    | 'DOCUMENT_MASTER_KEY'
    | 'DOCUMENT_MASTER_KEY_ID'
    | 'DOCUMENT_MASTER_KEY_PREVIOUS'
    | 'DOCUMENT_MASTER_KEY_PREVIOUS_ID'
  >,
): KeyWrapper {
  return env.DOCUMENT_MASTER_KEY === undefined
    ? new UnavailableKeyWrapper()
    : EnvKeyWrapper.fromEnv(env);
}

/** The bucket, or a store that refuses every upload. */
export function buildDocumentStorage(
  env: Pick<
    Env,
    | 'S3_ENDPOINT'
    | 'S3_REGION'
    | 'S3_BUCKET'
    | 'S3_ACCESS_KEY_ID'
    | 'S3_SECRET_ACCESS_KEY'
    | 'S3_FORCE_PATH_STYLE'
  >,
): DocumentStorage {
  const {
    S3_ENDPOINT,
    S3_REGION,
    S3_BUCKET,
    S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY,
    S3_FORCE_PATH_STYLE,
  } = env;

  // The validator already refuses a half-configured bucket; the check is
  // repeated so a wiring that skips `loadEnv` cannot end up with one.
  if (
    S3_ENDPOINT === undefined ||
    S3_BUCKET === undefined ||
    S3_ACCESS_KEY_ID === undefined ||
    S3_SECRET_ACCESS_KEY === undefined
  ) {
    return new UnavailableDocumentStorage();
  }

  return new S3DocumentStorage({
    S3_ENDPOINT,
    S3_BUCKET,
    S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY,
    S3_REGION,
    S3_FORCE_PATH_STYLE,
  });
}

/** The daemon, or a scanner that refuses every upload. */
export function buildVirusScanner(env: Pick<Env, 'CLAMAV_HOST' | 'CLAMAV_PORT'>): VirusScanner {
  const { CLAMAV_HOST: host, CLAMAV_PORT: port } = env;

  return host === undefined || port === undefined
    ? new RefusingScanner()
    : new ClamdScanner(host, port);
}

/**
 * The one-time store a view link spends its nonce in, or null without one.
 *
 * It is the same contract and the same shared Redis client the OTP proof uses -
 * SET NX to remember, GETDEL to spend - because the guarantee is the same one:
 * a link is good for exactly one read. Null is passed through instead of being
 * replaced by an in-process map, so `DocumentViewService` fails closed (503)
 * rather than handing out replayable links on a multi-instance deployment.
 */
export function buildProofNonceStore(client: unknown): ProofNonceStore | null {
  return client === null || client === undefined
    ? null
    : new RedisProofNonceStore(client as ProofRedisClient);
}

/**
 * Everything the document routes need: uploading one, and issuing a single-use
 * link to view one.
 *
 * The three seams the upload reads - the key wrapper, the store and the scanner
 * - are chosen here from the validated environment, so a deployment that has not
 * configured them still boots and still refuses every upload (see the builders
 * above). The view path adds two more real seams, both wired here rather than
 * injected from `AuthModule`: the shared Redis for single-use nonces and the
 * Prisma-backed session store it reads the viewer row from. Neither is ever
 * replaced by an in-memory stand-in - a missing Redis yields null, which turns
 * the feature off with a generic 503 instead of degrading to replayable links.
 *
 * `PrismaModule`, `AppConfigModule` and the pino logger are global, so only the
 * trail and the counters are imported.
 */
@Module({
  // AuditModule supplies the append-only trail the upload writes in the same
  // transaction and the view path writes before a byte is read; RateLimitModule
  // the shared counters behind the strict limits and the Redis client the view
  // links spend their nonces in.
  imports: [AuditModule, RateLimitModule],
  controllers: [
    DocumentUploadController,
    DocumentViewLinkController,
    StaffDocumentViewLinkController,
    // The bytes behind a link: the only route whose credential is the path.
    DocumentViewFileController,
  ],
  providers: [
    DocumentUploadService,
    // Its own decorators declare the dependencies; every one of them is a real
    // provider in this graph (crypto and storage below, the trail from
    // AuditModule, the two seams right after it).
    DocumentViewService,
    // Both are plain classes with one constructor argument and no decorators, so
    // their seam is wired here instead of being guessed by the injector.
    {
      provide: DocumentCryptoService,
      inject: [KEY_WRAPPER],
      useFactory: (wrapper: KeyWrapper): DocumentCryptoService =>
        new DocumentCryptoService(wrapper),
    },
    {
      provide: DocumentIngestService,
      inject: [VIRUS_SCANNER],
      useFactory: (scanner: VirusScanner): DocumentIngestService =>
        new DocumentIngestService(scanner),
    },
    {
      provide: KEY_WRAPPER,
      inject: [ENV],
      useFactory: (env: Env): KeyWrapper => buildKeyWrapper(env),
    },
    {
      provide: DOCUMENT_STORAGE,
      inject: [ENV],
      useFactory: (env: Env): DocumentStorage => buildDocumentStorage(env),
    },
    {
      provide: VIRUS_SCANNER,
      inject: [ENV],
      useFactory: (env: Env): VirusScanner => buildVirusScanner(env),
    },
    { provide: IDENTITY_DOCUMENT_REPOSITORY, useClass: PrismaIdentityDocumentRepository },
    // The same shared Redis client the counters use, so a link's nonce lives in
    // one place for every instance; null when no Redis is configured.
    {
      provide: PROOF_NONCE_STORE,
      inject: [REDIS_CLIENT],
      useFactory: (client: unknown): ProofNonceStore | null => buildProofNonceStore(client),
    },
    // The view decision reads the viewer's role and status from the database on
    // every request, exactly like the guards do, so a block or a role change
    // applies to the next link as well.
    { provide: SESSION_REPOSITORY, useClass: PrismaSessionRepository },
  ],
  exports: [DocumentUploadService],
})
export class DocumentsModule implements NestModule {
  /**
   * An upload answer describes a private document, and a view link is a secret
   * in its own right, so none of these answers is ever cacheable - set for the
   * whole routes, which also covers the guard refusals.
   */
  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(noStoreMiddleware)
      .forRoutes(
        DocumentUploadController,
        DocumentViewLinkController,
        StaffDocumentViewLinkController,
        DocumentViewFileController,
      );
  }
}
