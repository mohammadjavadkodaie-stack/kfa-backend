import { Module, type MiddlewareConsumer, type NestModule } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { noStoreMiddleware } from '../common/middleware/no-store.middleware';
import { ENV } from '../config/config.module';
import type { Env } from '../config/env';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
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
 * Everything the document upload route needs.
 *
 * The three seams the services read - the key wrapper, the store and the scanner
 * - are chosen here from the validated environment, so a deployment that has not
 * configured them still boots and still refuses every upload (see the builders
 * above). `PrismaModule`, `AppConfigModule` and the pino logger are global, so
 * only the trail and the counters are imported.
 */
@Module({
  // AuditModule supplies the append-only trail the upload writes in the same
  // transaction; RateLimitModule the shared counters behind the strict limits.
  imports: [AuditModule, RateLimitModule],
  controllers: [DocumentUploadController],
  providers: [
    DocumentUploadService,
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
  ],
  exports: [DocumentUploadService],
})
export class DocumentsModule implements NestModule {
  /**
   * An upload answer describes a private document, so it is never cacheable -
   * set for the whole route, which also covers the guard refusals.
   */
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(noStoreMiddleware).forRoutes(DocumentUploadController);
  }
}
