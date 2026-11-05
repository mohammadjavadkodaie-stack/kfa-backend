import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import { createObjectKey } from './document-storage';
import {
  createS3Client,
  MAX_DOCUMENT_BYTES,
  S3DocumentStorage,
  type S3DocumentStorageConfig,
} from './s3-document-storage';

/**
 * Fixture configuration. The values are shaped like real settings only so that a
 * leak would be visible; none of them can authenticate against anything.
 */
const CONFIG: S3DocumentStorageConfig = {
  S3_ENDPOINT: 'http://127.0.0.1:9000',
  S3_REGION: 'us-east-1',
  S3_BUCKET: 'test-only-documents',
  S3_ACCESS_KEY_ID: 'test-only-access-key',
  S3_SECRET_ACCESS_KEY: 'test-only-secret-key',
  S3_FORCE_PATH_STYLE: true,
};

/** Stands in for what a real bucket holds: ciphertext, never plaintext. */
const CIPHERTEXT = Buffer.from('aes-256-gcm ciphertext, unreadable on purpose', 'utf8');

type Responder = (command: unknown) => Promise<unknown>;

/** Records every command and answers with whatever the test hands it. */
class RecordingClient {
  readonly commands: unknown[] = [];
  respond: Responder = async () => ({});

  async send(command: unknown): Promise<unknown> {
    this.commands.push(command);
    return this.respond(command);
  }
}

function createStorage() {
  const client = new RecordingClient();
  const storage = new S3DocumentStorage(CONFIG, client as unknown as S3Client);

  return { storage, client };
}

/** What GetObject throws for an absent key. */
function missingObject(): Error {
  return Object.assign(new Error('NoSuchKey'), {
    name: 'NoSuchKey',
    $metadata: { httpStatusCode: 404 },
  });
}

/**
 * A failure that names everything the adapter has to keep to itself: the bucket,
 * the object key and the endpoint.
 */
function verboseFailure(objectKey: string): Error {
  return Object.assign(
    new Error(`AccessDenied: ${CONFIG.S3_BUCKET}/${objectKey} at ${CONFIG.S3_ENDPOINT}`),
    { name: 'AccessDenied', $metadata: { httpStatusCode: 403 } },
  );
}

describe('S3DocumentStorage.put', () => {
  it('writes the ciphertext under the configured bucket, with no ACL', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    await storage.put(objectKey, CIPHERTEXT);

    expect(client.commands).toHaveLength(1);

    const command = client.commands[0] as PutObjectCommand;

    expect(command).toBeInstanceOf(PutObjectCommand);
    // Exact equality: any extra input (an ACL, a content type, a tag) fails here,
    // and nothing in this adapter may make an object more public than the bucket.
    expect(command.input).toEqual({
      Bucket: CONFIG.S3_BUCKET,
      Key: objectKey,
      Body: CIPHERTEXT,
    });
  });

  it('reports any upload failure as one generic error', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    client.respond = async () => {
      throw verboseFailure(objectKey);
    };

    await expect(storage.put(objectKey, CIPHERTEXT)).rejects.toThrow(
      new Error('document storage unavailable'),
    );
  });
});

describe('S3DocumentStorage.get', () => {
  it('returns the stored bytes', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    client.respond = async () => ({
      Body: Readable.from([CIPHERTEXT]),
      ContentLength: CIPHERTEXT.byteLength,
    });

    await expect(storage.get(objectKey)).resolves.toEqual(CIPHERTEXT);

    const command = client.commands[0] as GetObjectCommand;

    expect(command).toBeInstanceOf(GetObjectCommand);
    expect(command.input).toEqual({ Bucket: CONFIG.S3_BUCKET, Key: objectKey });
  });

  it('joins a body that arrives in several chunks', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    client.respond = async () => ({
      Body: Readable.from([CIPHERTEXT.subarray(0, 11), CIPHERTEXT.subarray(11)]),
    });

    await expect(storage.get(objectKey)).resolves.toEqual(CIPHERTEXT);
  });

  it('reports a missing object exactly like the in-memory adapter', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    client.respond = async () => {
      throw missingObject();
    };

    await expect(storage.get(objectKey)).rejects.toThrow(new Error('document not found'));
  });

  it('treats an empty response as an outage rather than an empty document', async () => {
    const { storage } = createStorage();
    const objectKey = createObjectKey();

    await expect(storage.get(objectKey)).rejects.toThrow(new Error('document storage unavailable'));
  });

  it('refuses a declared size above the cap before reading a byte', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    client.respond = async () => ({
      Body: Readable.from(
        // Never iterated: the declared size alone has to stop the read.
        (function* never(): Generator<Buffer> {
          throw new Error('the body must not be read');
        })(),
      ),
      ContentLength: MAX_DOCUMENT_BYTES + 1,
    });

    await expect(storage.get(objectKey)).rejects.toThrow(new Error('document storage unavailable'));
  });

  it('stops a stream that grows past the cap without a declared size', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();
    const chunk = Buffer.alloc(1024 * 1024, 0x61);

    client.respond = async () => ({
      Body: Readable.from(
        (async function* tooMuch(): AsyncGenerator<Buffer> {
          for (let sent = 0; sent <= MAX_DOCUMENT_BYTES / chunk.byteLength; sent += 1) {
            yield chunk;
          }
        })(),
      ),
    });

    await expect(storage.get(objectKey)).rejects.toThrow(new Error('document storage unavailable'));
  });

  it('keeps the bucket, the key and the endpoint out of the error', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    client.respond = async () => {
      throw verboseFailure(objectKey);
    };

    const message = await storage.get(objectKey).catch((error: Error) => error.message);

    expect(message).toBe('document storage unavailable');
    expect(message).not.toContain(objectKey);
    expect(message).not.toContain(CONFIG.S3_BUCKET);
    expect(message).not.toContain(CONFIG.S3_ENDPOINT);
  });
});

describe('S3DocumentStorage.exists', () => {
  it('answers true when the object is there', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    await expect(storage.exists(objectKey)).resolves.toBe(true);

    const command = client.commands[0] as HeadObjectCommand;

    expect(command).toBeInstanceOf(HeadObjectCommand);
    expect(command.input).toEqual({ Bucket: CONFIG.S3_BUCKET, Key: objectKey });
  });

  it('answers false for both shapes of "not there"', async () => {
    const objectKey = createObjectKey();
    const responses: Responder[] = [
      async () => {
        throw missingObject();
      },
      // HeadObject reports a bare 404 that the SDK names NotFound.
      async () => {
        throw Object.assign(new Error('NotFound'), {
          name: 'NotFound',
          $metadata: { httpStatusCode: 404 },
        });
      },
    ];

    for (const respond of responses) {
      const { storage, client } = createStorage();

      client.respond = respond;

      await expect(storage.exists(objectKey)).resolves.toBe(false);
    }
  });

  it('throws instead of answering false when the store is unreachable', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    client.respond = async () => {
      throw verboseFailure(objectKey);
    };

    await expect(storage.exists(objectKey)).rejects.toThrow(
      new Error('document storage unavailable'),
    );
  });
});

describe('S3DocumentStorage.delete', () => {
  it('deletes the object and returns nothing', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    await expect(storage.delete(objectKey)).resolves.toBeUndefined();

    const command = client.commands[0] as DeleteObjectCommand;

    expect(command).toBeInstanceOf(DeleteObjectCommand);
    expect(command.input).toEqual({ Bucket: CONFIG.S3_BUCKET, Key: objectKey });
  });

  it('reports a failed delete as one generic error', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    client.respond = async () => {
      throw verboseFailure(objectKey);
    };

    await expect(storage.delete(objectKey)).rejects.toThrow(
      new Error('document storage unavailable'),
    );
  });
});

describe('S3DocumentStorage URLs', () => {
  it('never hands a URL back to a caller', async () => {
    const { storage, client } = createStorage();
    const objectKey = createObjectKey();

    client.respond = async (command) => {
      if (command instanceof GetObjectCommand) return { Body: Readable.from([CIPHERTEXT]) };

      return {};
    };

    const results = [
      await storage.put(objectKey, CIPHERTEXT),
      await storage.get(objectKey),
      await storage.delete(objectKey),
      await storage.exists(objectKey),
    ];

    for (const result of results) {
      expect(typeof result).not.toBe('string');
    }

    // A presigned URL is the one way a document could become shareable, so the
    // adapter must not grow one: the source is checked instead of a mock.
    const source = readFileSync(join(__dirname, 's3-document-storage.ts'), 'utf8');

    expect(source).not.toMatch(/presign/iu);
    expect(source).not.toMatch(/getSignedUrl/u);
    expect(source).not.toMatch(/new URL\(/u);
  });
});

describe('createS3Client', () => {
  it('signs with S3_REGION when it is set', async () => {
    const client = createS3Client({ ...CONFIG, S3_REGION: 'eu-central-1' });

    try {
      await expect(client.config.region()).resolves.toBe('eu-central-1');
    } finally {
      client.destroy();
    }
  });

  it('falls back to us-east-1 so a signature always has a region', async () => {
    const client = createS3Client({ ...CONFIG, S3_REGION: undefined });

    try {
      await expect(client.config.region()).resolves.toBe('us-east-1');
    } finally {
      client.destroy();
    }
  });
});
