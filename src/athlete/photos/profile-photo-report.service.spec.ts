import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { AUTHENTICATED_KEY } from '../../auth/decorators/authenticated.decorator';
import { ROLES_KEY } from '../../auth/decorators/roles.decorator';
import type { PolicySubject } from '../../auth/policy/access-policy';
import { Role } from '../../auth/roles';
import { STEP_UP_REQUIRED_KEY } from '../../auth/totp/step-up.guard';
import {
  PROFILE_PHOTO_REPORT_LIMITS,
  ProfilePhotoReportController,
} from './profile-photo-report.controller';
import { parsePhotoReport, sanitizeReportNote } from './profile-photo-report.dto';
import type {
  PhotoReportInput,
  ProfilePhotoReportRepository,
  ReportablePhoto,
} from './profile-photo-report.repository';
import { ProfilePhotoReportService } from './profile-photo-report.service';
import type { ProfilePhotoStatus } from './profile-photo.repository';

/**
 * Reporting another account's photo, below HTTP: one row per (photo, reporter),
 * APPROVED photos only, never the owner, and never a hint about what the refusal
 * was for.
 */

const REPORTER_ID = '11111111-1111-4111-8111-111111111111';
const OWNER_ID = '22222222-2222-4222-8222-222222222222';
const PHOTO_ID = '33333333-3333-4333-8333-333333333333';

const reporter: PolicySubject = { id: REPORTER_ID, role: Role.USER };

/** The `photo_reports` table: a list of writes plus every photo to look up. */
class InMemoryReportPhotos implements ProfilePhotoReportRepository {
  readonly photos = new Map<string, ReportablePhoto>();
  readonly created: PhotoReportInput[] = [];
  /** Set to simulate the unique pair losing a race with another request. */
  duplicate = false;

  seed(photoId: string, status: ProfilePhotoStatus = 'APPROVED', ownerUserId = OWNER_ID): void {
    this.photos.set(photoId, { id: photoId, status, ownerUserId });
  }

  async findReportablePhoto(photoId: string): Promise<ReportablePhoto | null> {
    return this.photos.get(photoId) ?? null;
  }

  async create(report: PhotoReportInput): Promise<boolean> {
    if (this.duplicate) return false;

    this.created.push(report);

    return true;
  }
}

function createService(): { service: ProfilePhotoReportService; photos: InMemoryReportPhotos } {
  const photos = new InMemoryReportPhotos();
  const service = new ProfilePhotoReportService(photos);

  return { service, photos };
}

async function refusalOf(call: Promise<unknown>, type: new () => Error): Promise<Error> {
  try {
    await call;
  } catch (error) {
    if (error instanceof type) return error;

    throw error;
  }

  throw new Error('expected the call to be refused');
}

describe('ProfilePhotoReportService', () => {
  it('writes one report for an approved photo of another account', async () => {
    const { service, photos } = createService();

    photos.seed(PHOTO_ID);

    await service.report(reporter, PHOTO_ID, { reason: 'SPAM', note: 'stolen photo' });

    expect(photos.created).toEqual([
      {
        photoId: PHOTO_ID,
        reporterUserId: REPORTER_ID,
        reason: 'SPAM',
        note: 'stolen photo',
      },
    ]);
  });

  it('answers a PENDING photo with the generic 404 and writes nothing', async () => {
    const { service, photos } = createService();

    photos.seed(PHOTO_ID, 'PENDING');

    const refused = await refusalOf(
      service.report(reporter, PHOTO_ID, { reason: 'ABUSE', note: null }),
      NotFoundException,
    );

    expect(refused.message).toBe('Not Found');
    expect(photos.created).toEqual([]);
  });

  it('hides a rejected, a removed and an unknown photo behind the same 404', async () => {
    const { service, photos } = createService();

    photos.seed(PHOTO_ID, 'REJECTED');
    photos.seed('44444444-4444-4444-8444-444444444444', 'REMOVED');

    for (const photoId of [PHOTO_ID, '44444444-4444-4444-8444-444444444444', crypto.randomUUID()]) {
      await refusalOf(
        service.report(reporter, photoId, { reason: 'NUDITY', note: null }),
        NotFoundException,
      );
    }

    expect(photos.created).toEqual([]);
  });

  it('refuses the owner reporting their own photo, writing nothing', async () => {
    const { service, photos } = createService();

    photos.seed(PHOTO_ID, 'APPROVED', REPORTER_ID);

    await refusalOf(
      service.report(reporter, PHOTO_ID, { reason: 'OTHER', note: null }),
      ForbiddenException,
    );

    expect(photos.created).toEqual([]);
  });

  it('treats a second report by the same user as a silent no-op', async () => {
    const { service, photos } = createService();

    photos.seed(PHOTO_ID);
    photos.duplicate = true;

    await expect(
      service.report(reporter, PHOTO_ID, { reason: 'SPAM', note: null }),
    ).resolves.toBeUndefined();
    expect(photos.created).toEqual([]);
  });
});

describe('the report body', () => {
  it('accepts the four reasons and refuses anything else', () => {
    expect(parsePhotoReport({ reason: 'SPAM' })).toEqual({ reason: 'SPAM', note: null });

    for (const reason of ['spam', 'HARASSMENT', '', undefined]) {
      expect(() => parsePhotoReport({ reason })).toThrow(BadRequestException);
    }
  });

  it('refuses an unknown key or an over-long note with the generic 400', () => {
    expect(() => parsePhotoReport({ reason: 'SPAM', reporterId: REPORTER_ID })).toThrow(
      BadRequestException,
    );
    expect(() => parsePhotoReport({ reason: 'SPAM', note: 'x'.repeat(201) })).toThrow(
      BadRequestException,
    );
  });

  it('flattens the note to one line and drops a note that is only whitespace', () => {
    expect(sanitizeReportNote('  line\u0000one\nline two  ')).toBe('line one line two');
    expect(parsePhotoReport({ reason: 'SPAM', note: '   ' })).toEqual({
      reason: 'SPAM',
      note: null,
    });
  });
});

describe('the report route', () => {
  const handlers = ProfilePhotoReportController.prototype;

  it('marks the route authenticated, with no staff role and no step-up', () => {
    expect(Reflect.getMetadata(AUTHENTICATED_KEY, handlers.report)).toBe(true);
    expect(Reflect.getMetadata(ROLES_KEY, handlers.report)).toBeUndefined();
    expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, handlers.report)).toBeUndefined();
  });

  it('keeps both per-user windows tight', () => {
    expect(PROFILE_PHOTO_REPORT_LIMITS).toEqual([
      { limit: 5, windowSeconds: 60 },
      { limit: 20, windowSeconds: 3_600 },
    ]);
  });
});
