import { Inject, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PinoLogger } from 'nestjs-pino';
import { AuditService } from '../audit/audit.service';
import type { PolicySubject } from '../auth/policy/access-policy';
import type { AccessPolicyContext } from '../auth/policy/access-policy.service';
import { ResourceOwnershipService } from '../auth/policy/resource-ownership.service';
import { PrismaService } from '../database/prisma.service';
import { CLOCK, isMinor, type Clock } from './profile/athlete-age';
import {
  ATHLETE_PROFILE_REPOSITORY,
  type AthleteProfileInput,
  type AthleteProfileRecord,
  type AthleteProfileRepository,
  type Gender,
} from './profile/athlete-profile.repository';

/** The closed set of audit actions this module writes. */
export const ATHLETE_AUDIT_ACTIONS = {
  PROFILE_CREATE: 'athlete.profile.create',
  PROFILE_UPDATE: 'athlete.profile.update',
} as const;

export type AthleteAuditAction = (typeof ATHLETE_AUDIT_ACTIONS)[keyof typeof ATHLETE_AUDIT_ACTIONS];

const AUDIT_TARGET_TYPE = 'athlete_profile';

/** Everything a caller may edit. Audit metadata names fields from this list only. */
const EDITABLE_FIELDS = [
  'legalFirstName',
  'legalLastName',
  'dateOfBirth',
  'gender',
  'nationality',
  'countryOfResidence',
  'city',
  'clubName',
  'weightKg',
  'heightCm',
] as const;

/** What the API returns: the profile plus the derived flag, and nothing internal. */
export interface AthleteProfileView {
  readonly legalFirstName: string;
  readonly legalLastName: string;
  readonly dateOfBirth: string;
  readonly gender: Gender;
  readonly nationality: string;
  readonly countryOfResidence: string;
  readonly city: string;
  readonly clubName: string | null;
  readonly weightKg: number | null;
  readonly heightCm: number | null;
  readonly isMinor: boolean;
  readonly updatedAt: string;
}

/** `undefined` from the input layer would otherwise read as "changed" against NULL. */
function valueOf(input: Partial<AthleteProfileInput>, field: (typeof EDITABLE_FIELDS)[number]) {
  return input[field] ?? null;
}

/**
 * Field names only, never values: the audit row must not become a copy of the
 * profile. On the first save there is nothing to compare with, so every
 * editable name counts as new.
 */
export function changedFields(
  previous: AthleteProfileRecord | null,
  input: AthleteProfileInput,
): string[] {
  if (previous === null) return [...EDITABLE_FIELDS];

  return EDITABLE_FIELDS.filter((field) => valueOf(previous, field) !== valueOf(input, field));
}

/**
 * The caller's own profile. No method takes a user id: the owner always comes
 * from the verified principal, so there is no id a request could point
 * somewhere else.
 */
@Injectable()
export class AthleteService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(ATHLETE_PROFILE_REPOSITORY) private readonly profiles: AthleteProfileRepository,
    private readonly ownership: ResourceOwnershipService,
    private readonly audit: AuditService,
    private readonly logger: PinoLogger,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  async readProfile(
    actor: PolicySubject,
    context: AccessPolicyContext,
  ): Promise<AthleteProfileView> {
    const record = await this.loadOwn(actor, context);

    // A caller without a profile is told nothing more than that.
    if (record === null) throw new NotFoundException();

    return this.toView(record);
  }

  async saveProfile(
    actor: PolicySubject,
    input: AthleteProfileInput,
    context: AccessPolicyContext,
  ): Promise<AthleteProfileView> {
    const previous = await this.loadOwn(actor, context);

    // One transaction for the row and its trail: the upsert goes first so the
    // chain lock is held for the shortest possible time, and the audit row joins
    // the same client. If the trail cannot be written, nothing is written at all.
    const record = await this.prisma.$transaction(
      async (tx) => {
        const saved = await this.profiles.upsertForUser(actor.id, input, tx);

        await this.record(
          previous === null
            ? ATHLETE_AUDIT_ACTIONS.PROFILE_CREATE
            : ATHLETE_AUDIT_ACTIONS.PROFILE_UPDATE,
          actor,
          changedFields(previous, input),
          context,
          tx,
        );

        return saved;
      },
      { maxWait: 5_000, timeout: 10_000 },
    );

    return this.toView(record);
  }

  /**
   * The lookup is keyed by the caller, so a foreign row can only come back from
   * a bug or a future admin path; either way the ownership check - not a local
   * id comparison - is what answers, so the refusal is audited like any other.
   */
  private async loadOwn(
    actor: PolicySubject,
    context: AccessPolicyContext,
  ): Promise<AthleteProfileRecord | null> {
    const record = await this.profiles.findByUserId(actor.id);

    if (record === null) return null;

    await this.ownership.assertOwnsResource(actor, record.userId, context);

    return record;
  }

  /**
   * Fail closed, like the admin endpoints: the row is written in the same
   * transaction, so a trail that cannot be written rolls the row back and the
   * request fails rather than report a change nobody can account for.
   */
  private async record(
    action: AthleteAuditAction,
    actor: PolicySubject,
    fields: readonly string[],
    context: AccessPolicyContext,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    try {
      await this.audit.record(
        {
          action,
          actorId: actor.id,
          actorRole: String(actor.role),
          targetType: AUDIT_TARGET_TYPE,
          // The caller's own id, never anybody else's.
          targetId: actor.id,
          requestId: context.requestId,
          ip: context.ip,
          metadata: { fields },
        },
        tx,
      );
    } catch {
      this.logger.warn({ requestId: context.requestId, action }, 'athlete audit failed');

      throw new ServiceUnavailableException();
    }
  }

  private toView(record: AthleteProfileRecord): AthleteProfileView {
    return {
      legalFirstName: record.legalFirstName,
      legalLastName: record.legalLastName,
      dateOfBirth: record.dateOfBirth,
      gender: record.gender,
      nationality: record.nationality,
      countryOfResidence: record.countryOfResidence,
      city: record.city,
      clubName: record.clubName,
      weightKg: record.weightKg,
      heightCm: record.heightCm,
      isMinor: isMinor(record.dateOfBirth, this.clock()),
      updatedAt: record.updatedAt.toISOString(),
    };
  }
}
