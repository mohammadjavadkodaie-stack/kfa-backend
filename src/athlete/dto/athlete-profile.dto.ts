import { Transform, type TransformFnParams } from 'class-transformer';
import {
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Length,
  Max,
  Min,
  registerDecorator,
  ValidatorConstraint,
  type ValidationOptions,
  type ValidatorConstraintInterface,
} from 'class-validator';
import { ISO_ALPHA2_CODES } from '../countries';
import {
  ageInYears,
  MAX_AGE_YEARS,
  MIN_AGE_YEARS,
  parseBirthDate,
  SYSTEM_CLOCK,
  type Clock,
} from '../profile/athlete-age';
import type { AthleteProfileInput, Gender } from '../profile/athlete-profile.repository';

/** Typed against the column enum, so the two cannot drift apart. */
const GENDERS: readonly Gender[] = ['FEMALE', 'MALE', 'OTHER', 'UNDISCLOSED'];

/** Trims before the length rules run, so whitespace is never a name. */
const trimmed = ({ value }: TransformFnParams): unknown =>
  typeof value === 'string' ? value.trim() : value;

/**
 * One birth date rule for both halves of the contract: the day has to exist and
 * the age that follows from it has to be plausible. A future date lands outside
 * the window on its own, so it needs no separate check.
 */
@ValidatorConstraint({ name: 'birthDate', async: false })
export class BirthDateConstraint implements ValidatorConstraintInterface {
  constructor(private readonly clock: Clock = SYSTEM_CLOCK) {}

  validate(value: unknown): boolean {
    const birth = parseBirthDate(value);

    if (birth === null) return false;

    const age = ageInYears(birth, this.clock());

    return age >= MIN_AGE_YEARS && age <= MAX_AGE_YEARS;
  }

  defaultMessage(): string {
    return `dateOfBirth must be a real date between ${MIN_AGE_YEARS} and ${MAX_AGE_YEARS} years ago`;
  }
}

export function IsBirthDate(options?: ValidationOptions): PropertyDecorator {
  return (target: object, propertyName: string | symbol): void => {
    registerDecorator({
      name: 'birthDate',
      target: target.constructor,
      propertyName: String(propertyName),
      options,
      validator: BirthDateConstraint,
    });
  };
}

/**
 * The caller's own profile, create or replace.
 *
 * There is no user id here on purpose: the owner is the verified principal, and
 * the strict global pipe rejects any key this class does not declare.
 */
export class AthleteProfileDto {
  @Transform(trimmed)
  @IsString()
  @Length(1, 100)
  legalFirstName!: string;

  @Transform(trimmed)
  @IsString()
  @Length(1, 100)
  legalLastName!: string;

  @IsBirthDate()
  dateOfBirth!: string;

  @IsIn(GENDERS)
  gender!: Gender;

  @IsIn(ISO_ALPHA2_CODES)
  nationality!: string;

  @IsIn(ISO_ALPHA2_CODES)
  countryOfResidence!: string;

  @Transform(trimmed)
  @IsString()
  @Length(1, 100)
  city!: string;

  // Omitted and null both mean "not given"; the repository stores NULL.
  @IsOptional()
  @Transform(trimmed)
  @IsString()
  @Length(1, 120)
  clubName?: string | null;

  @IsOptional()
  @IsInt()
  @Min(20)
  @Max(300)
  weightKg?: number | null;

  @IsOptional()
  @IsInt()
  @Min(100)
  @Max(250)
  heightCm?: number | null;
}

/** Written out instead of spread, so a stray key can never reach storage. */
export function toProfileInput(dto: AthleteProfileDto): AthleteProfileInput {
  return {
    legalFirstName: dto.legalFirstName,
    legalLastName: dto.legalLastName,
    dateOfBirth: dto.dateOfBirth,
    gender: dto.gender,
    nationality: dto.nationality,
    countryOfResidence: dto.countryOfResidence,
    city: dto.city,
    clubName: dto.clubName ?? null,
    weightKg: dto.weightKg ?? null,
    heightCm: dto.heightCm ?? null,
  };
}
