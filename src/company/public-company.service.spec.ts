import { NotFoundException } from '@nestjs/common';
import type { CompanyKind } from '@prisma/client';
import type { PublicCompanyQuery } from './public-company.dto';
import type { PublicCompanyRepository, PublicCompanyRow } from './public-company.repository';
import { PublicCompanyService } from './public-company.service';

/**
 * The public company read model without PostgreSQL.
 *
 * The fake applies the same predicates the real repository holds (live rows only,
 * `slug > cursor`, optional kind), which is how a soft-deleted company is shown
 * to disappear. One row deliberately carries every staff-only column: the
 * whitelist case proves the service rebuilds the answer field by field instead of
 * forwarding whatever the repository returned.
 */

const ACTOR_ID = '11111111-1111-4111-8111-111111111111';

/** A repository row plus, optionally, anything else a wider select may carry. */
type FakeRow = PublicCompanyRow & { readonly [field: string]: unknown };

/** The staff-only fields, with values distinctive enough to spot in JSON. */
const STAFF_ONLY = {
  id: '22222222-2222-4222-8222-222222222222',
  legalName: 'Acme Rockets Anonim Sirketi',
  tradeRegistryNumber: '1234567890',
  mersisNumber: '1234567890123456',
  taxNumber: '9876543210',
  taxOffice: 'Nilufer Vergi Dairesi',
  chamberName: 'Bursa Chamber of Commerce',
  chamberRegisteredAt: new Date('2020-01-02T00:00:00.000Z'),
  naceCode: '12.34.56',
  address: '123 Gizli Sokak No 4',
  contactEmail: 'secret-contact@example.com',
  createdById: ACTOR_ID,
  updatedById: ACTOR_ID,
  createdAt: new Date('2026-11-01T00:00:00.000Z'),
  updatedAt: new Date('2026-11-02T00:00:00.000Z'),
  deletedAt: null,
} as const;

function row(slug: string, kind: CompanyKind = 'ORGANIZER'): FakeRow {
  return {
    slug,
    displayName: `Company ${slug}`,
    country: 'TR',
    kind,
    description: null,
    websiteUrl: null,
  };
}

class FakePublicCompanies implements PublicCompanyRepository {
  readonly rows = new Map<string, FakeRow>();
  readonly retired = new Set<string>();
  readonly listCalls: {
    limit: number;
    cursor: string | undefined;
    kind: CompanyKind | undefined;
  }[] = [];
  readonly readCalls: string[] = [];

  seed(row: FakeRow, deleted = false): void {
    this.rows.set(row.slug, row);

    if (deleted) this.retired.add(row.slug);
  }

  private live(): FakeRow[] {
    return [...this.rows.values()]
      .filter((row) => !this.retired.has(row.slug))
      .sort((left, right) => (left.slug < right.slug ? -1 : left.slug > right.slug ? 1 : 0));
  }

  async listAlphabetical(
    limit: number,
    cursor: string | undefined,
    kind?: CompanyKind,
  ): Promise<PublicCompanyRow[]> {
    this.listCalls.push({ limit, cursor, kind });

    return this.live()
      .filter((row) => kind === undefined || row.kind === kind)
      .filter((row) => cursor === undefined || row.slug > cursor)
      .slice(0, limit + 1);
  }

  async findActiveBySlug(slug: string): Promise<PublicCompanyRow | null> {
    this.readCalls.push(slug);

    const row = this.rows.get(slug);

    return row === undefined || this.retired.has(slug) ? null : row;
  }
}

function createService() {
  const repository = new FakePublicCompanies();
  const service = new PublicCompanyService(repository);

  return { service, repository };
}

function query(overrides: Partial<PublicCompanyQuery> = {}): PublicCompanyQuery {
  return { limit: 20, ...overrides };
}

describe('PublicCompanyService', () => {
  it('lists live companies alphabetically and leaves a retired one out', async () => {
    const { service, repository } = createService();

    repository.seed(row('charlie-co'));
    repository.seed(row('alpha-co'));
    repository.seed(row('bravo-co'), true);

    const page = await service.list(query());

    expect(page.items.map((item) => item.slug)).toEqual(['alpha-co', 'charlie-co']);
    expect(page.nextCursor).toBeNull();
    expect(JSON.stringify(page)).not.toContain('bravo-co');
  });

  it('pages with the limit + 1 sentinel and ends with a null cursor', async () => {
    const { service, repository } = createService();

    for (const slug of ['alpha-co', 'bravo-co', 'charlie-co', 'delta-co', 'echo-co']) {
      repository.seed(row(slug));
    }

    const first = await service.list(query({ limit: 2 }));

    expect(first.items.map((item) => item.slug)).toEqual(['alpha-co', 'bravo-co']);
    expect(first.nextCursor).toBe('bravo-co');

    const second = await service.list(query({ limit: 2, cursor: first.nextCursor ?? undefined }));

    expect(second.items.map((item) => item.slug)).toEqual(['charlie-co', 'delta-co']);
    expect(second.nextCursor).toBe('delta-co');

    const third = await service.list(query({ limit: 2, cursor: second.nextCursor ?? undefined }));

    expect(third.items.map((item) => item.slug)).toEqual(['echo-co']);
    // The sentinel row was read but never returned.
    expect(third.nextCursor).toBeNull();
    expect(repository.listCalls).toEqual([
      { limit: 2, cursor: undefined, kind: undefined },
      { limit: 2, cursor: 'bravo-co', kind: undefined },
      { limit: 2, cursor: 'delta-co', kind: undefined },
    ]);
  });

  it('returns exactly the six public fields even when the row carries every staff column', async () => {
    const { service, repository } = createService();

    repository.seed({
      ...row('acme-rockets', 'SPONSOR'),
      ...STAFF_ONLY,
      displayName: 'Acme Rockets',
      description: 'We build sounding rockets.',
      websiteUrl: 'https://acme.example',
    });

    const page = await service.list(query());
    const item = await service.read('acme-rockets');
    const serialized = JSON.stringify({ page, item });

    for (const forbidden of [
      'id',
      'legalName',
      'tradeRegistryNumber',
      'mersisNumber',
      'taxNumber',
      'taxOffice',
      'chamberName',
      'chamberRegisteredAt',
      'naceCode',
      'address',
      'contactEmail',
      'createdById',
      'updatedById',
      'createdAt',
      'updatedAt',
      'deletedAt',
      'Anonim',
      'Nilufer Vergi Dairesi',
      'Bursa Chamber of Commerce',
      '123 Gizli Sokak',
      'secret-contact@example.com',
      '1234567890123456',
      '12.34.56',
      ACTOR_ID,
    ]) {
      expect(serialized).not.toContain(forbidden);
    }

    const expectedKeys = ['country', 'description', 'displayName', 'kind', 'slug', 'websiteUrl'];

    expect(Object.keys(item).sort()).toEqual(expectedKeys);
    expect(Object.keys(page.items[0] ?? {}).sort()).toEqual(expectedKeys);
    expect(item).toEqual({
      slug: 'acme-rockets',
      displayName: 'Acme Rockets',
      country: 'TR',
      kind: 'SPONSOR',
      description: 'We build sounding rockets.',
      websiteUrl: 'https://acme.example',
    });
  });

  it('passes the kind filter through to the live, alphabetical page', async () => {
    const { service, repository } = createService();

    repository.seed(row('alpha-co', 'SPONSOR'));
    repository.seed(row('bravo-co', 'ORGANIZER'));
    repository.seed(row('charlie-co', 'SPONSOR'), true);

    const page = await service.list(query({ kind: 'SPONSOR' }));

    expect(page.items.map((item) => item.slug)).toEqual(['alpha-co']);
    expect(repository.listCalls).toEqual([{ limit: 20, cursor: undefined, kind: 'SPONSOR' }]);
  });

  it('answers one generic 404 for missing, soft-deleted and malformed slugs alike', async () => {
    const { service, repository } = createService();

    repository.seed(row('retired-co'), true);

    const failures = await Promise.all(
      ['missing-co', 'retired-co', 'Not A Slug'].map((slug) =>
        service.read(slug).then(
          () => null,
          (error: unknown) => error,
        ),
      ),
    );

    for (const failure of failures) {
      expect(failure).toBeInstanceOf(NotFoundException);
      expect((failure as NotFoundException).getStatus()).toBe(404);
      expect((failure as NotFoundException).message).toBe('Not Found');
    }

    // The refusal carries no reason and no slug: the three bodies are identical.
    const bodies = failures.map((failure) =>
      JSON.stringify((failure as NotFoundException).getResponse()),
    );

    expect(new Set(bodies).size).toBe(1);

    for (const body of bodies) {
      expect(body).not.toContain('retired-co');
      expect(body).not.toContain('missing-co');
      expect(body).not.toContain('Not A Slug');
    }

    // A malformed slug never reaches the table.
    expect(repository.readCalls).toEqual(['missing-co', 'retired-co']);
  });
});
