import { NotFoundException } from '@nestjs/common';
import type { PublicRankingRepository, PublicRankingRow } from './public-ranking.repository';
import { PublicRankingService } from './public-ranking.service';

/**
 * The public read model without PostgreSQL.
 *
 * The fake applies the same predicate the real repository holds (approved set
 * joined at read time), which is how a stale ranking row for an un-approved
 * profile is shown to disappear. Ordering, ties, the limit + 1 sentinel and one
 * generic 404 are the facts this spec pins.
 */

const PROFILE_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PROFILE_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PROFILE_C = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const PROFILE_D = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const PROFILE_E = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

class FakePublicRanking implements PublicRankingRepository {
  readonly rows = new Map<string, PublicRankingRow>();
  readonly approved = new Set<string>();
  readonly listCalls: { limit: number; cursor: string | undefined }[] = [];

  seed(athleteProfileId: string, totalPoints: number, rank: number, approved = true): void {
    this.rows.set(athleteProfileId, { athleteProfileId, totalPoints, rank });

    if (approved) this.approved.add(athleteProfileId);
  }

  private visible(): PublicRankingRow[] {
    return [...this.rows.values()]
      .filter((row) => this.approved.has(row.athleteProfileId))
      .sort(
        (left, right) =>
          left.rank - right.rank || left.athleteProfileId.localeCompare(right.athleteProfileId),
      );
  }

  async listApproved(limit: number, cursor: string | undefined): Promise<PublicRankingRow[]> {
    this.listCalls.push({ limit, cursor });

    const rows = this.visible();
    const start =
      cursor === undefined ? 0 : rows.findIndex((row) => row.athleteProfileId === cursor) + 1;

    return rows.slice(start, start + limit + 1);
  }

  async findApproved(athleteProfileId: string): Promise<PublicRankingRow | null> {
    const row = this.rows.get(athleteProfileId);

    if (row === undefined || !this.approved.has(athleteProfileId)) return null;

    return row;
  }
}

function createService() {
  const repository = new FakePublicRanking();
  const service = new PublicRankingService(repository);

  return { service, repository };
}

describe('PublicRankingService', () => {
  it('orders by rank and returns ties with the same rank', async () => {
    const { service, repository } = createService();

    repository.seed(PROFILE_C, 30, 2);
    repository.seed(PROFILE_B, 30, 2);
    repository.seed(PROFILE_A, 50, 1);

    const page = await service.list({ limit: 20 });

    expect(page.items.map((item) => item.athleteProfileId)).toEqual([
      PROFILE_A,
      PROFILE_B,
      PROFILE_C,
    ]);
    expect(page.items.map((item) => item.rank)).toEqual([1, 2, 2]);
    expect(page.nextCursor).toBeNull();
  });

  it('drops an un-approved athlete at read time even with a stale ranking row', async () => {
    const { service, repository } = createService();

    repository.seed(PROFILE_A, 50, 1);
    repository.seed(PROFILE_B, 30, 2, false);
    repository.seed(PROFILE_C, 10, 3);

    const page = await service.list({ limit: 20 });

    expect(page.items.map((item) => item.athleteProfileId)).toEqual([PROFILE_A, PROFILE_C]);
    expect(JSON.stringify(page)).not.toContain(PROFILE_B);
  });

  it('pages with the limit + 1 sentinel and ends with a null cursor', async () => {
    const { service, repository } = createService();

    repository.seed(PROFILE_A, 50, 1);
    repository.seed(PROFILE_B, 40, 2);
    repository.seed(PROFILE_C, 30, 3);
    repository.seed(PROFILE_D, 20, 4);
    repository.seed(PROFILE_E, 10, 5);

    const first = await service.list({ limit: 2 });

    expect(first.items).toHaveLength(2);
    expect(first.nextCursor).toBe(PROFILE_B);

    const second = await service.list({ limit: 2, cursor: first.nextCursor ?? undefined });

    expect(second.items.map((item) => item.athleteProfileId)).toEqual([PROFILE_C, PROFILE_D]);
    expect(second.nextCursor).toBe(PROFILE_D);

    const third = await service.list({ limit: 2, cursor: second.nextCursor ?? undefined });

    expect(third.items.map((item) => item.athleteProfileId)).toEqual([PROFILE_E]);
    // The sentinel row was read but never returned.
    expect(third.nextCursor).toBeNull();
    expect(repository.listCalls).toEqual([
      { limit: 2, cursor: undefined },
      { limit: 2, cursor: PROFILE_B },
      { limit: 2, cursor: PROFILE_D },
    ]);
  });

  it('returns exactly the three public fields, nothing identity or result shaped', async () => {
    const { service, repository } = createService();

    repository.seed(PROFILE_A, 50, 1);
    repository.seed(PROFILE_B, 30, 2);

    const serialized = JSON.stringify(await service.list({ limit: 20 }));

    for (const forbidden of [
      'userId',
      'email',
      'enteredById',
      'enteredBy',
      'eventName',
      'eventDate',
      'createdAt',
      'reviewStatus',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }

    const item = (JSON.parse(serialized) as { items: object[] }).items[0];

    expect(Object.keys(item ?? {}).sort()).toEqual(['athleteProfileId', 'rank', 'totalPoints']);
  });

  it('reads one approved athlete', async () => {
    const { service, repository } = createService();

    repository.seed(PROFILE_A, 50, 1);

    await expect(service.read(PROFILE_A)).resolves.toEqual({
      athleteProfileId: PROFILE_A,
      totalPoints: 50,
      rank: 1,
    });
  });

  it('answers one generic 404 for missing and un-approved profiles alike', async () => {
    const { service, repository } = createService();

    repository.seed(PROFILE_B, 30, 2, false);

    const failures = await Promise.all(
      [PROFILE_A, PROFILE_B].map((id) =>
        service.read(id).then(
          () => null,
          (error: unknown) => error,
        ),
      ),
    );

    for (const failure of failures) expect(failure).toBeInstanceOf(NotFoundException);

    // The refusal carries no reason and no id.
    expect((failures[0] as NotFoundException).message).toBe('Not Found');
    expect(JSON.stringify((failures[1] as NotFoundException).getResponse())).not.toContain(
      PROFILE_B,
    );
  });
});
