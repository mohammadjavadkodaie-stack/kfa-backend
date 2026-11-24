import { BadRequestException } from '@nestjs/common';
import { ROLES_KEY } from '../auth/decorators/roles.decorator';
import type { AuthenticatedRequest } from '../auth/guards/auth.guard';
import { Role } from '../auth/roles';
import { STEP_UP_REQUIRED_KEY } from '../auth/totp/step-up.guard';
import type { CompanyRow } from './company.repository';
import type { CompanyService } from './company.service';
import { StaffCompanyController } from './staff-company.controller';

/**
 * The staff company routes at the controller seam: what the route decorators
 * declare, and what the controller hands the service.
 *
 * The guards themselves are global and are covered by the route-marker sweep;
 * here the point is that a route cannot lose its role or step-up marker, that a
 * body carrying an undeclared key never reaches the service, and that the actor
 * and request facts come from the verified principal, not the body.
 */

const ACTOR_ID = '11111111-1111-4111-8111-111111111111';

const ROW: CompanyRow = {
  id: '22222222-2222-4222-8222-222222222222',
  slug: 'bursa-atletizm-kulubu',
  displayName: 'Bursa Atletizm Kulübü',
  country: 'TR',
  kind: 'ORGANIZER',
  description: null,
  websiteUrl: null,
  legalName: 'Bursa Atletizm Kulübü Derneği',
  tradeRegistryNumber: null,
  mersisNumber: null,
  taxNumber: null,
  taxOffice: null,
  chamberName: null,
  chamberRegisteredAt: null,
  naceCode: null,
  address: null,
  contactEmail: null,
  createdById: ACTOR_ID,
  updatedById: ACTOR_ID,
  createdAt: new Date('2026-11-01T00:00:00.000Z'),
  updatedAt: new Date('2026-11-01T00:00:00.000Z'),
  deletedAt: null,
};

const VALID_BODY = {
  slug: 'bursa-atletizm-kulubu',
  displayName: 'Bursa Atletizm Kulübü',
  country: 'TR',
  kind: 'ORGANIZER',
  legalName: 'Bursa Atletizm Kulübü Derneği',
};

const request = {
  auth: { userId: ACTOR_ID, role: Role.ADMIN },
  id: 'req-company',
  ip: '203.0.113.9',
} as unknown as AuthenticatedRequest;

const ROUTES = ['list', 'get', 'create', 'update', 'remove'] as const;
const WRITES = ['create', 'update', 'remove'] as const;

function createController() {
  const companies = {
    list: jest.fn(async () => ({ items: [ROW], nextCursor: null })),
    get: jest.fn(async () => ROW),
    create: jest.fn(async () => ROW),
    update: jest.fn(async () => ROW),
    delete: jest.fn(async () => undefined),
  };
  const controller = new StaffCompanyController(companies as unknown as CompanyService);

  return { controller, companies };
}

describe('StaffCompanyController', () => {
  it.each(ROUTES)('%s is staff-only: ADMIN and OWNER, never USER or ATHLETE', (route) => {
    const handler = StaffCompanyController.prototype[route];

    expect(Reflect.getMetadata(ROLES_KEY, handler)).toEqual([Role.ADMIN, Role.OWNER]);
  });

  it.each(WRITES)('%s requires a step-up proof', (route) => {
    expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, StaffCompanyController.prototype[route])).toBe(
      true,
    );
  });

  it.each(['list', 'get'] as const)('%s is a read and needs no step-up proof', (route) => {
    expect(Reflect.getMetadata(STEP_UP_REQUIRED_KEY, StaffCompanyController.prototype[route])).toBe(
      undefined,
    );
  });

  it('creates with the principal and the request facts, never a body field', async () => {
    const { controller, companies } = createController();

    await controller.create(VALID_BODY, request);

    expect(companies.create).toHaveBeenCalledWith(
      expect.objectContaining({ slug: VALID_BODY.slug }),
      { id: ACTOR_ID, role: Role.ADMIN },
      { requestId: 'req-company', ip: '203.0.113.9' },
    );
  });

  it('refuses a create body with an undeclared key before the service runs', async () => {
    const { controller, companies } = createController();

    await expect(
      controller.create({ ...VALID_BODY, createdById: ACTOR_ID }, request),
    ).rejects.toThrow(BadRequestException);
    expect(companies.create).not.toHaveBeenCalled();
  });

  it('refuses a patch that tries to rename the slug', async () => {
    const { controller, companies } = createController();

    await expect(controller.update({ id: ROW.id }, { slug: 'yeni-slug' }, request)).rejects.toThrow(
      BadRequestException,
    );
    expect(companies.update).not.toHaveBeenCalled();
  });

  it('passes the path id and the parsed patch to the service', async () => {
    const { controller, companies } = createController();

    await controller.update({ id: ROW.id }, { displayName: 'Yeni Ad' }, request);

    expect(companies.update).toHaveBeenCalledWith(
      ROW.id,
      { displayName: 'Yeni Ad' },
      { id: ACTOR_ID, role: Role.ADMIN },
      { requestId: 'req-company', ip: '203.0.113.9' },
    );
  });

  it('passes the page window to the list and returns its page unchanged', async () => {
    const { controller, companies } = createController();

    const page = await controller.list({ limit: 5, cursor: ROW.id });

    expect(companies.list).toHaveBeenCalledWith(5, ROW.id);
    expect(page).toEqual({ items: [ROW], nextCursor: null });
  });

  it('deletes through the service and returns nothing', async () => {
    const { controller, companies } = createController();

    await expect(controller.remove({ id: ROW.id }, request)).resolves.toBeUndefined();
    expect(companies.delete).toHaveBeenCalledWith(
      ROW.id,
      { id: ACTOR_ID, role: Role.ADMIN },
      { requestId: 'req-company', ip: '203.0.113.9' },
    );
  });
});
