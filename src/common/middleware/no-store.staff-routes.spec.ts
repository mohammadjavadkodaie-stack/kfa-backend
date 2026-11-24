import {
  Controller,
  ForbiddenException,
  Get,
  type INestApplication,
  Module,
  type MiddlewareConsumer,
  type NestModule,
  Post,
  Query,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AdminUsersController } from '../../admin/admin-users.controller';
import { AdminUsersModule } from '../../admin/admin-users.module';
import { StaffPhotoReviewController } from '../../staff-photo-review/staff-photo-review.controller';
import { StaffPhotoReviewModule } from '../../staff-photo-review/staff-photo-review.module';
import { StaffReviewController } from '../../staff-review/staff-review.controller';
import { StaffReviewModule } from '../../staff-review/staff-review.module';
import { noStoreMiddleware } from './no-store.middleware';

/**
 * `Cache-Control: no-store` on the staff routes that answer with personal data.
 *
 * The middleware is applied at module level, so the header is set before any
 * guard runs: a refusal is as uncacheable as a success. The modules below are
 * the real ones and their own `configure` is what runs; only the handlers
 * underneath are probes, because the point here is the wiring and the header,
 * not the data.
 */

/** The controller each module must cover, and the path it is served under. */
const GROUPS = [
  { path: '/admin/users', module: AdminUsersModule, controller: AdminUsersController },
  { path: '/staff/reviews', module: StaffReviewModule, controller: StaffReviewController },
  {
    path: '/staff/photo-reviews',
    module: StaffPhotoReviewModule,
    controller: StaffPhotoReviewController,
  },
];

/** A `MiddlewareConsumer` that records what a module asks Nest to apply. */
class RecordingConsumer {
  readonly applied: unknown[][] = [];
  readonly scoped: unknown[][] = [];

  apply(...middleware: unknown[]): this {
    this.applied.push(middleware);
    return this;
  }

  forRoutes(...routes: unknown[]): this {
    this.scoped.push(routes);
    return this;
  }
}

describe('no-store wiring', () => {
  it.each(GROUPS)(
    '$path applies the shared no-store middleware to its whole controller',
    ({ module, controller }) => {
      const consumer = new RecordingConsumer();

      new module().configure(consumer as unknown as MiddlewareConsumer);

      expect(consumer.applied).toEqual([[noStoreMiddleware]]);
      // The class, not a list of methods: every verb of the controller is covered.
      expect(consumer.scoped).toEqual([[controller]]);
    },
  );
});

/** A page of accounts, refused with the generic 403 a guard answers with. */
@Controller('admin/users')
class AdminUsersProbe {
  @Get()
  list(@Query('refuse') refuse?: string): { items: readonly string[] } {
    if (refuse !== undefined) throw new ForbiddenException();

    return { items: [] };
  }

  /** Not a GET: the middleware must cover the other verbs as well. */
  @Post(':id/block')
  block(): void {}
}

/** The review queue, refused with the 503 a dead store answers with. */
@Controller('staff/reviews')
class StaffReviewProbe {
  @Get()
  list(@Query('refuse') refuse?: string): { items: readonly string[] } {
    if (refuse !== undefined) throw new ServiceUnavailableException();

    return { items: [] };
  }
}

/** The photo queue, refused with the same generic 403. */
@Controller('staff/photo-reviews')
class StaffPhotoReviewProbe {
  @Get()
  list(@Query('refuse') refuse?: string): { items: readonly string[] } {
    if (refuse !== undefined) throw new ForbiddenException();

    return { items: [] };
  }
}

/** A route outside the three groups: nothing may add the header here. */
@Controller('health')
class OutsideProbe {
  @Get()
  read(): { status: string } {
    return { status: 'ok' };
  }
}

/**
 * The production wiring, run by Nest itself: each module's own `configure`
 * registers its middleware, and the probes stand in for the handlers it guards.
 */
@Module({ controllers: [AdminUsersProbe, StaffReviewProbe, StaffPhotoReviewProbe, OutsideProbe] })
class ProbeModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    for (const group of GROUPS) {
      new group.module().configure(consumer);
    }
  }
}

describe('no-store on the answers', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [ProbeModule] }).compile();

    app = moduleRef.createNestApplication({ logger: false });
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it.each(GROUPS)('$path carries the header on success and on refusal', async ({ path }) => {
    const success = await request(app.getHttpServer()).get(path);
    const refusal = await request(app.getHttpServer()).get(`${path}?refuse=1`);

    expect(success.status).toBe(200);
    // 403 from a guard, 503 from a store that cannot answer.
    expect([403, 503]).toContain(refusal.status);
    expect(success.headers['cache-control']).toBe('no-store');
    expect(refusal.headers['cache-control']).toBe('no-store');
  });

  it('covers a non-GET route of a protected controller', async () => {
    const response = await request(app.getHttpServer()).post('/admin/users/1/block');

    expect(response.status).toBe(201);
    expect(response.headers['cache-control']).toBe('no-store');
  });

  it('leaves a route outside the groups untouched', async () => {
    const response = await request(app.getHttpServer()).get('/health');

    expect(response.status).toBe(200);
    expect(response.headers['cache-control']).toBeUndefined();
  });
});
