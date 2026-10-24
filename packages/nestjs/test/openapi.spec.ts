import { Controller, Get, HttpCode, INestApplication, Post } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { ApiForbiddenResponse, ApiNotFoundResponse, DocumentBuilder, OpenAPIObject, SwaggerModule } from '@nestjs/swagger';
import { GrantedTo } from '../src/decorators/granted-to.decorator';
import { GrantedModule } from '../src/granted.module';
import { and, hasRole, isAuthenticated, isFalse, isTrue, isUser, not, or } from '../src/security/boolean-spec';

@Controller('items')
@GrantedTo(hasRole('USER'))
class ItemsController {
  @Get()
  list() {}

  @Post()
  @GrantedTo(or(hasRole('ADMIN'), and(hasRole('MANAGER'), hasRole('AUDIT'))))
  create() {}
}

@Controller('users')
class UsersController {
  @Get(':id')
  @GrantedTo(or(hasRole('ADMIN'), isUser('Param', 'id')))
  get() {}

  @Get()
  @GrantedTo(isAuthenticated(), not(hasRole('GUEST')))
  list() {}

  @Get('public/all')
  @GrantedTo(isTrue())
  open() {}

  @Post('never')
  @GrantedTo(isFalse())
  never() {}

  @Post()
  ungranted() {}
}

@Controller('orders')
class OrdersController {
  @GrantedTo(hasRole('ADMIN'))
  @HttpCode(204)
  @Post('purge')
  purge() {}

  @GrantedTo(hasRole('ADMIN'))
  @ApiNotFoundResponse({ description: 'No such order' })
  @Get(':id')
  get() {}

  @ApiForbiddenResponse({ description: 'Admins only' })
  @GrantedTo(hasRole('ADMIN'))
  @Post(':id/cancel')
  cancel() {}
}

async function document(scheme?: string): Promise<OpenAPIObject> {
  const moduleRef = await Test.createTestingModule({
    imports: [GrantedModule.forRoot(scheme ? { openApiSecurityScheme: scheme } : {})],
    controllers: [ItemsController, UsersController, OrdersController],
  }).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  await app.init();
  const doc = SwaggerModule.createDocument(app, new DocumentBuilder().addBearerAuth().build());
  await app.close();
  return doc;
}

describe('OpenAPI security written by @GrantedTo', () => {
  let doc: OpenAPIObject;
  beforeAll(async () => {
    doc = await document();
  });

  it('writes the class-level roles on a route without its own @GrantedTo', () => {
    expect(doc.paths['/items'].get.security).toEqual([{ bearer: ['USER'] }]);
  });

  it('merges class and method specs: or → entries, and → roles of one entry', () => {
    expect(doc.paths['/items'].post.security).toEqual([{ bearer: ['ADMIN', 'USER'] }, { bearer: ['MANAGER', 'AUDIT', 'USER'] }]);
  });

  it('a branch with no role is an authenticated caller', () => {
    expect(doc.paths['/users/{id}'].get.security).toEqual([{ bearer: ['ADMIN'] }, { bearer: [] }]);
    expect(doc.paths['/users'].get.security).toEqual([{ bearer: [] }]);
  });

  it('isTrue() is an anonymous caller, isFalse() writes nothing', () => {
    expect(doc.paths['/users/public/all'].get.security).toEqual([{}]);
    expect(doc.paths['/users/never'].post.security).toBeUndefined();
  });

  it('leaves a route without @GrantedTo alone', () => {
    expect(doc.paths['/users'].post.security).toBeUndefined();
  });

  it('describes the merged rule in a 403 response, keeping the default one', () => {
    expect(doc.paths['/items'].get.responses).toEqual({ '200': { description: '' }, '403': { description: 'Forbidden unless: hasRole(USER)' } });
    expect(doc.paths['/items'].post.responses['403']).toEqual({
      description: 'Forbidden unless: (hasRole(ADMIN) or (hasRole(MANAGER) and hasRole(AUDIT))) and hasRole(USER)',
    });
    expect(doc.paths['/items'].post.responses['201']).toEqual({ description: '' });
    expect(doc.paths['/users'].get.responses['403']).toEqual({ description: 'Forbidden unless: isAuthenticated() and not(hasRole(GUEST))' });
  });

  it('no 403 when an anonymous caller gets through, nor on a route without @GrantedTo', () => {
    expect(doc.paths['/users/public/all'].get.responses).toEqual({ '200': { description: '' } });
    expect(doc.paths['/users'].post.responses).toEqual({ '201': { description: '' } });
  });

  it('keeps the @HttpCode, the responses and the 403 the host declared', () => {
    expect(doc.paths['/orders/purge'].post.responses).toEqual({ '204': { description: '' }, '403': { description: 'Forbidden unless: hasRole(ADMIN)' } });
    expect(doc.paths['/orders/{id}'].get.responses).toEqual({ '404': { description: 'No such order' }, '403': { description: 'Forbidden unless: hasRole(ADMIN)' } });
    expect(doc.paths['/orders/{id}/cancel'].post.responses['403']).toEqual({ description: 'Admins only' });
  });

  it('writes under the configured scheme name', async () => {
    const custom = await document('jwt');
    expect(custom.paths['/items'].get.security).toEqual([{ jwt: ['USER'] }]);
    expect(custom.paths['/users/{id}'].get.security).toEqual([{ jwt: ['ADMIN'] }, { jwt: [] }]);
  });
});
