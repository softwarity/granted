import { HttpStatus, RequestMethod } from '@nestjs/common';
import { BooleanSpec } from './boolean-spec';

/**
 * OpenAPI side of `@GrantedTo`: each route's specs are written under the
 * metadata keys `@nestjs/swagger` reads for `@ApiSecurity()` and
 * `@ApiResponse()` — no dependency on it, the metadata is just unused without.
 *
 * - `security`: a spec is reduced to role alternatives. The entries of
 *   `security` are alternatives (`or`), the roles of one entry are all required
 *   (`and`): `or(hasRole(A), and(hasRole(B), hasRole(C)))` →
 *   `[{ bearer: [A] }, { bearer: [B, C] }]`. A branch with no role (`isUser`,
 *   `isAuthenticated`, a custom spec…) gives `{ bearer: [] }`: authenticated;
 *   `isTrue()` gives `{}`: anonymous.
 * - a `403` response, described by the rule in clear:
 *   `Forbidden unless: hasRole(A) or (hasRole(B) and hasRole(C))`.
 *
 * Decorators only register the routes; they are written when `GrantedModule`
 * is instantiated — every decorator (`@HttpCode()`, `@ApiResponse()`…) applied,
 * and before the host calls `SwaggerModule.createDocument()`.
 */

const API_SECURITY = 'swagger/apiSecurity';
const API_RESPONSE = 'swagger/apiResponse';
// Constants of @nestjs/common: set by @Get(), @Post()… and by @HttpCode() on a route handler.
const METHOD_METADATA = 'method';
const HTTP_CODE_METADATA = '__httpCode__';

/** One alternative: the roles it requires, or `null` for an anonymous caller. */
type Alternative = string[] | null;
type Handler = (...args: never[]) => unknown;
type ControllerClass = abstract new (...args: never[]) => unknown;
type Responses = Record<string, object>;

interface SpecDescription {
  alternatives: Alternative[];
  label: string;
  // Combines several specs: wrapped in parentheses inside another combination.
  compound: boolean;
}

const descriptions = new WeakMap<BooleanSpec, SpecDescription>();

/** Records how a spec reads in the OpenAPI document; returns the spec. */
export function describeSpec(spec: BooleanSpec, alternatives: Alternative[], label = spec.id, compound = false): BooleanSpec {
  descriptions.set(spec, { alternatives, label, compound });
  return spec;
}

/** A spec not described (a custom one) counts as authenticated, labelled by its id. */
function descriptionOf(spec: BooleanSpec): SpecDescription {
  return descriptions.get(spec) ?? { alternatives: [[]], label: spec.id, compound: false };
}

/** Label of specs joined by `and` / `or`; a combination inside is wrapped in parentheses. */
export function joinLabels(specs: BooleanSpec[], operator: 'and' | 'or'): string {
  return specs
    .map(descriptionOf)
    .map(({ label, compound }) => (compound && specs.length > 1 ? `(${label})` : label))
    .join(` ${operator} `);
}

/** Every alternative of each spec combined with every alternative of the others. */
export function andAlternatives(specs: BooleanSpec[]): Alternative[] {
  return specs.reduce<Alternative[]>(
    (combined, spec) =>
      combined.flatMap((left) =>
        descriptionOf(spec).alternatives.map((right) => {
          if (left === null) {
            return right;
          }
          return right === null ? left : [...new Set([...left, ...right])];
        }),
      ),
    [null],
  );
}

export function orAlternatives(specs: BooleanSpec[]): Alternative[] {
  return specs.flatMap((spec) => descriptionOf(spec).alternatives);
}

interface GrantedRoute {
  handler: Handler;
  controller: ControllerClass;
  // What was last written, removed by identity on rewrite: what the host declared stays.
  security: object[];
  responses: Responses;
}

const routes = new Map<Handler, GrantedRoute>();

/**
 * Called by `@GrantedTo` on a handler (`target` = prototype) or a controller
 * (`target` = class): registers the routes concerned.
 */
export function documentGrantedTo(target: object, handler?: Handler): void {
  if (handler) {
    track(handler, target.constructor as ControllerClass);
    return;
  }
  const controller = target as ControllerClass;
  for (const key of Object.getOwnPropertyNames(controller.prototype)) {
    const value = Object.getOwnPropertyDescriptor(controller.prototype, key)?.value;
    if (key !== 'constructor' && typeof value === 'function' && Reflect.hasMetadata(METHOD_METADATA, value)) {
      track(value, controller);
    }
  }
}

function track(handler: Handler, controller: ControllerClass): void {
  if (!routes.has(handler)) {
    routes.set(handler, { handler, controller, security: [], responses: {} });
  }
}

/** Writes the OpenAPI metadata of every registered route, class and method specs merged as the guard does. */
export function writeOpenApi(securityScheme: string): void {
  routes.forEach((route) => {
    const specs: BooleanSpec[] = [...(Reflect.getMetadata('booleanSpecs', route.handler) ?? []), ...(Reflect.getMetadata('booleanSpecs', route.controller) ?? [])];
    const alternatives = andAlternatives(specs);
    writeSecurity(route, alternatives, securityScheme);
    // No 403 when an anonymous caller gets through anyway.
    writeResponses(route, alternatives.includes(null) ? undefined : `Forbidden unless: ${joinLabels(specs, 'and')}`);
  });
}

function writeSecurity(route: GrantedRoute, alternatives: Alternative[], securityScheme: string): void {
  const seen = new Set<string>();
  const requirements = alternatives
    .filter((alternative) => {
      const key = JSON.stringify(alternative);
      return !seen.has(key) && !!seen.add(key);
    })
    .map((alternative) => (alternative === null ? {} : { [securityScheme]: alternative }));
  const declared = ((Reflect.getMetadata(API_SECURITY, route.handler) ?? []) as object[]).filter((requirement) => !route.security.includes(requirement));
  route.security = requirements;
  // An empty `security` would mean "no security": nothing granted (isFalse()) writes nothing.
  if (declared.length || requirements.length) {
    Reflect.defineMetadata(API_SECURITY, [...declared, ...requirements], route.handler);
  } else {
    Reflect.deleteMetadata(API_SECURITY, route.handler);
  }
}

function writeResponses(route: GrantedRoute, forbidden: string | undefined): void {
  const declared: Responses = { ...Reflect.getMetadata(API_RESPONSE, route.handler) };
  for (const [status, response] of Object.entries(route.responses)) {
    if (declared[status] === response) {
      delete declared[status];
    }
  }
  const written: Responses = {};
  if (forbidden) {
    // A route with responses loses swagger's default one: put it back when the host declared none.
    if (Object.keys(declared).length === 0) {
      written[defaultStatus(route.handler)] = { description: '' };
    }
    // A 403 the host declared, on the route or the controller, wins.
    if (!declared[HttpStatus.FORBIDDEN] && !Reflect.getMetadata(API_RESPONSE, route.controller)?.[HttpStatus.FORBIDDEN]) {
      written[HttpStatus.FORBIDDEN] = { description: forbidden };
    }
  }
  route.responses = written;
  const responses = { ...declared, ...written };
  if (Object.keys(responses).length) {
    Reflect.defineMetadata(API_RESPONSE, responses, route.handler);
  } else {
    Reflect.deleteMetadata(API_RESPONSE, route.handler);
  }
}

/** The status swagger documents for a route without declared responses. */
function defaultStatus(handler: Handler): number {
  return Reflect.getMetadata(HTTP_CODE_METADATA, handler) ?? (Reflect.getMetadata(METHOD_METADATA, handler) === RequestMethod.POST ? HttpStatus.CREATED : HttpStatus.OK);
}
