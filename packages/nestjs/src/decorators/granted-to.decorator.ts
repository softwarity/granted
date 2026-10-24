import { SetMetadata } from '@nestjs/common';
import { BooleanSpec } from '../security/boolean-spec';
import { documentGrantedTo } from '../security/openapi';

/**
 * Attaches authorization specs to a route handler **or** a controller class.
 *
 * Applied to a class, the specs become a baseline for every route in that
 * controller; applied to a method they tighten it further. The guard merges
 * both levels and requires **all** specs (class + method) to pass.
 *
 * The merged specs also go in the OpenAPI document, read by `@nestjs/swagger`:
 * the route's `security` (one entry per alternative, listing the roles it
 * requires) and a `403` response describing the rule.
 */
export const GrantedTo =
  (...booleanSpecs: BooleanSpec[]): MethodDecorator & ClassDecorator =>
  (target: object, key?: string | symbol, descriptor?: PropertyDescriptor) => {
    SetMetadata('booleanSpecs', booleanSpecs)(target, key as string | symbol, descriptor as PropertyDescriptor);
    // Also the route's `security` and `403` in the OpenAPI document, when the host generates one.
    documentGrantedTo(target, descriptor?.value);
  };
