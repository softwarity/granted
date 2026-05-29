import { SetMetadata } from '@nestjs/common';
import { BooleanSpec } from '../security/boolean-spec';

/**
 * Attaches authorization specs to a route handler **or** a controller class.
 *
 * Applied to a class, the specs become a baseline for every route in that
 * controller; applied to a method they tighten it further. The guard merges
 * both levels and requires **all** specs (class + method) to pass.
 */
export const GrantedTo = (...booleanSpecs: BooleanSpec[]) => SetMetadata('booleanSpecs', booleanSpecs);
