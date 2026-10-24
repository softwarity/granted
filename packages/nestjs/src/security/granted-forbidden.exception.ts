import { ForbiddenException } from '@nestjs/common';

/**
 * Thrown by the guard when a `@GrantedTo` spec rejects the request.
 *
 * The response body is the one NestJS sends for any guard returning `false`
 * (`{ statusCode: 403, message: 'Forbidden resource', error: 'Forbidden' }`):
 * the caller learns nothing about the policy. The details are carried as
 * properties, for the host app to log in its own format from an exception
 * filter (`exception instanceof GrantedForbiddenException`).
 */
export class GrantedForbiddenException extends ForbiddenException {
  constructor(
    /** `id` of the first spec that failed, e.g. `hasRole(ADMIN)` — an `and(...)` / `or(...)` is reported whole. */
    readonly deniedSpec: string,
    /** Caller's username, as read by the principal provider. */
    readonly username: string,
    /** Caller's roles after hierarchy expansion and `knownRoles` filtering — the ones the specs were evaluated against. */
    readonly roles: string[],
    /** Caller's tenant, if any. */
    readonly tenant?: string,
  ) {
    super('Forbidden resource');
  }
}
