/**
 * Role post-processing shared by the guard and the `@Roles()` decorator.
 *
 * Two independent, opt-in transforms applied to the raw roles read from the
 * request:
 *
 *  1. **Hierarchy expansion** — if `roleHierarchy` is given, every role is
 *     expanded transitively with the roles it implies. `{ ADMIN: ['MANAGER'],
 *     MANAGER: ['USER'] }` means holding `ADMIN` yields `[ADMIN, MANAGER, USER]`.
 *     Cycles are handled safely.
 *
 *  2. **Known-roles filtering** — if `knownRoles` is given, any role outside
 *     that set is dropped, so a shared token carrying roles for other modules
 *     doesn't pollute this module's view.
 *
 * Order is expand-then-filter: expand to the full implied set first, then keep
 * only the roles this module declares. List `knownRoles` accordingly.
 */
export function expandRoles(roles: string[], hierarchy?: Record<string, string[]>): string[] {
  if (!hierarchy) {
    return [...new Set(roles)];
  }
  const result = new Set<string>(roles);
  const stack = [...roles];
  while (stack.length) {
    const role = stack.pop() as string;
    for (const implied of hierarchy[role] ?? []) {
      if (!result.has(implied)) {
        result.add(implied);
        stack.push(implied);
      }
    }
  }
  return [...result];
}

export function resolveRoles(roles: string[], hierarchy?: Record<string, string[]>, knownRoles?: string[]): string[] {
  let resolved = expandRoles(roles, hierarchy);
  if (knownRoles) {
    const known = new Set(knownRoles);
    resolved = resolved.filter((role) => known.has(role));
  }
  return resolved;
}

/**
 * The roles as a list of strings, however they were carried: a list (a JWT
 * claim), a JSON array or a comma-separated string (a header, or a claim an
 * issuer flattened). A string is never spread into its characters — that would
 * hand a one-letter role to whoever holds a role starting with it.
 *
 * `format` forces one encoding; by default a value starting with `[` is read
 * as JSON, anything else as a comma-separated list. Malformed JSON gives no
 * role, with a warning that never shows the value.
 */
export function toRoleList(raw: unknown, format?: 'json' | 'csv'): string[] {
  if (Array.isArray(raw)) {
    return raw.filter((role): role is string => typeof role === 'string' && role.length > 0);
  }
  if (typeof raw !== 'string' || raw.trim() === '') {
    return [];
  }
  if (format === 'csv' || (format !== 'json' && !raw.trim().startsWith('['))) {
    return raw
      .split(',')
      .map((role) => role.trim())
      .filter((role) => role.length > 0);
  }
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return toRoleList(parsed);
    }
  } catch {
    // Reported below, like a JSON value that isn't an array.
  }
  console.warn('[nestjs-granted] roles are not a JSON array of strings: ignored');
  return [];
}
