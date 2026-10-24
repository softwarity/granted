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
