package io.softwarity.granted;

import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The roles a caller is judged on: its own, expanded with the roles they imply, then cut down
 * to the roles this service knows. Expand first, then filter - list {@code known-roles}
 * accordingly. Cycles in the hierarchy are harmless.
 */
public final class RoleHierarchy {

    private RoleHierarchy() {
    }

    public static Set<String> resolve(Collection<String> roles, Map<String, List<String>> hierarchy, Optional<List<String>> knownRoles) {
        Set<String> resolved = new LinkedHashSet<>(roles);
        Deque<String> pending = new ArrayDeque<>(roles);
        while (!pending.isEmpty()) {
            for (String implied : hierarchy.getOrDefault(pending.pop(), List.of())) {
                if (resolved.add(implied)) {
                    pending.push(implied);
                }
            }
        }
        knownRoles.ifPresent(known -> resolved.retainAll(Set.copyOf(known)));
        return resolved;
    }
}
