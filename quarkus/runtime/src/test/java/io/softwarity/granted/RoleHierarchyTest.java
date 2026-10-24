package io.softwarity.granted;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

class RoleHierarchyTest {

    private static final Map<String, List<String>> HIERARCHY = Map.of("ADMIN", List.of("MANAGER"), "MANAGER", List.of("USER"));

    @Test
    void expandsTransitively() {
        assertEquals(Set.of("ADMIN", "MANAGER", "USER"), RoleHierarchy.resolve(List.of("ADMIN"), HIERARCHY, Optional.empty()));
    }

    @Test
    void survivesACycle() {
        Map<String, List<String>> cycle = Map.of("A", List.of("B"), "B", List.of("A"));
        assertEquals(Set.of("A", "B"), RoleHierarchy.resolve(List.of("A"), cycle, Optional.empty()));
    }

    @Test
    void filtersAfterExpanding() {
        assertEquals(Set.of("USER"), RoleHierarchy.resolve(List.of("ADMIN", "OTHER"), HIERARCHY, Optional.of(List.of("USER"))));
    }

    @Test
    void keepsEveryRoleWithoutAHierarchyOrKnownRoles() {
        assertEquals(Set.of("X", "Y"), RoleHierarchy.resolve(List.of("X", "Y", "X"), Map.of(), Optional.empty()));
    }
}
