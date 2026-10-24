package io.softwarity.granted;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jakarta.json.Json;

/** The rules of nestjs-granted's @Claim, value by value. */
class ClaimsTest {

    private final List<String> logged = new ArrayList<>();

    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            logged.add(record.getMessage() + " " + List.of(record.getParameters() == null ? new Object[0] : record.getParameters()));
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };

    @BeforeEach
    void capture() {
        Logger.getLogger(Claims.class.getName()).addHandler(capture);
    }

    @AfterEach
    void release() {
        Logger.getLogger(Claims.class.getName()).removeHandler(capture);
    }

    @Test
    void parsesAListGivenAsJsonOrAsCsv() {
        assertEquals(List.of("FR", "GP"), Claims.list("[\"FR\",\"GP\"]", String.class, "territories"));
        assertEquals(List.of("FR", "GP"), Claims.list(" FR , GP ,", String.class, "territories"));
        assertEquals(List.of("FR"), Claims.list("FR", String.class, "territories"));
        assertEquals(List.of(), Claims.list(null, String.class, "territories"));
        assertEquals(List.of(), Claims.list("", String.class, "territories"));
    }

    @Test
    void aMalformedJsonListIsInvalid() {
        assertSame(Claims.INVALID, Claims.list("[\"FR\",", String.class, "territories"));
        assertSame(Claims.INVALID, Claims.list("[ {\"a\": 1} ]", String.class, "territories"));
    }

    @Test
    void dropsOnlyTheElementsOfTheWrongTypeAndNeverLogsThem() {
        assertEquals(List.of("FR", "GP"), Claims.list(List.of("FR", 42L, "GP"), String.class, "territories"));
        assertEquals(List.of(1L, 3L), Claims.list("1, two, 3", Long.class, "codes"));
        assertSame(Claims.INVALID, Claims.list(List.of(41L, 42L), String.class, "territories"));
        String all = String.join(" ", logged);
        assertTrue(all.contains("territories"), all);
        assertFalse(all.matches(".*\\b(42|two)\\b.*"), all);
    }

    @Test
    void convertsANumberOrABooleanGivenAsAString() {
        assertEquals(5000L, Claims.scalar("5000", Long.class));
        assertEquals(5000, Claims.scalar("5000", Integer.class));
        assertEquals(2.5, Claims.scalar("2.5", Double.class));
        assertEquals(false, Claims.scalar("false", Boolean.class));
        assertSame(Claims.INVALID, Claims.scalar("a-lot", Long.class));
        assertSame(Claims.INVALID, Claims.scalar("2.5", Long.class));
        assertSame(Claims.INVALID, Claims.scalar("yes", Boolean.class));
        assertSame(Claims.INVALID, Claims.scalar(42L, String.class));
    }

    @Test
    void refusesAListWhereOneValueIsExpectedUnlessAskedAsIs() {
        assertSame(Claims.INVALID, Claims.scalar(List.of(1L, 2L), Long.class));
        assertEquals(List.of(1L, 2L), Claims.scalar(List.of(1L, 2L), Object.class));
        assertNull(Claims.scalar("", String.class));
    }

    @Test
    void unwrapsJsonValues() {
        Object value = Claims.unwrap(Json.createObjectBuilder()
                .add("roles", Json.createArrayBuilder().add("A").add(1).add(2.5).add(true))
                .build());
        assertEquals(java.util.Map.of("roles", List.of("A", 1L, 2.5, true)), value);
    }

    @Test
    void aTypeNoClaimReadsAsIsADeveloperError() {
        assertThrows(IllegalArgumentException.class, () -> Claims.scalar("x", java.time.Instant.class));
    }
}
