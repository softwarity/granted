package io.softwarity.granted;

import java.io.StringReader;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

/**
 * Reads a claim and gives it the type the code asks for - the rules of nestjs-granted's
 * {@code @Claim}, so a value means the same thing in both:
 *
 * <ul>
 * <li>a string is parsed: a list is a JSON array ({@code ["FR","GP"]}) or a comma-separated
 * list ({@code FR, GP}); a number or a boolean given as a string converts;</li>
 * <li>missing gives nothing - an empty list for a list;</li>
 * <li>a value of the wrong type is treated as missing, with a warning naming the claim, never
 * the value; in a list only the elements of the wrong type are dropped, and a list left empty
 * counts as missing.</li>
 * </ul>
 */
final class Claims {

    private static final Logger LOG = Logger.getLogger(Claims.class);

    /** Marks a value that doesn't have the expected type. */
    static final Object INVALID = new Object();

    private static final Set<Class<?>> TYPES = Set.of(String.class, Long.class, Integer.class, Double.class, Boolean.class, Object.class);

    private Claims() {
    }

    /** A claim of the verified token, by its dotted path, as plain Java values. */
    static Object read(JsonWebToken jwt, String path) {
        String[] keys = path.split("\\.");
        Object value = unwrap(jwt.getClaim(keys[0]));
        for (int i = 1; i < keys.length && value != null; i++) {
            value = value instanceof Map<?, ?> map ? map.get(keys[i]) : null;
        }
        return value;
    }

    /**
     * JSON-P values - what a custom claim comes back as - to plain Java ones: a string, a long
     * or a double, a boolean, a list, a map.
     */
    static Object unwrap(Object value) {
        if (value instanceof JsonString string) {
            return string.getString();
        }
        if (value instanceof JsonNumber number) {
            return number.isIntegral() ? (Object) number.longValue() : (Object) number.doubleValue();
        }
        if (value == JsonValue.TRUE) {
            return Boolean.TRUE;
        }
        if (value == JsonValue.FALSE) {
            return Boolean.FALSE;
        }
        if (value == JsonValue.NULL) {
            return null;
        }
        if (value instanceof JsonObject object) {
            Map<String, Object> map = new LinkedHashMap<>();
            object.forEach((key, item) -> map.put(key, unwrap(item)));
            return map;
        }
        if (value instanceof Collection<?> collection) {
            // A JsonArray is a List<JsonValue>; groups and audiences come back as a Set<String>.
            List<Object> list = new ArrayList<>();
            collection.forEach(item -> list.add(unwrap(item)));
            return list;
        }
        return value;
    }

    /** The roles a claim or a header carries: strings only, whatever the shape. */
    static List<String> strings(Object raw) {
        Object list = list(raw);
        if (!(list instanceof List<?> items)) {
            return List.of();
        }
        return items.stream().filter(String.class::isInstance).map(String.class::cast).map(String::trim)
                .filter(role -> !role.isEmpty()).toList();
    }

    /** A single value of {@code type}, {@code null} when missing, {@link #INVALID} when of the wrong type. */
    static Object scalar(Object raw, Class<?> type) {
        checkType(type);
        if (raw == null || "".equals(raw)) {
            return null;
        }
        if (raw instanceof List<?>) {
            return type == Object.class ? raw : INVALID;
        }
        return convert(raw, type);
    }

    /** A list of {@code type}, without the elements of the wrong type; {@link #INVALID} when nothing is left. */
    static Object list(Object raw, Class<?> type, String name) {
        checkType(type);
        if (raw == null || "".equals(raw)) {
            return List.of();
        }
        Object list = list(raw);
        if (list == INVALID) {
            return INVALID;
        }
        List<?> items = (List<?>) list;
        List<Object> values = new ArrayList<>();
        for (Object item : items) {
            Object value = convert(item, type);
            if (value != INVALID) {
                values.add(value);
            }
        }
        int dropped = items.size() - values.size();
        if (dropped > 0 && values.isEmpty()) {
            return INVALID;
        }
        if (dropped > 0) {
            // Never the values: they come from the caller's token or headers.
            LOG.warnf("[quarkus-granted] claim '%s': %d element(s) not of the expected type (%s) ignored", name, dropped, typeName(type));
        }
        return List.copyOf(values);
    }

    static void warnInvalid(String name, Class<?> type, boolean array) {
        LOG.warnf("[quarkus-granted] claim '%s' is not of the expected type (%s%s): ignored", name, typeName(type), array ? "[]" : "");
    }

    private static Object list(Object raw) {
        if (raw == null) {
            return List.of();
        }
        if (raw instanceof List<?>) {
            return raw;
        }
        if (raw instanceof String string) {
            return parseList(string);
        }
        return List.of(raw);
    }

    /** A JSON array, or else a comma-separated list. */
    private static Object parseList(String raw) {
        if (raw.trim().startsWith("[")) {
            try (JsonReader reader = Json.createReader(new StringReader(raw))) {
                JsonValue value = reader.readValue();
                return value instanceof JsonArray ? unwrap(value) : INVALID;
            } catch (RuntimeException e) {
                return INVALID;
            }
        }
        List<Object> items = new ArrayList<>();
        for (String item : raw.split(",")) {
            if (!item.trim().isEmpty()) {
                items.add(item.trim());
            }
        }
        return items;
    }

    private static Object convert(Object value, Class<?> type) {
        if (type == Object.class || type.isInstance(value)) {
            return value;
        }
        if (type == String.class) {
            return INVALID;
        }
        if (type == Boolean.class) {
            return "true".equals(value) ? Boolean.TRUE : "false".equals(value) ? Boolean.FALSE : INVALID;
        }
        BigDecimal number = number(value);
        if (number == null) {
            return INVALID;
        }
        try {
            if (type == Long.class) {
                return number.longValueExact();
            }
            if (type == Integer.class) {
                return number.intValueExact();
            }
        } catch (ArithmeticException e) {
            return INVALID;
        }
        return number.doubleValue();
    }

    /** A developer's error, whether the value is there or not. */
    private static void checkType(Class<?> type) {
        if (!TYPES.contains(type)) {
            throw new IllegalArgumentException("A claim reads as String, Long, Integer, Double, Boolean or Object, not " + type.getName());
        }
    }

    private static BigDecimal number(Object value) {
        if (value instanceof Long || value instanceof Integer) {
            return BigDecimal.valueOf(((Number) value).longValue());
        }
        if (value instanceof Double d) {
            return d.isNaN() || d.isInfinite() ? null : BigDecimal.valueOf(d);
        }
        if (value instanceof String string && !string.isBlank()) {
            try {
                return new BigDecimal(string.trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private static String typeName(Class<?> type) {
        if (type == String.class) {
            return "string";
        }
        if (type == Boolean.class) {
            return "boolean";
        }
        return type == Object.class ? "any" : "number";
    }
}
