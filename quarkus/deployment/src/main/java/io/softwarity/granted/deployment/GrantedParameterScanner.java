package io.softwarity.granted.deployment;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.AnnotationValue;
import org.jboss.jandex.DotName;
import org.jboss.jandex.PrimitiveType;
import org.jboss.jandex.Type;
import org.jboss.resteasy.reactive.server.core.parameters.ParameterExtractor;
import org.jboss.resteasy.reactive.server.processor.scanning.MethodScanner;

import io.softwarity.granted.GrantedClaim;
import io.softwarity.granted.GrantedParameterExtractor;
import io.softwarity.granted.GrantedParameterExtractor.Collection;
import io.softwarity.granted.GrantedParameterExtractor.Kind;
import io.softwarity.granted.GrantedRoles;
import io.softwarity.granted.GrantedTenant;
import io.softwarity.granted.GrantedUsername;

/**
 * Recognises the granted parameters of a resource method at build time and says, once and for
 * all, how each gets its value. A parameter of a type the annotation can't fill fails the build,
 * naming the annotation and the type - never a request.
 */
final class GrantedParameterScanner implements MethodScanner {

    static final DotName CLAIM = DotName.createSimple(GrantedClaim.class);
    static final DotName USERNAME = DotName.createSimple(GrantedUsername.class);
    static final DotName ROLES = DotName.createSimple(GrantedRoles.class);
    static final DotName TENANT = DotName.createSimple(GrantedTenant.class);

    private static final DotName STRING = DotName.createSimple(String.class);
    private static final DotName LIST = DotName.createSimple(List.class);
    private static final DotName SET = DotName.createSimple(Set.class);
    private static final DotName COLLECTION = DotName.createSimple(java.util.Collection.class);

    /** What a claim reads as, by the parameter's (or the list element's) type. */
    private static final Set<DotName> CLAIM_TYPES = Set.of(STRING, DotName.createSimple(Integer.class),
            DotName.createSimple(Long.class), DotName.createSimple(Double.class), DotName.createSimple(Boolean.class),
            DotName.createSimple(Object.class));

    @Override
    public ParameterExtractor handleCustomParameter(Type type, Map<DotName, AnnotationInstance> annotations, boolean field,
            Map<String, Object> methodContext) {
        if (annotations.containsKey(USERNAME)) {
            expect(type.name().equals(STRING), "@GrantedUsername", type, "String");
            return new GrantedParameterExtractor(Kind.USERNAME, null, null, Collection.NONE, false);
        }
        if (annotations.containsKey(TENANT)) {
            expect(type.name().equals(STRING), "@GrantedTenant", type, "String");
            return new GrantedParameterExtractor(Kind.TENANT, null, null, Collection.NONE, false);
        }
        if (annotations.containsKey(ROLES)) {
            Collection collection = collection(type);
            expect(collection != Collection.NONE && element(type).name().equals(STRING), "@GrantedRoles", type,
                    "Set<String> or List<String>");
            return new GrantedParameterExtractor(Kind.ROLES, null, null, collection, false);
        }
        if (annotations.containsKey(CLAIM)) {
            return claim(type, annotations.get(CLAIM));
        }
        return null;
    }

    private static ParameterExtractor claim(Type type, AnnotationInstance annotation) {
        String name = annotation.value().asString();
        AnnotationValue requiredValue = annotation.value("required");
        boolean required = requiredValue != null && requiredValue.asBoolean();
        String what = "@GrantedClaim(\"" + name + "\")";
        String expected = "String, Integer, Long, Double, Boolean, Object, or a List or Set of one of them";
        Collection collection = collection(type);
        Type element = collection == Collection.NONE ? type : element(type);
        if (element.kind() == Type.Kind.PRIMITIVE) {
            // A primitive can't say "missing": only a required claim fills one.
            expect(collection == Collection.NONE && required, what, type, "a wrapper type (Integer, Long...) - or required = true on a primitive");
            element = PrimitiveType.box(element.asPrimitiveType());
        }
        expect(CLAIM_TYPES.contains(element.name()), what, type, expected);
        return new GrantedParameterExtractor(Kind.CLAIM, name, element.name().toString(), collection, required);
    }

    private static Collection collection(Type type) {
        if (type.kind() != Type.Kind.PARAMETERIZED_TYPE) {
            return Collection.NONE;
        }
        DotName raw = type.name();
        if (raw.equals(LIST) || raw.equals(COLLECTION)) {
            return Collection.LIST;
        }
        return raw.equals(SET) ? Collection.SET : Collection.NONE;
    }

    private static Type element(Type type) {
        return type.asParameterizedType().arguments().get(0);
    }

    private static void expect(boolean condition, String annotation, Type type, String expected) {
        if (!condition) {
            throw new IllegalStateException(annotation + " can't fill a parameter of type " + type + ": expected " + expected);
        }
    }
}
