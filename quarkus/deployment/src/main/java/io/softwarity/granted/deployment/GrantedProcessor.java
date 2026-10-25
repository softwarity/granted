package io.softwarity.granted.deployment;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import io.quarkus.arc.deployment.ExcludedTypeBuildItem;
import io.quarkus.arc.deployment.UnremovableBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.Capability;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.ExtensionSslNativeSupportBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.resteasy.reactive.common.deployment.JaxRsSecurityConfig;
import io.quarkus.resteasy.reactive.server.spi.MethodScannerBuildItem;
import io.quarkus.security.spi.SecurityTransformerBuildItem;
import io.quarkus.smallrye.health.deployment.spi.HealthBuildItem;
import io.quarkus.smallrye.openapi.deployment.spi.AddToOpenAPIDefinitionBuildItem;
import io.quarkus.vertx.http.deployment.HttpRootPathBuildItem;
import io.softwarity.granted.AccessDenial;
import io.softwarity.granted.GrantedBuildTimeConfig;
import io.softwarity.granted.GrantedCaller;
import io.softwarity.granted.deployment.GrantedOpenApiFilter.Access;
import io.softwarity.granted.jwt.GrantedJwksHealthCheck;
import io.softwarity.granted.jwt.GrantedRecorder;

class GrantedProcessor {

    private static final String FEATURE = "granted";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    /** The @GrantedClaim, @GrantedUsername, @GrantedRoles and @GrantedTenant parameters of the resource methods. */
    @BuildStep
    MethodScannerBuildItem parameters() {
        return new MethodScannerBuildItem(new GrantedParameterScanner());
    }

    /** The parameters look the caller - and, to refuse, the denial - up for each request: they stay, even where no code injects them. */
    @BuildStep
    UnremovableBeanBuildItem caller() {
        return UnremovableBeanBuildItem.beanTypes(GrantedCaller.class, AccessDenial.class);
    }

    /** granted fetches discovery documents and JWK Sets over HTTPS: a native image needs SSL. */
    @BuildStep
    ExtensionSslNativeSupportBuildItem ssl() {
        return new ExtensionSslNativeSupportBuildItem(FEATURE);
    }

    /**
     * The granted-jwks readiness check, when quarkus-smallrye-health is there. That extension makes
     * {@code @Readiness} define a bean, and this jar is a bean archive: a disabled check has to be
     * excluded, not merely left unregistered.
     */
    @BuildStep
    void health(Capabilities capabilities, GrantedBuildTimeConfig config, BuildProducer<HealthBuildItem> health,
            BuildProducer<ExcludedTypeBuildItem> excluded) {
        if (!capabilities.isPresent(Capability.SMALLRYE_HEALTH)) {
            return;
        }
        if (config.health().enabled()) {
            health.produce(new HealthBuildItem(GrantedJwksHealthCheck.class.getName(), true));
        } else {
            excluded.produce(new ExcludedTypeBuildItem(GrantedJwksHealthCheck.class.getName()));
        }
    }

    /**
     * Each route's rule in the OpenAPI document, when quarkus-smallrye-openapi is present. The
     * document is generated at build time: the rules are read from the index now, and the filter
     * runs with smallrye-openapi's own - after them, its class name sorting after theirs. Without
     * that extension, nothing is produced and nothing of it is loaded.
     */
    @BuildStep
    void openApi(Capabilities capabilities, GrantedBuildTimeConfig config, CombinedIndexBuildItem index,
            SecurityTransformerBuildItem securityTransformer, JaxRsSecurityConfig jaxRsSecurity, HttpRootPathBuildItem httpRootPath,
            BuildProducer<AddToOpenAPIDefinitionBuildItem> openApi) {
        if (!capabilities.isPresent(Capability.SMALLRYE_OPENAPI)) {
            return;
        }
        Config buildConfig = ConfigProvider.getConfig();
        // What Quarkus REST applies to an endpoint without a rule: deny first, then the default roles.
        Access unannotated = jaxRsSecurity.denyJaxRs() ? Access.denyAll()
                : jaxRsSecurity.defaultRolesAllowed().filter(roles -> !roles.isEmpty())
                        .map(roles -> Access.rolesAllowed(GrantedOpenApiScanner.resolve(roles.toArray(String[]::new), buildConfig)))
                        .orElse(null);
        var routes = new GrantedOpenApiScanner(index.getIndex(),
                SecurityTransformerBuildItem.createSecurityTransformer(index.getIndex(), securityTransformer),
                values -> GrantedOpenApiScanner.resolve(values, buildConfig), unannotated)
                .scan(httpRootPath.getRootPath(), buildConfig.getOptionalValue("quarkus.rest.path", String.class).orElse(""));
        if (!routes.isEmpty()) {
            // null: every document the application defines.
            openApi.produce(new AddToOpenAPIDefinitionBuildItem(new GrantedOpenApiFilter(routes, config.openapi().securityScheme()), null));
        }
    }

    /**
     * Whether another extension verifies the token: with granted.source=jwt and no key, granted reads
     * the token it verified - and without one, the application must not start.
     */
    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    void externalVerifier(GrantedRecorder recorder, Capabilities capabilities) {
        recorder.externalVerifier(capabilities.isPresent(Capability.OIDC) || capabilities.isPresent(Capability.JWT));
    }
}
