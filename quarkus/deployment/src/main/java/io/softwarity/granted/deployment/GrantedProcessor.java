package io.softwarity.granted.deployment;

import io.quarkus.arc.deployment.UnremovableBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.resteasy.reactive.server.spi.MethodScannerBuildItem;
import io.softwarity.granted.AccessDenial;
import io.softwarity.granted.GrantedCaller;

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
}
