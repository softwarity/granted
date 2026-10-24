package io.softwarity.granted.jwt;

import io.quarkus.runtime.annotations.Recorder;

/** What the build knows and the runtime needs: whether another extension verifies the token. */
@Recorder
public class GrantedRecorder {

    public void externalVerifier(boolean present) {
        JwtVerification.externalVerifier(present);
    }
}
