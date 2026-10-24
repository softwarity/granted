package io.softwarity.granted.jwt;

/** A token that failed verification. Its message is logged - never the token. */
class VerificationException extends Exception {

    /**
     * The signature was valid: the token was refused for its dates, issuer or audience. No other
     * key can do better, and no re-fetch of the keys is warranted.
     */
    final boolean signatureMatched;

    VerificationException(String message) {
        this(message, false);
    }

    VerificationException(String message, boolean signatureMatched) {
        super(message, null, false, false);
        this.signatureMatched = signatureMatched;
    }
}
