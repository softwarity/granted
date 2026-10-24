package io.softwarity.granted;

import io.quarkus.security.ForbiddenException;

/** A claim the code requires is missing, or not of the expected type: the request is refused (403). */
public class MissingClaimException extends ForbiddenException {

    private final String claim;

    public MissingClaimException(String claim) {
        super("claim '" + claim + "' required");
        this.claim = claim;
    }

    /** The claim's name, as the code asked for it. */
    public String claim() {
        return claim;
    }
}
