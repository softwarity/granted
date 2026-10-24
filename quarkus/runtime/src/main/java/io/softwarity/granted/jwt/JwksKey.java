package io.softwarity.granted.jwt;

import java.security.Key;
import java.util.List;

/** A key of a JWK Set, and the algorithms it verifies with - set from the JWK Set, never from a token. */
record JwksKey(String kid, Key key, List<String> algorithms) {
}
