package granted

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// jwtGranted is a Granted reading the caller from tokens, and the logs of its provider.
func jwtGranted(t *testing.T, cfg JWTConfig) (*Granted, *JWTProvider, *logs) {
	t.Helper()
	logger, logged := newLogger()
	cfg.Logger = logger
	provider, err := NewJWTProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{Provider: provider, Logger: logger}), provider, logged
}

func TestJWTWithAKey(t *testing.T) {
	ec := ecKey(t, "")
	rsa := rsaKey(t, "")

	t.Run("verifies ES256 by default", func(t *testing.T) {
		g, _, _ := jwtGranted(t, JWTConfig{Key: pemOf(t, ec.public)})
		got := callerOf(t, g, request("GET", "/", bearerHeader(signWith(t, ec, map[string]any{"sub": "alice", "roles": []any{"ADMIN"}, "tenant": "acme"}))))
		want := identity{Username: "alice", Roles: []string{"ADMIN"}, Tenant: "acme"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("refuses at construction a key that can't verify the algorithms", func(t *testing.T) {
		if _, err := NewJWTProvider(JWTConfig{Key: pemOf(t, rsa.public)}); err == nil || !strings.Contains(err.Error(), "can't verify ES256") {
			t.Fatal(err)
		}
	})

	t.Run("verifies the configured algorithms only", func(t *testing.T) {
		g, _, logged := jwtGranted(t, JWTConfig{Key: pemOf(t, rsa.public), Algorithms: []string{"RS256"}})
		if got := callerOf(t, g, request("GET", "/", bearerHeader(signWith(t, rsa, map[string]any{"sub": "alice"})))); got.Username != "alice" {
			t.Fatal(got)
		}
		rs384 := sign(t, "RS384", rsa.private, "", map[string]any{"sub": "mallory"})
		if got := callerOf(t, g, request("GET", "/", bearerHeader(rs384))); got.Username != Anonymous {
			t.Fatal(got)
		}
		if !strings.Contains(logged.String(), "JWT verification failed (RS256): invalid algorithm") {
			t.Fatal(logged)
		}
	})

	t.Run("reads the key from a file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "key.pem")
		if err := os.WriteFile(file, []byte(pemOf(t, ec.public)), 0o600); err != nil {
			t.Fatal(err)
		}
		g, _, _ := jwtGranted(t, JWTConfig{KeyFile: file})
		if got := callerOf(t, g, request("GET", "/", bearerHeader(signWith(t, ec, map[string]any{"sub": "alice"})))); got.Username != "alice" {
			t.Fatal(got)
		}
	})

	t.Run("verifies HS* with a shared secret", func(t *testing.T) {
		secret := []byte("test-secret")
		g, _, _ := jwtGranted(t, JWTConfig{Key: string(secret), Algorithms: []string{"HS256"}})
		if got := callerOf(t, g, request("GET", "/", bearerHeader(sign(t, "HS256", secret, "", map[string]any{"sub": "alice"})))); got.Username != "alice" {
			t.Fatal(got)
		}
		if got := callerOf(t, g, request("GET", "/", bearerHeader(sign(t, "HS256", []byte("other"), "", map[string]any{"sub": "alice"})))); got.Username != Anonymous {
			t.Fatal(got)
		}
	})

	t.Run("verifies EdDSA with a PEM key", func(t *testing.T) {
		ed := edKey(t, "")
		g, _, _ := jwtGranted(t, JWTConfig{Key: pemOf(t, ed.public), Algorithms: []string{"EdDSA"}})
		if got := callerOf(t, g, request("GET", "/", bearerHeader(signWith(t, ed, map[string]any{"sub": "alice"})))); got.Username != "alice" {
			t.Fatal(got)
		}
	})

	t.Run("refuses a token signed by another key, and never logs the token", func(t *testing.T) {
		g, _, logged := jwtGranted(t, JWTConfig{Key: pemOf(t, ec.public)})
		forged := signWith(t, ecKey(t, ""), map[string]any{"sub": "mallory"})
		if got := callerOf(t, g, request("GET", "/", bearerHeader(forged))); got.Username != Anonymous {
			t.Fatal(got)
		}
		if !strings.Contains(logged.String(), "invalid signature") || strings.Contains(logged.String(), forged) {
			t.Fatal(logged)
		}
	})

	t.Run("refuses a malformed token", func(t *testing.T) {
		g, _, logged := jwtGranted(t, JWTConfig{Key: pemOf(t, ec.public)})
		if got := callerOf(t, g, request("GET", "/", bearerHeader("not.a-token"))); got.Username != Anonymous {
			t.Fatal(got)
		}
		if !strings.Contains(logged.String(), "jwt malformed") {
			t.Fatal(logged)
		}
	})

	t.Run("checks the validity dates", func(t *testing.T) {
		g, _, logged := jwtGranted(t, JWTConfig{Key: pemOf(t, ec.public)})
		now := time.Now().Unix()
		valid := signWith(t, ec, map[string]any{"sub": "alice", "nbf": now - 60, "exp": now + 60})
		expired := signWith(t, ec, map[string]any{"sub": "alice", "exp": now - 60})
		early := signWith(t, ec, map[string]any{"sub": "alice", "nbf": now + 600})
		if got := callerOf(t, g, request("GET", "/", bearerHeader(valid))); got.Username != "alice" {
			t.Fatal(got)
		}
		for _, token := range []string{expired, early} {
			if got := callerOf(t, g, request("GET", "/", bearerHeader(token))); got.Username != Anonymous {
				t.Fatal(got)
			}
		}
		if !regexp.MustCompile(`jwt expired[\s\S]*jwt not active`).MatchString(logged.String()) {
			t.Fatal(logged)
		}
	})

	t.Run("checks issuer and audience when they are set", func(t *testing.T) {
		g, _, logged := jwtGranted(t, JWTConfig{Key: pemOf(t, ec.public), Issuer: []string{"https://idp.acme", "https://gateway.acme"}, Audience: Audience{Patterns: []*regexp.Regexp{regexp.MustCompile(`^orders-`)}}})
		claims := map[string]any{"sub": "alice", "iss": "https://gateway.acme", "aud": []any{"billing-api", "orders-api"}}
		if got := callerOf(t, g, request("GET", "/", bearerHeader(signWith(t, ec, claims)))); got.Username != "alice" {
			t.Fatal(got)
		}
		for _, change := range []map[string]any{{"iss": "https://evil.example"}, {"aud": "billing-api"}, {"aud": nil}} {
			forged := map[string]any{}
			for k, v := range claims {
				forged[k] = v
			}
			for k, v := range change {
				forged[k] = v
			}
			if got := callerOf(t, g, request("GET", "/", bearerHeader(signWith(t, ec, forged)))); got.Username != Anonymous {
				t.Fatalf("%v: %v", change, got)
			}
		}
		if !regexp.MustCompile(`jwt issuer invalid[\s\S]*jwt audience invalid`).MatchString(logged.String()) {
			t.Fatal(logged)
		}
	})

	t.Run("does not check issuer and audience when unset", func(t *testing.T) {
		g, _, _ := jwtGranted(t, JWTConfig{Key: pemOf(t, ec.public)})
		token := signWith(t, ec, map[string]any{"sub": "alice", "iss": "https://elsewhere", "aud": "billing-api"})
		if got := callerOf(t, g, request("GET", "/", bearerHeader(token))); got.Username != "alice" {
			t.Fatal(got)
		}
	})
}

func TestJWTClaims(t *testing.T) {
	ec := ecKey(t, "")

	t.Run("never reads the identity headers", func(t *testing.T) {
		g, _, _ := jwtGranted(t, JWTConfig{Key: pemOf(t, ec.public)})
		headers := bearerHeader(signWith(t, ec, map[string]any{"sub": "alice"}))
		headers["username"], headers["roles"], headers["tenant"], headers["territories"] = "mallory", `["ADMIN"]`, "globex", "FR"
		got := callerOf(t, g, request("GET", "/", headers))
		if !reflect.DeepEqual(got, identity{Username: "alice", Roles: []string{}, Tenant: ""}) {
			t.Fatal(got)
		}
		if claims := Claims[string](contextFor(t, g, request("GET", "/", headers)), "territories"); len(claims) != 0 {
			t.Fatal("a header was read as a claim:", claims)
		}
		if got := callerOf(t, g, request("GET", "/", map[string]string{"username": "mallory", "roles": `["ADMIN"]`})); got.Username != Anonymous || len(got.Roles) != 0 {
			t.Fatal(got)
		}
	})

	t.Run("map the claims of a preset, nested ones by their dotted path", func(t *testing.T) {
		g, _, _ := jwtGranted(t, JWTConfig{Key: pemOf(t, ec.public), Claims: Keycloak})
		token := signWith(t, ec, map[string]any{"sub": "f81d4fae", "preferred_username": "alice", "realm_access": map[string]any{"roles": []any{"admin"}, "territories": []any{"FR", "GP"}}, "tenant": "acme"})
		r := request("GET", "/", bearerHeader(token))
		got := callerOf(t, g, r)
		if !reflect.DeepEqual(got, identity{Username: "alice", Roles: []string{"admin"}, Tenant: "acme"}) {
			t.Fatal(got)
		}
		if territories := Claims[string](contextFor(t, g, request("GET", "/", bearerHeader(token))), "realm_access.territories"); !reflect.DeepEqual(territories, []string{"FR", "GP"}) {
			t.Fatal(territories)
		}
	})

	t.Run("split a roles claim given as a string", func(t *testing.T) {
		g, _, _ := jwtGranted(t, JWTConfig{Key: pemOf(t, ec.public), Claims: ClaimMapping{Tenant: "tid"}})
		for _, roles := range []any{"ADMIN, USER", `["ADMIN","USER"]`, []any{"ADMIN", 42.0, "USER"}} {
			got := callerOf(t, g, request("GET", "/", bearerHeader(signWith(t, ec, map[string]any{"sub": "alice", "roles": roles, "tid": "contoso"}))))
			if !reflect.DeepEqual(got, identity{Username: "alice", Roles: []string{"ADMIN", "USER"}, Tenant: "contoso"}) {
				t.Errorf("%v: %+v", roles, got)
			}
		}
	})
}

func TestJWTUnverified(t *testing.T) {
	g, _, _ := jwtGranted(t, JWTConfig{Unverified: true})
	token := sign(t, "none", nil, "", map[string]any{"sub": "alice", "roles": []any{"USER"}})
	if got := callerOf(t, g, request("GET", "/", bearerHeader(token))); got.Username != "alice" {
		t.Fatal(got)
	}
}

func TestJWTConfiguration(t *testing.T) {
	ec := ecKey(t, "")
	key := pemOf(t, ec.public)
	cases := map[string]struct {
		cfg  JWTConfig
		want string
	}{
		"no key":                        {JWTConfig{}, "no key to verify tokens with"},
		"issuer without a key":          {JWTConfig{Issuer: []string{"x"}, Unverified: true}, "need a key"},
		"audience without a key":        {JWTConfig{Audience: Audience{Values: []string{"api"}}}, "need a key"},
		"unverified with a key":         {JWTConfig{Key: key, Unverified: true}, "Unverified cannot be combined"},
		"jwks and a key":                {JWTConfig{Key: key, JWKSURI: "http://idp/jwks"}, "JWKSURI cannot be combined"},
		"discovery and a key":           {JWTConfig{Key: key, DiscoveryURIs: []OpenIDProvider{{URI: "http://idp"}}}, "DiscoveryURIs cannot be combined"},
		"issuer with providers only":    {JWTConfig{Issuer: []string{"x"}, DiscoveryURIs: []OpenIDProvider{{URI: "http://idp"}}}, "Issuer applies to JWKSURI only"},
		"jwks with providers, no iss":   {JWTConfig{JWKSURI: "http://a/jwks", DiscoveryURIs: []OpenIDProvider{{URI: "http://idp"}}}, "JWKSURI needs an Issuer"},
		"provider issuer alone":         {JWTConfig{DiscoveryURIs: []OpenIDProvider{{Issuer: "x"}}}, "together, or neither"},
		"provider without a URL":        {JWTConfig{DiscoveryURIs: []OpenIDProvider{{}}}, "needs a URI"},
		"empty bypass pattern":          {JWTConfig{DiscoveryURIs: []OpenIDProvider{{URI: "http://idp", Bypass: []string{""}}}}, "Bypass is a list"},
		"empty algorithms":              {JWTConfig{Key: key, Algorithms: []string{}}, "empty list"},
		"none":                          {JWTConfig{Key: key, Algorithms: []string{"none"}}, `refused algorithm "none"`},
		"unknown algorithm":             {JWTConfig{Key: key, Algorithms: []string{"XX256"}}, "unknown or refused"},
		"HS* with a JWK Set":            {JWTConfig{JWKSURI: "http://idp/jwks", Algorithms: []string{"HS256"}}, "HS256 cannot be used with JWKSURI"},
		"HS* mixed with RS*":            {JWTConfig{Key: "secret", Algorithms: []string{"HS256", "RS256"}}, "mixes HS*"},
		"a key that isn't a PEM":        {JWTConfig{Key: "secret"}, "not a PEM public key"},
		"a key file that doesn't exist": {JWTConfig{KeyFile: "/nonexistent/key.pem"}, "KeyFile"},
	}
	for name, tc := range cases {
		if _, err := NewJWTProvider(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
