package granted

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// idp is a local identity provider: a JWK Set it serves as it is set, a
// discovery document, and how often each was fetched, with what.
type idp struct {
	*httptest.Server
	mu            sync.Mutex
	keys          []map[string]any
	status        int
	delay         time.Duration
	fetches       int
	discoveries   int
	issuer        string
	authorization string
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	i := &idp{status: http.StatusOK}
	i.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hang" {
			<-r.Context().Done() // never answers — exercises the timeout
			return
		}
		i.mu.Lock()
		i.authorization = r.Header.Get("Authorization")
		delay, status := i.delay, i.status
		var body any
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			i.discoveries++
			body = map[string]any{"issuer": i.issuer, "jwks_uri": i.URL + "/jwks.json"}
		} else {
			i.fetches++
			body = map[string]any{"keys": i.keys}
		}
		i.mu.Unlock()
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(i.Close)
	return i
}

func (i *idp) publish(keys ...map[string]any) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = keys
}

func (i *idp) set(f func(*idp)) {
	i.mu.Lock()
	defer i.mu.Unlock()
	f(i)
}

func (i *idp) fetchCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.fetches
}

// jwksGranted is a Granted verifying with the provider's JWK Set, on a clock the test moves.
func jwksGranted(t *testing.T, cfg JWTConfig) (*Granted, *clock, *logs) {
	t.Helper()
	g, provider, logged := jwtGranted(t, cfg)
	c := &clock{}
	provider.now = c.now
	return g, c, logged
}

func usernameOf(t *testing.T, g *Granted, token string) string {
	t.Helper()
	return callerOf(t, g, request("GET", "/", bearerHeader(token))).Username
}

func TestJWKS(t *testing.T) {
	keyA, keyB, outsider := rsaKey(t, "key-a"), rsaKey(t, "key-b"), rsaKey(t, "outsider")
	ec, ed := ecKey(t, "key-ec"), edKey(t, "key-ed")
	alice := map[string]any{"sub": "alice", "roles": []any{"ADMIN"}}
	provider := newIDP(t)
	reset := func(keys ...map[string]any) {
		provider.set(func(i *idp) { i.status, i.fetches, i.delay = http.StatusOK, 0, 0 })
		provider.publish(keys...)
	}
	jwks := func(cfg JWTConfig) (*Granted, *clock, *logs) {
		cfg.JWKSURI = provider.URL + "/jwks.json"
		return jwksGranted(t, cfg)
	}

	t.Run("verifies RS256, ES256 and EdDSA tokens against one set, with no algorithm configured", func(t *testing.T) {
		reset(jwkOf(t, keyA), jwkOf(t, ec), jwkOf(t, ed))
		g, _, logged := jwks(JWTConfig{})
		for _, key := range []testKey{keyA, ec, ed} {
			if got := usernameOf(t, g, signWith(t, key, alice)); got != "alice" {
				t.Errorf("%s: %s", key.alg, got)
			}
		}
		if provider.fetchCount() != 1 || logged.String() != "" {
			t.Fatalf("fetches %d, log %s", provider.fetchCount(), logged)
		}
	})

	t.Run("refuses a token whose kid is not in the set", func(t *testing.T) {
		reset(jwkOf(t, keyA))
		g, _, logged := jwks(JWTConfig{})
		if got := usernameOf(t, g, sign(t, "RS256", keyA.private, "unknown", alice)); got != Anonymous {
			t.Fatal(got)
		}
		if !strings.Contains(logged.String(), "JWT verification failed (JWKS): no JWKS key matches the token") {
			t.Fatal(logged)
		}
	})

	t.Run("refuses a token announcing another algorithm than its key", func(t *testing.T) {
		reset(jwkOf(t, keyA))
		g, _, logged := jwks(JWTConfig{})
		// Each of these would verify if the token's `alg` were trusted.
		rs384 := sign(t, "RS384", keyA.private, keyA.kid, alice)
		hs256 := sign(t, "HS256", []byte(pemOf(t, keyA.public)), keyA.kid, alice)
		unsigned := sign(t, "none", nil, keyA.kid, alice)
		for _, token := range []string{rs384, hs256, unsigned} {
			logged.reset()
			if got := usernameOf(t, g, token); got != Anonymous {
				t.Fatal(got)
			}
			if !strings.Contains(logged.String(), "invalid algorithm") {
				t.Fatal(logged)
			}
		}
	})

	t.Run("used as an allowlist, Algorithms rejects the keys of any other algorithm", func(t *testing.T) {
		reset(jwkOf(t, keyA), jwkOf(t, ec), jwkOf(t, ed))
		g, _, logged := jwks(JWTConfig{Algorithms: []string{"RS256", "EdDSA"}})
		if usernameOf(t, g, signWith(t, keyA, alice)) != "alice" || usernameOf(t, g, signWith(t, ed, alice)) != "alice" {
			t.Fatal("allowed algorithms refused")
		}
		if got := usernameOf(t, g, signWith(t, ec, alice)); got != Anonymous {
			t.Fatal(got)
		}
		if !strings.Contains(logged.String(), "JWT verification failed (RS256, EdDSA): invalid algorithm") {
			t.Fatal(logged)
		}
	})

	t.Run("infers the algorithm of a key published without alg from its type", func(t *testing.T) {
		reset(withoutAlg(jwkOf(t, keyA)), withoutAlg(jwkOf(t, ec)), withoutAlg(jwkOf(t, ed)))
		g, _, _ := jwks(JWTConfig{})
		for _, key := range []testKey{keyA, ec, ed} {
			if got := usernameOf(t, g, signWith(t, key, alice)); got != "alice" {
				t.Errorf("%s: %s", key.alg, got)
			}
		}
		// An RSA key without alg is taken as RS256, whatever the token says.
		if got := usernameOf(t, g, sign(t, "RS384", keyA.private, keyA.kid, alice)); got != Anonymous {
			t.Fatal(got)
		}
	})

	t.Run("lets the allowlist choose the algorithm of a key published without alg", func(t *testing.T) {
		reset(withoutAlg(jwkOf(t, keyA)))
		ps256 := sign(t, "PS256", keyA.private, keyA.kid, alice)
		g, _, _ := jwks(JWTConfig{})
		if got := usernameOf(t, g, ps256); got != Anonymous {
			t.Fatal(got)
		}
		allowPS, _, _ := jwks(JWTConfig{Algorithms: []string{"PS256"}})
		if got := usernameOf(t, allowPS, ps256); got != "alice" {
			t.Fatal(got)
		}
		if got := usernameOf(t, allowPS, signWith(t, keyA, alice)); got != Anonymous {
			t.Fatal(got)
		}
	})

	t.Run("ignores a key whose alg its type cannot verify", func(t *testing.T) {
		wrongRSA, wrongEC := jwkOf(t, keyA), jwkOf(t, ec)
		wrongRSA["alg"], wrongEC["alg"] = "ES256", "HS256"
		reset(wrongRSA, wrongEC)
		g, _, _ := jwks(JWTConfig{})
		if usernameOf(t, g, signWith(t, keyA, alice)) != Anonymous || usernameOf(t, g, signWith(t, ec, alice)) != Anonymous {
			t.Fatal("a key verified an algorithm its type can't")
		}
	})

	t.Run("ignores symmetric and encryption keys published in the set", func(t *testing.T) {
		secret := []byte("shared-secret")
		encryption := jwkOf(t, keyB)
		encryption["use"] = "enc"
		reset(map[string]any{"kty": "oct", "k": base64.RawURLEncoding.EncodeToString(secret), "kid": "hmac"}, encryption)
		g, _, _ := jwks(JWTConfig{})
		if usernameOf(t, g, sign(t, "HS256", secret, "hmac", alice)) != Anonymous || usernameOf(t, g, signWith(t, keyB, alice)) != Anonymous {
			t.Fatal("a symmetric or encryption key verified a token")
		}
	})

	t.Run("re-fetches the set when a token is signed by a key rotated in since the last fetch", func(t *testing.T) {
		reset(jwkOf(t, keyA))
		g, c, _ := jwks(JWTConfig{})
		if usernameOf(t, g, signWith(t, keyA, alice)) != "alice" {
			t.Fatal("key A")
		}
		provider.publish(jwkOf(t, keyA), jwkOf(t, keyB))
		c.advance(31 * time.Second)
		if got := usernameOf(t, g, signWith(t, keyB, alice)); got != "alice" {
			t.Fatal(got)
		}
		if provider.fetchCount() != 2 {
			t.Fatal(provider.fetchCount())
		}
	})

	t.Run("re-fetches at most once per cooldown, however many unknown kids come in", func(t *testing.T) {
		reset(jwkOf(t, keyA))
		g, c, _ := jwks(JWTConfig{})
		usernameOf(t, g, signWith(t, keyA, alice))
		c.advance(31 * time.Second)
		for _, kid := range []string{"forged-1", "forged-2", "forged-3"} {
			if got := usernameOf(t, g, sign(t, "RS256", outsider.private, kid, alice)); got != Anonymous {
				t.Fatal(got)
			}
		}
		if provider.fetchCount() != 2 {
			t.Fatal(provider.fetchCount())
		}
	})

	t.Run("shares a single fetch between concurrent requests", func(t *testing.T) {
		reset(jwkOf(t, keyA))
		provider.set(func(i *idp) { i.delay = 100 * time.Millisecond })
		g, _, _ := jwks(JWTConfig{})
		token := signWith(t, keyA, alice)
		var wg sync.WaitGroup
		names := make([]string, 3)
		for n := range names {
			wg.Add(1)
			go func() {
				defer wg.Done()
				names[n] = Username(contextFor(t, g, request("GET", "/", bearerHeader(token))))
			}()
		}
		wg.Wait()
		if strings.Join(names, ",") != "alice,alice,alice" || provider.fetchCount() != 1 {
			t.Fatalf("%v, fetches %d", names, provider.fetchCount())
		}
	})

	t.Run("re-fetches the set once the cache max age has elapsed, dropping withdrawn keys", func(t *testing.T) {
		reset(jwkOf(t, keyA))
		g, c, _ := jwks(JWTConfig{JWKSCacheMaxAge: time.Minute})
		usernameOf(t, g, signWith(t, keyA, alice))
		provider.publish(jwkOf(t, keyB))
		c.advance(61 * time.Second)
		if got := usernameOf(t, g, signWith(t, keyA, alice)); got != Anonymous {
			t.Fatal(got)
		}
		if provider.fetchCount() != 2 {
			t.Fatal(provider.fetchCount())
		}
	})

	t.Run("keeps the last known keys when a fetch fails", func(t *testing.T) {
		reset(jwkOf(t, keyA))
		g, c, logged := jwks(JWTConfig{JWKSCacheMaxAge: time.Minute})
		usernameOf(t, g, signWith(t, keyA, alice))
		provider.set(func(i *idp) { i.status = http.StatusServiceUnavailable })
		c.advance(61 * time.Second)
		if got := usernameOf(t, g, signWith(t, keyA, alice)); got != "alice" {
			t.Fatal(got)
		}
		if provider.fetchCount() != 2 || !strings.Contains(logged.String(), "JWKS fetch failed") || !strings.Contains(logged.String(), "HTTP 503") {
			t.Fatalf("fetches %d, log %s", provider.fetchCount(), logged)
		}
	})

	t.Run("does not re-fetch for an expired token or one for another audience — its key is known", func(t *testing.T) {
		reset(jwkOf(t, keyA))
		g, c, logged := jwks(JWTConfig{Audience: Audience{Values: []string{"orders-api"}}})
		usernameOf(t, g, signWith(t, keyA, map[string]any{"sub": "alice", "aud": "orders-api"}))
		c.advance(31 * time.Second)
		expired := signWith(t, keyA, map[string]any{"sub": "alice", "aud": "orders-api", "exp": time.Now().Unix() - 60})
		otherAudience := signWith(t, keyA, map[string]any{"sub": "alice", "aud": "billing-api"})
		for _, token := range []string{expired, otherAudience} {
			if got := usernameOf(t, g, token); got != Anonymous {
				t.Fatal(got)
			}
		}
		if provider.fetchCount() != 1 || !strings.Contains(logged.String(), "jwt expired") || !strings.Contains(logged.String(), "jwt audience invalid. expected: orders-api") {
			t.Fatalf("fetches %d, log %s", provider.fetchCount(), logged)
		}
	})

	t.Run("tries every key when the token carries no kid", func(t *testing.T) {
		reset(jwkOf(t, keyA), jwkOf(t, keyB))
		g, _, _ := jwks(JWTConfig{})
		if got := usernameOf(t, g, sign(t, "RS256", keyB.private, "", alice)); got != "alice" {
			t.Fatal(got)
		}
	})

	t.Run("treats a request without a token as anonymous, without fetching or logging", func(t *testing.T) {
		reset(jwkOf(t, keyA))
		g, _, logged := jwks(JWTConfig{})
		if got := callerOf(t, g, request("GET", "/", nil)); got.Username != Anonymous {
			t.Fatal(got)
		}
		if provider.fetchCount() != 0 || logged.String() != "" {
			t.Fatalf("fetches %d, log %s", provider.fetchCount(), logged)
		}
	})

	t.Run("gives an anonymous caller when the JWK Set doesn't answer in time", func(t *testing.T) {
		g, _, logged := jwksGranted(t, JWTConfig{JWKSURI: provider.URL + "/hang", JWKSTimeout: 100 * time.Millisecond})
		if got := usernameOf(t, g, signWith(t, keyA, alice)); got != Anonymous {
			t.Fatal(got)
		}
		if !strings.Contains(logged.String(), "JWKS fetch failed") {
			t.Fatal(logged)
		}
	})

	t.Run("checks the issuer of a lone JWK Set when it is set", func(t *testing.T) {
		reset(jwkOf(t, keyA))
		g, _, logged := jwks(JWTConfig{Issuer: []string{"https://idp.acme"}})
		if got := usernameOf(t, g, signWith(t, keyA, map[string]any{"sub": "alice", "iss": "https://idp.acme"})); got != "alice" {
			t.Fatal(got)
		}
		if got := usernameOf(t, g, signWith(t, keyA, map[string]any{"sub": "alice", "iss": "https://evil.example"})); got != Anonymous {
			t.Fatal(got)
		}
		if !strings.Contains(logged.String(), "jwt issuer invalid. expected: https://idp.acme") {
			t.Fatal(logged)
		}
	})

	t.Run("refuses none and HS* at construction", func(t *testing.T) {
		for _, algs := range [][]string{{"HS256"}, {"RS256", "none"}} {
			if _, err := NewJWTProvider(JWTConfig{JWKSURI: provider.URL + "/jwks.json", Algorithms: algs}); err == nil {
				t.Errorf("%v accepted", algs)
			}
		}
	})
}

func TestOpenIDProviders(t *testing.T) {
	cluster, idpKey := rsaKey(t, "cluster"), ecKey(t, "idp")
	kubernetes, gateway := newIDP(t), newIDP(t)
	kubernetes.set(func(i *idp) { i.issuer = "https://kubernetes.default.svc.cluster.local" })
	gateway.set(func(i *idp) { i.issuer = "https://gateway.acme" })
	kubernetes.publish(jwkOf(t, cluster))
	gateway.publish(jwkOf(t, idpKey))
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pod-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	g, _, logged := jwksGranted(t, JWTConfig{
		Claims: ClaimMapping{Username: "preferred_username"},
		DiscoveryURIs: []OpenIDProvider{
			{URI: gateway.URL},
			{URI: kubernetes.URL + "/.well-known/openid-configuration", BearerTokenFile: tokenFile, Bypass: []string{"system:serviceaccount:my-namespace:*"}},
		},
	})
	trusted := g.Require(IsFalse())(whoami)

	t.Run("routes a token to the keys of its issuer, read from the discovery document", func(t *testing.T) {
		token := signWith(t, idpKey, map[string]any{"sub": "f81d4fae", "preferred_username": "alice", "iss": "https://gateway.acme"})
		if got := usernameOf(t, g, token); got != "alice" {
			t.Fatal(got)
		}
	})

	t.Run("refuses a token whose issuer no provider announces", func(t *testing.T) {
		logged.reset()
		token := signWith(t, idpKey, map[string]any{"preferred_username": "alice", "iss": "https://evil.example"})
		if got := usernameOf(t, g, token); got != Anonymous {
			t.Fatal(got)
		}
		if !strings.Contains(logged.String(), "jwt issuer invalid. expected:") {
			t.Fatal(logged)
		}
	})

	t.Run("never verifies a token with the keys of another issuer", func(t *testing.T) {
		token := signWith(t, cluster, map[string]any{"preferred_username": "alice", "iss": "https://gateway.acme"})
		if got := usernameOf(t, g, token); got != Anonymous {
			t.Fatal(got)
		}
	})

	t.Run("lets through a service account of the namespace, named by its sub", func(t *testing.T) {
		token := signWith(t, cluster, map[string]any{"sub": "system:serviceaccount:my-namespace:billing", "iss": "https://kubernetes.default.svc.cluster.local"})
		recorder := call(t, trusted, request("GET", "/", bearerHeader(token)))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"username":"system:serviceaccount:my-namespace:billing"`) {
			t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
		}
		other := signWith(t, cluster, map[string]any{"sub": "system:serviceaccount:other:billing", "iss": "https://kubernetes.default.svc.cluster.local"})
		if code := call(t, trusted, request("GET", "/", bearerHeader(other))).Code; code != http.StatusForbidden {
			t.Fatalf("status %d", code)
		}
	})

	t.Run("never bypasses on a claim alone: a gateway token with the same sub is checked", func(t *testing.T) {
		token := signWith(t, idpKey, map[string]any{"sub": "system:serviceaccount:my-namespace:billing", "iss": "https://gateway.acme"})
		if code := call(t, trusted, request("GET", "/", bearerHeader(token))).Code; code != http.StatusForbidden {
			t.Fatalf("status %d", code)
		}
	})

	t.Run("sends the bearer token to its own provider only", func(t *testing.T) {
		var k8s, gw string
		kubernetes.set(func(i *idp) { k8s = i.authorization })
		gateway.set(func(i *idp) { gw = i.authorization })
		if k8s != "Bearer pod-token" || gw != "" {
			t.Fatalf("kubernetes %q, gateway %q", k8s, gw)
		}
	})
}

func (i *idp) discoveryCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.discoveries
}

func TestDiscoveryURIsCaching(t *testing.T) {
	key := ecKey(t, "idp")
	alice := map[string]any{"sub": "alice", "iss": "https://gateway.acme"}

	t.Run("reads the discovery document once, then again past the cache max age", func(t *testing.T) {
		gateway := newIDP(t)
		gateway.set(func(i *idp) { i.issuer = "https://gateway.acme" })
		gateway.publish(jwkOf(t, key))
		g, c, _ := jwksGranted(t, JWTConfig{DiscoveryURIs: []OpenIDProvider{{URI: gateway.URL}}, JWKSCacheMaxAge: time.Minute})
		for range 3 {
			if got := usernameOf(t, g, signWith(t, key, alice)); got != "alice" {
				t.Fatal(got)
			}
		}
		if gateway.discoveryCount() != 1 || gateway.fetchCount() != 1 {
			t.Fatalf("discovery %d, jwks %d", gateway.discoveryCount(), gateway.fetchCount())
		}
		c.advance(61 * time.Second)
		usernameOf(t, g, signWith(t, key, alice))
		if gateway.discoveryCount() != 2 || gateway.fetchCount() != 2 {
			t.Fatalf("discovery %d, jwks %d", gateway.discoveryCount(), gateway.fetchCount())
		}
	})

	t.Run("re-reads it at most once per cooldown, however many unknown issuers come in", func(t *testing.T) {
		gateway := newIDP(t)
		gateway.set(func(i *idp) { i.issuer = "https://gateway.acme" })
		gateway.publish(jwkOf(t, key))
		g, c, _ := jwksGranted(t, JWTConfig{DiscoveryURIs: []OpenIDProvider{{URI: gateway.URL}}, JWKSCacheMaxAge: time.Minute})
		usernameOf(t, g, signWith(t, key, alice))
		c.advance(61 * time.Second)
		for _, iss := range []string{"https://forged-1", "https://forged-2", "https://forged-3"} {
			if got := usernameOf(t, g, signWith(t, key, map[string]any{"sub": "mallory", "iss": iss})); got != Anonymous {
				t.Fatal(got)
			}
		}
		if gateway.discoveryCount() != 2 {
			t.Fatal(gateway.discoveryCount())
		}
	})

	t.Run("checks a provider's own audience, in place of the global one", func(t *testing.T) {
		gateway, other := newIDP(t), newIDP(t)
		gateway.set(func(i *idp) { i.issuer = "https://gateway.acme" })
		other.set(func(i *idp) { i.issuer = "https://other.acme" })
		otherKey := rsaKey(t, "other")
		gateway.publish(jwkOf(t, key))
		other.publish(jwkOf(t, otherKey))
		g, _, logged := jwksGranted(t, JWTConfig{
			Audience:      Audience{Values: []string{"orders-api"}},
			DiscoveryURIs: []OpenIDProvider{{URI: gateway.URL}, {URI: other.URL, Audience: &Audience{Values: []string{"other-api"}}}},
		})
		if got := usernameOf(t, g, signWith(t, key, map[string]any{"sub": "alice", "iss": "https://gateway.acme", "aud": "orders-api"})); got != "alice" {
			t.Fatal(got)
		}
		if got := usernameOf(t, g, signWith(t, otherKey, map[string]any{"sub": "bob", "iss": "https://other.acme", "aud": "other-api"})); got != "bob" {
			t.Fatal(got)
		}
		if got := usernameOf(t, g, signWith(t, otherKey, map[string]any{"sub": "bob", "iss": "https://other.acme", "aud": "orders-api"})); got != Anonymous {
			t.Fatal(got)
		}
		if !strings.Contains(logged.String(), "jwt audience invalid. expected: other-api") {
			t.Fatal(logged)
		}
	})

	t.Run("re-reads the bearer token file at every fetch", func(t *testing.T) {
		cluster := newIDP(t)
		cluster.set(func(i *idp) { i.issuer = "https://kubernetes.default.svc.cluster.local" })
		cluster.publish(jwkOf(t, key))
		tokenFile := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(tokenFile, []byte("first"), 0o600); err != nil {
			t.Fatal(err)
		}
		g, c, _ := jwksGranted(t, JWTConfig{DiscoveryURIs: []OpenIDProvider{{URI: cluster.URL, BearerTokenFile: tokenFile}}, JWKSCacheMaxAge: time.Minute})
		token := signWith(t, key, map[string]any{"sub": "system:serviceaccount:ns:svc", "iss": "https://kubernetes.default.svc.cluster.local"})
		usernameOf(t, g, token)
		var sent string
		cluster.set(func(i *idp) { sent = i.authorization })
		if sent != "Bearer first" {
			t.Fatal(sent)
		}
		if err := os.WriteFile(tokenFile, []byte("rotated\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		c.advance(61 * time.Second)
		usernameOf(t, g, token)
		cluster.set(func(i *idp) { sent = i.authorization })
		if sent != "Bearer rotated" {
			t.Fatal(sent)
		}
	})
}
