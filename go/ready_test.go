package granted

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func readyProvider(t *testing.T, cfg JWTConfig) *JWTProvider {
	t.Helper()
	_, provider, _ := jwtGranted(t, cfg)
	return provider
}

func TestReady(t *testing.T) {
	t.Run("nothing to wait for without a JWK Set", func(t *testing.T) {
		if err := readyProvider(t, JWTConfig{Unverified: true}).Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("up once the keys are fetched, through the discovery document", func(t *testing.T) {
		gateway := newIDP(t)
		gateway.set(func(i *idp) { i.issuer = "https://gateway.acme" })
		gateway.publish(jwkOf(t, ecKey(t, "idp")))
		provider := readyProvider(t, JWTConfig{DiscoveryURIs: []OpenIDProvider{{URI: gateway.URL}}})
		if err := provider.Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
		if gateway.discoveryCount() != 1 || gateway.fetchCount() != 1 {
			t.Fatalf("%d discoveries, %d fetches", gateway.discoveryCount(), gateway.fetchCount())
		}
	})

	t.Run("down when the discovery is unreachable, naming the provider", func(t *testing.T) {
		gateway := newIDP(t)
		gateway.set(func(i *idp) { i.issuer, i.status = "https://gateway.acme", http.StatusServiceUnavailable })
		provider := readyProvider(t, JWTConfig{DiscoveryURIs: []OpenIDProvider{{URI: gateway.URL}}})
		err := provider.Ready(context.Background())
		if err == nil || !strings.Contains(err.Error(), gateway.URL+": OpenID configuration: HTTP 503") {
			t.Fatal(err)
		}
	})

	t.Run("down while a JWK Set has no key, up once it has", func(t *testing.T) {
		jwks := newIDP(t)
		jwks.set(func(i *idp) { i.keys = []map[string]any{} })
		provider := readyProvider(t, JWTConfig{JWKSURI: jwks.URL + "/jwks.json", JWKSCooldown: time.Nanosecond})
		err := provider.Ready(context.Background())
		if err == nil || !strings.Contains(err.Error(), jwks.URL+"/jwks.json: no key in the JWK Set") {
			t.Fatal(err)
		}
		jwks.set(func(i *idp) { i.status = http.StatusInternalServerError })
		if err := provider.Ready(context.Background()); err == nil || !strings.Contains(err.Error(), "JWK Set: HTTP 500") {
			t.Fatal(err)
		}
		jwks.set(func(i *idp) { i.status = http.StatusOK })
		jwks.publish(jwkOf(t, rsaKey(t, "a")))
		if err := provider.Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("leaves out a provider with SkipReadiness", func(t *testing.T) {
		gateway, kubernetes := newIDP(t), newIDP(t)
		gateway.set(func(i *idp) { i.issuer = "https://gateway.acme" })
		gateway.publish(jwkOf(t, ecKey(t, "idp")))
		kubernetes.set(func(i *idp) { i.status = http.StatusForbidden })
		provider := readyProvider(t, JWTConfig{DiscoveryURIs: []OpenIDProvider{
			{URI: gateway.URL},
			{URI: kubernetes.URL, SkipReadiness: true},
		}})
		if err := provider.Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
		if kubernetes.discoveryCount() != 0 {
			t.Fatal("the skipped provider was fetched")
		}
	})

	t.Run("probed in a loop, fetches no more than once per cooldown", func(t *testing.T) {
		jwks := newIDP(t)
		provider := readyProvider(t, JWTConfig{JWKSURI: jwks.URL + "/jwks.json"})
		for range 5 {
			if provider.Ready(context.Background()) == nil {
				t.Fatal("up without keys")
			}
		}
		if jwks.fetchCount() != 1 {
			t.Fatalf("%d fetches", jwks.fetchCount())
		}
	})

	t.Run("gives up waiting when its context ends", func(t *testing.T) {
		hung := newIDP(t)
		provider := readyProvider(t, JWTConfig{JWKSURI: hung.URL + "/hang", JWKSTimeout: 300 * time.Millisecond})
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if err := provider.Ready(ctx); err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
			t.Fatal(err)
		}
	})
}
