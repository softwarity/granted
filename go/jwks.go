package granted

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// fetchPolicy is the cache age, the minimum delay between two fetches, and the
// timeout of a fetch.
type fetchPolicy struct {
	maxAge, cooldown, timeout time.Duration
}

// fetched is a value read over HTTP: cached, re-fetched once older than maxAge
// or when forced — but never twice within cooldown. A failed fetch keeps the
// last known value, so an identity provider's outage doesn't turn every caller
// anonymous. Concurrent requests share one fetch.
type fetched[T any] struct {
	policy  fetchPolicy
	now     func() time.Time
	load    func(ctx context.Context) (T, error)
	failure func() string
	logger  *slog.Logger

	mu          sync.Mutex
	value       T
	generation  uint64
	fetchedAt   time.Time
	attemptedAt time.Time
	pending     chan struct{}
}

// get returns the value and its generation: a generation that didn't change
// means nothing new was fetched.
func (f *fetched[T]) get(force bool) (T, uint64) {
	f.mu.Lock()
	now := f.now()
	fresh := !f.fetchedAt.IsZero() && now.Sub(f.fetchedAt) < f.policy.maxAge
	if (fresh && !force) || (f.pending == nil && !f.attemptedAt.IsZero() && now.Sub(f.attemptedAt) < f.policy.cooldown) {
		defer f.mu.Unlock()
		return f.value, f.generation
	}
	if pending := f.pending; pending != nil {
		f.mu.Unlock()
		<-pending
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.value, f.generation
	}
	f.attemptedAt = now
	pending := make(chan struct{})
	f.pending = pending
	f.mu.Unlock()

	// Not the request's context: the fetch is shared, and one caller leaving
	// mustn't fail it for the others.
	ctx, cancel := context.WithTimeout(context.Background(), f.policy.timeout)
	value, err := f.load(ctx)
	cancel()

	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		f.value = value
		f.generation++
		f.fetchedAt = f.now()
	} else {
		f.logger.Warn(f.failure() + ": " + err.Error())
	}
	f.pending = nil
	close(pending)
	return f.value, f.generation
}

// expire makes the next get fetch, cooldown or not — its URL changed. The last
// known value stays until then.
func (f *fetched[T]) expire() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetchedAt = time.Time{}
	f.attemptedAt = time.Time{}
}

// jwksKey is a key of a JWK Set, with the algorithms it verifies — set from
// the JWK Set and the allowlist, never from a token.
type jwksKey struct {
	kid        string
	key        any
	algorithms []string
}

type openidConfiguration struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// source is a JWK Set, the issuer its keys vouch for, and the audience and
// bypass that apply to their tokens.
type source struct {
	keys      *fetched[[]jwksKey]
	discovery *fetched[*openidConfiguration]
	audience  Audience
	bypass    []*regexp.Regexp

	mu      sync.Mutex
	jwksURI string
	// issuers routes tokens here. Nil for a lone JWKSURI configured without
	// Issuer: every token is. Nil for a discovery source until its document is
	// read: none is.
	issuers []string
}

func (p *JWTProvider) newSource(provider OpenIDProvider, issuer []string, audience *Audience) *source {
	s := &source{audience: *audience, jwksURI: provider.JWKSURI, issuers: issuer}
	for _, pattern := range provider.Bypass {
		s.bypass = append(s.bypass, subjectPattern(pattern))
	}
	s.keys = &fetched[[]jwksKey]{
		policy: p.policy, now: p.clock, logger: p.logger,
		load: func(ctx context.Context) ([]jwksKey, error) {
			body, err := p.fetch(ctx, s.uri(), provider.BearerTokenFile)
			if err != nil {
				return nil, err
			}
			return p.parseJWKS(body)
		},
		failure: func() string { return "JWKS fetch failed (" + s.uri() + ")" },
	}
	if provider.JWKSURI == "" {
		discoveryURI := openidConfigurationURL(provider.URI)
		s.discovery = &fetched[*openidConfiguration]{
			policy: p.policy, now: p.clock, logger: p.logger,
			load: func(ctx context.Context) (*openidConfiguration, error) {
				body, err := p.fetch(ctx, discoveryURI, provider.BearerTokenFile)
				if err != nil {
					return nil, err
				}
				var configuration openidConfiguration
				if json.Unmarshal(body, &configuration) != nil || configuration.Issuer == "" || configuration.JWKSURI == "" {
					return nil, errors.New(`no "issuer" or "jwks_uri" in the response`)
				}
				return &configuration, nil
			},
			failure: func() string { return "OpenID configuration fetch failed (" + discoveryURI + ")" },
		}
	}
	return s
}

// clock reads p.now at call time, so a test can move it after construction.
func (p *JWTProvider) clock() time.Time { return p.now() }

func (s *source) uri() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwksURI
}

func (s *source) expectedIssuers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issuers
}

// discover brings the issuer and the JWK Set URL up to date from the discovery
// document — nothing to do when they are configured.
func (s *source) discover() {
	if s.discovery == nil {
		return
	}
	configuration, _ := s.discovery.get(false)
	if configuration == nil {
		return
	}
	s.mu.Lock()
	changed := configuration.JWKSURI != s.jwksURI
	s.jwksURI = configuration.JWKSURI
	s.issuers = []string{configuration.Issuer}
	s.mu.Unlock()
	if changed {
		s.keys.expire()
	}
}

func (s *source) accepts(iss any) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.issuers == nil {
		return s.discovery == nil
	}
	value, ok := iss.(string)
	return ok && slices.Contains(s.issuers, value)
}

func (s *source) bypasses(claims map[string]any) bool {
	sub, ok := claims["sub"].(string)
	if !ok {
		return false
	}
	for _, pattern := range s.bypass {
		if pattern.MatchString(sub) {
			return true
		}
	}
	return false
}

// subjectPattern compiles a `sub` pattern: `*` matches any run of characters,
// everything else is literal.
func subjectPattern(pattern string) *regexp.Regexp {
	parts := strings.Split(pattern, "*")
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$")
}

const openidConfigurationPath = "/.well-known/openid-configuration"

func openidConfigurationURL(uri string) string {
	if strings.HasSuffix(uri, openidConfigurationPath) {
		return uri
	}
	return strings.TrimRight(uri, "/") + openidConfigurationPath
}

// maxDocument bounds a JWK Set or a discovery document.
const maxDocument = 1 << 20

func (p *JWTProvider) fetch(ctx context.Context, url, bearerTokenFile string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if bearerTokenFile != "" {
		// Read at every fetch: a projected token is rotated on disk by the kubelet.
		token, err := os.ReadFile(bearerTokenFile)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	}
	response, err := p.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, maxDocument))
}

// parseJWKS reads the public signature keys of a JWK Set. Encryption keys, and
// entries that aren't public keys (symmetric `oct` ones, which would open the
// door to HS256 forgeries), are skipped.
func (p *JWTProvider) parseJWKS(body []byte) ([]jwksKey, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(body, &set) != nil || set.Keys == nil {
		return nil, errors.New(`no "keys" array in the response`)
	}
	keys := []jwksKey{}
	for _, raw := range set.Keys {
		var meta struct {
			Kid string  `json:"kid"`
			Alg *string `json:"alg"`
			Use string  `json:"use"`
		}
		if json.Unmarshal(raw, &meta) != nil || meta.Use == "enc" {
			continue
		}
		parsed, err := jwk.ParseKey(raw)
		if err != nil {
			continue
		}
		public, err := jwk.PublicRawKeyOf(parsed)
		if err != nil {
			continue
		}
		possible := keyAlgorithms(public)
		if len(possible) == 0 {
			continue
		}
		keys = append(keys, jwksKey{kid: meta.Kid, key: public, algorithms: p.keyAlgorithms(possible, meta.Alg)})
	}
	return keys, nil
}

// keyAlgorithms is the `alg` the JWK declares, provided its key type can
// verify it. Without `alg`: the one the key type implies (RSA → RS256, EC →
// its curve's ES*, Ed25519 → EdDSA) or, when Algorithms is configured,
// whichever of those the key type can verify — an RSA key may sign PS256 as
// well. Empty when nothing fits: the key verifies no token.
func (p *JWTProvider) keyAlgorithms(possible []string, declared *string) []string {
	if p.algorithms == nil {
		if declared == nil {
			return possible[:1]
		}
		if slices.Contains(possible, *declared) {
			return []string{*declared}
		}
		return nil
	}
	var out []string
	for _, alg := range possible {
		if slices.Contains(p.algorithms, alg) && (declared == nil || alg == *declared) {
			out = append(out, alg)
		}
	}
	return out
}

func (p *JWTProvider) sourcesFor(iss any) []*source {
	var out []*source
	for _, s := range p.sources {
		if s.accepts(iss) {
			out = append(out, s)
		}
	}
	return out
}

func (p *JWTProvider) unknownIssuer() error {
	var known []string
	for _, s := range p.sources {
		known = append(known, s.expectedIssuers()...)
	}
	if len(known) == 0 {
		return verifyError("jwt issuer invalid: no OpenID configuration fetched yet")
	}
	return verifyError("jwt issuer invalid. expected: " + strings.Join(known, " or "))
}

// verifyWithJWKS routes the token to the JWK Set of its issuer and verifies it
// with the cached keys; on failure, re-fetches the set once and retries — the
// identity provider may have rotated its keys.
func (p *JWTProvider) verifyWithJWKS(compact string, t token) (map[string]any, bool, error) {
	iss := t.payload["iss"]
	// Only the documents that may announce the token's issuer are awaited: a hung provider doesn't slow down the others.
	discover := p.sourcesFor(iss)
	if len(discover) == 0 {
		discover = p.sources
	}
	var wg sync.WaitGroup
	for _, s := range discover {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.discover()
		}()
	}
	wg.Wait()

	failure := p.unknownIssuer()
	for _, s := range p.sourcesFor(iss) {
		keys, generation := s.keys.get(false)
		claims, err := p.verifyWithKeys(compact, t, keys, s)
		if err == nil {
			return claims, s.bypasses(claims), nil
		}
		failure = err
		if signatureMatched(err) {
			continue
		}
		refreshed, newGeneration := s.keys.get(true)
		if newGeneration == generation {
			continue
		}
		if claims, err = p.verifyWithKeys(compact, t, refreshed, s); err == nil {
			return claims, s.bypasses(claims), nil
		}
		failure = err
	}
	return nil, false, failure
}

// verifyWithKeys verifies with the key matching `kid` or, when the token has
// none, with each key in turn. The algorithm is the key's: the token's `alg`
// only has to agree with it. Taking it from the token is what `alg: none` and
// RS/HS confusion attacks rely on.
func (p *JWTProvider) verifyWithKeys(compact string, t token, keys []jwksKey, s *source) (map[string]any, error) {
	var failure error = verifyError("no JWKS key matches the token")
	for _, key := range keys {
		if t.kid != "" && key.kid != t.kid {
			continue
		}
		if !slices.Contains(key.algorithms, t.alg) {
			failure = verifyError("invalid algorithm")
			continue
		}
		claims, err := p.checkSignature(compact, t.alg, key.key)
		if err == nil {
			err = p.validate(claims, s.expectedIssuers(), s.audience)
		}
		if err == nil {
			return claims, nil
		}
		if signatureMatched(err) {
			return nil, err
		}
		failure = err
	}
	return nil, failure
}
