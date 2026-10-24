package granted

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// ClaimMapping names the claims the caller's identity is read from. Each one
// accepts a dotted path for a nested claim (Keycloak's `realm_access.roles`).
// An empty field takes its default.
type ClaimMapping struct {
	// Username claim. Defaults to `sub`.
	Username string
	// Roles claim: an array, or a string read as a JSON array or a comma-separated list. Defaults to `roles`.
	Roles string
	// Tenant claim. Defaults to `tenant`.
	Tenant string
}

// Claim mappings of well-known identity providers, for [JWTConfig.Claims].
var (
	// RFC9068 is the "JWT Profile for OAuth 2.0 Access Tokens", with SCIM's `roles`.
	RFC9068 = ClaimMapping{Username: "sub", Roles: "roles", Tenant: "tenant"}
	// AzureAD is Microsoft Entra ID: the UPN in `preferred_username`, the tenant in `tid`.
	AzureAD = ClaimMapping{Username: "preferred_username", Roles: "roles", Tenant: "tid"}
	// Keycloak keeps the realm roles under `realm_access.roles`.
	Keycloak = ClaimMapping{Username: "preferred_username", Roles: "realm_access.roles", Tenant: "tenant"}
	// Okta exposes the authorities as `groups`.
	Okta = ClaimMapping{Username: "sub", Roles: "groups", Tenant: "tenant"}
)

// Audience lists the accepted `aud` values. A token passes when one of its
// audiences equals a value or matches a pattern. Unset: not checked.
type Audience struct {
	Values   []string
	Patterns []*regexp.Regexp
}

func (a Audience) set() bool { return len(a.Values)+len(a.Patterns) > 0 }

func (a Audience) accepts(aud any) bool {
	var audiences []string
	switch v := aud.(type) {
	case string:
		audiences = []string{v}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				audiences = append(audiences, s)
			}
		}
	}
	for _, candidate := range audiences {
		if slices.Contains(a.Values, candidate) {
			return true
		}
		for _, pattern := range a.Patterns {
			if pattern.MatchString(candidate) {
				return true
			}
		}
	}
	return false
}

func (a Audience) String() string {
	expected := slices.Clone(a.Values)
	for _, pattern := range a.Patterns {
		expected = append(expected, "/"+pattern.String()+"/")
	}
	return strings.Join(expected, " or ")
}

// OpenIDProvider is an identity provider whose tokens are trusted: by its
// discovery document (URI), or by its issuer and JWK Set given outright.
type OpenIDProvider struct {
	// URI of the discovery document, or the URL it lives under
	// (`/.well-known/openid-configuration` is then appended). Not needed when
	// Issuer and JWKSURI are given.
	URI string
	// Issuer, given instead of read from the discovery document — with JWKSURI,
	// the two together. For a provider whose document announces a `jwks_uri` the
	// service cannot reach: the Kubernetes API server announces its internal
	// control-plane address.
	Issuer string
	// JWKSURI, given instead of read from the discovery document — with Issuer.
	JWKSURI string
	// BearerTokenFile holds a token sent as `Authorization: Bearer` to this
	// provider's discovery document and JWK Set — never to another. Read at
	// every fetch, so a rotated token is picked up. The Kubernetes API server
	// answers 403 without one.
	BearerTokenFile string
	// Audience of this provider's tokens, in place of [JWTConfig.Audience].
	Audience *Audience
	// Bypass lists `sub` patterns (`*` matches anything) whose tokens, from this
	// provider, pass every [Granted.Require] — e.g.
	// `system:serviceaccount:my-namespace:*` for the services of a namespace.
	Bypass []string
}

// JWTConfig configures [NewJWTProvider]: where the keys come from, which
// algorithms they verify, what the token must say, and which claims carry the
// identity.
type JWTConfig struct {
	// Claims carrying the identity. Defaults to `sub`, `roles`, `tenant`; see
	// [RFC9068], [AzureAD], [Keycloak], [Okta].
	Claims ClaimMapping

	// Key is a PEM public key — or, with HS* Algorithms, the shared secret.
	Key string
	// KeyFile is a file holding Key, read once at construction.
	KeyFile string
	// JWKSURI is the URL of the JWK Set the identity provider publishes, e.g.
	// `https://idp.example.com/.well-known/jwks.json`. Keys are fetched on first
	// use, cached, and re-fetched when a token fails verification — a key
	// rotation needs no restart. Each key verifies with its own algorithm, never
	// the one the token announces. Can't be combined with Key / KeyFile.
	JWKSURI string
	// DiscoveryURIs are the OpenID DiscoveryURIs to trust — nestjs-granted's
	// `discoveryUris`: an entry with only URI is its plain-string form. A token is verified only with the
	// keys of the provider whose issuer is its `iss`; any other `iss` is
	// rejected, and no URL is ever taken from the token. Can be combined with
	// JWKSURI, which then needs Issuer; not with Key / KeyFile.
	DiscoveryURIs []OpenIDProvider

	// Algorithms. With Key: the ones accepted, `ES256` by default; all HS*
	// (Key is then a shared secret) or none of them. With a JWK Set: optional,
	// an allowlist — each key verifies with its own algorithm, and only
	// RS*, PS*, ES* and EdDSA are accepted. `none` is never accepted.
	Algorithms []string
	// Issuer lists the accepted `iss`. Not checked when unset. With DiscoveryURIs,
	// it applies to JWKSURI only, and is required with it.
	Issuer []string
	// Audience lists the accepted `aud`. Not checked when unset.
	Audience Audience

	// JWKSCacheMaxAge after which a JWK Set or a discovery document is re-fetched. Defaults to 10 minutes.
	JWKSCacheMaxAge time.Duration
	// JWKSCooldown: never two fetches of a JWK Set or a discovery document closer
	// than this, so tokens with forged `kid`s or issuers can't make the
	// provider hammer the identity provider. Defaults to 30 seconds.
	JWKSCooldown time.Duration
	// JWKSTimeout of a fetch of a JWK Set or a discovery document. Defaults to 5 seconds.
	JWKSTimeout time.Duration
	// HTTPClient fetches the JWK Sets and the discovery documents. Defaults to a plain client.
	HTTPClient *http.Client
	// Logger receives the verification failures — never the token. Defaults to slog.Default().
	Logger *slog.Logger

	// Unverified reads the claims of a token whose signature is NOT checked,
	// for a service only reachable through a gateway that already verified it.
	// Anyone else can write any claim. Exclusive with every key option.
	Unverified bool
}

// JWTProvider reads the caller from a verified JWT carried in the
// `Authorization: Bearer <token>` header. A token that is missing, malformed
// or fails verification gives an anonymous caller: it is up to the specs to
// refuse it. The identity headers a gateway would send are never read.
type JWTProvider struct {
	claims     ClaimMapping
	algorithms []string
	key        any
	issuer     []string
	audience   Audience
	sources    []*source
	unverified bool
	client     *http.Client
	logger     *slog.Logger
	policy     fetchPolicy
	now        func() time.Time
}

// jwksAlgorithms are what a JWK Set key may verify: asymmetric signatures only
// — never `none`, never a shared-secret HS*.
var jwksAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// NewJWTProvider checks cfg and returns the provider. Nothing is fetched yet:
// the JWK Sets and discovery documents are read on the first token.
func NewJWTProvider(cfg JWTConfig) (*JWTProvider, error) {
	for _, provider := range cfg.DiscoveryURIs {
		if (provider.Issuer != "") != (provider.JWKSURI != "") {
			return nil, errors.New("granted: a DiscoveryURIs entry gives Issuer and JWKSURI together, or neither")
		}
		if provider.URI == "" && provider.JWKSURI == "" {
			return nil, errors.New("granted: each DiscoveryURIs entry needs a URI — or an Issuer and a JWKSURI")
		}
		if slices.Contains(provider.Bypass, "") {
			return nil, errors.New("granted: Bypass is a list of sub patterns, e.g. system:serviceaccount:my-namespace:*")
		}
	}
	jwks := cfg.JWKSURI != "" || len(cfg.DiscoveryURIs) > 0
	keyed := cfg.Key != "" || cfg.KeyFile != ""
	switch {
	case cfg.JWKSURI != "" && keyed:
		return nil, errors.New("granted: JWKSURI cannot be combined with Key or KeyFile")
	case len(cfg.DiscoveryURIs) > 0 && keyed:
		return nil, errors.New("granted: DiscoveryURIs cannot be combined with Key or KeyFile")
	case len(cfg.DiscoveryURIs) > 0 && len(cfg.Issuer) > 0 && cfg.JWKSURI == "":
		return nil, errors.New("granted: Issuer applies to JWKSURI only: DiscoveryURIs take their issuer from their discovery document")
	case len(cfg.DiscoveryURIs) > 0 && cfg.JWKSURI != "" && len(cfg.Issuer) == 0:
		// Without it, JWKSURI's keys would be tried on any token — the DiscoveryURIs' included.
		return nil, errors.New("granted: JWKSURI needs an Issuer when combined with DiscoveryURIs, to route its tokens")
	case cfg.Unverified && (keyed || jwks):
		return nil, errors.New("granted: Unverified cannot be combined with a key: a token is either verified or not")
	case (len(cfg.Issuer) > 0 || cfg.Audience.set()) && !keyed && !jwks:
		// An unverified token's claims can say anything: checking them would only look secure.
		return nil, errors.New("granted: Issuer and Audience need a key to verify the token: Key, KeyFile, JWKSURI or DiscoveryURIs")
	case !keyed && !jwks && !cfg.Unverified:
		return nil, errors.New("granted: no key to verify tokens with: set Key, KeyFile, JWKSURI or DiscoveryURIs — or Unverified, behind a gateway that verifies them")
	}

	p := &JWTProvider{
		claims:     cfg.Claims,
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		unverified: cfg.Unverified,
		client:     cfg.HTTPClient,
		logger:     cfg.Logger,
		policy:     fetchPolicy{maxAge: orDuration(cfg.JWKSCacheMaxAge, 10*time.Minute), cooldown: orDuration(cfg.JWKSCooldown, 30*time.Second), timeout: orDuration(cfg.JWKSTimeout, 5*time.Second)},
		now:        time.Now,
	}
	if p.client == nil {
		p.client = &http.Client{}
	}
	if p.logger == nil {
		p.logger = slog.Default()
	}

	if cfg.Algorithms != nil && len(cfg.Algorithms) == 0 {
		return nil, errors.New("granted: Algorithms is an empty list: no token could be verified")
	}
	p.algorithms = cfg.Algorithms
	if p.algorithms == nil && keyed {
		// The default is for a key only: with a JWK Set, each key brings its own algorithm.
		p.algorithms = []string{"ES256"}
	}
	for _, alg := range p.algorithms {
		if _, ok := jwa.LookupSignatureAlgorithm(alg); !ok || alg == "none" {
			return nil, fmt.Errorf("granted: unknown or refused algorithm %q", alg)
		}
	}
	if jwks {
		// A JWK Set publishes public keys: `none` and the shared-secret HS* have no place here.
		var refused []string
		for _, alg := range p.algorithms {
			if !slices.Contains(jwksAlgorithms, alg) {
				refused = append(refused, alg)
			}
		}
		if len(refused) > 0 {
			return nil, fmt.Errorf("granted: algorithm %s cannot be used with JWKSURI or DiscoveryURIs, which accept %s", strings.Join(refused, ", "), strings.Join(jwksAlgorithms, ", "))
		}
	}
	if keyed {
		if err := p.loadKey(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.JWKSURI != "" {
		p.sources = append(p.sources, p.newSource(OpenIDProvider{JWKSURI: cfg.JWKSURI}, cfg.Issuer, &cfg.Audience))
	}
	for _, provider := range cfg.DiscoveryURIs {
		var issuer []string
		if provider.Issuer != "" {
			issuer = []string{provider.Issuer}
		}
		audience := provider.Audience
		if audience == nil {
			audience = &cfg.Audience
		}
		p.sources = append(p.sources, p.newSource(provider, issuer, audience))
	}
	return p, nil
}

// loadKey reads the key: a shared secret for HS*, a PEM public key otherwise,
// which must be able to verify at least one of the algorithms.
func (p *JWTProvider) loadKey(cfg JWTConfig) error {
	material := cfg.Key
	if cfg.KeyFile != "" {
		read, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("granted: KeyFile: %w", err)
		}
		material = string(read)
	}
	hmac := 0
	for _, alg := range p.algorithms {
		if strings.HasPrefix(alg, "HS") {
			hmac++
		}
	}
	if hmac > 0 {
		if hmac != len(p.algorithms) {
			// A key is a secret or a public key: accepting both is what RS/HS confusion attacks rely on.
			return errors.New("granted: Algorithms mixes HS* with asymmetric algorithms: a key is a shared secret or a public key, not both")
		}
		p.key = []byte(material)
		return nil
	}
	parsed, err := jwk.ParseKey([]byte(material), jwk.WithPEM(true))
	if err != nil {
		return fmt.Errorf("granted: Key is not a PEM public key: %w", err)
	}
	public, err := jwk.PublicRawKeyOf(parsed)
	if err != nil {
		return fmt.Errorf("granted: Key is not a PEM public key: %w", err)
	}
	possible := keyAlgorithms(public)
	var usable []string
	for _, alg := range p.algorithms {
		if slices.Contains(possible, alg) {
			usable = append(usable, alg)
		}
	}
	if len(usable) == 0 {
		return fmt.Errorf("granted: this key can't verify %s: it verifies %s", strings.Join(p.algorithms, ", "), strings.Join(possible, ", "))
	}
	p.algorithms = usable
	p.key = public
	return nil
}

// keyAlgorithms are the algorithms a public key can verify, the one assumed
// for a JWK without `alg` first.
func keyAlgorithms(key any) []string {
	switch k := key.(type) {
	case *rsa.PublicKey, rsa.PublicKey:
		return []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	case *ecdsa.PublicKey:
		return curveAlgorithm(k.Curve.Params().Name)
	case ecdsa.PublicKey:
		return curveAlgorithm(k.Curve.Params().Name)
	case ed25519.PublicKey:
		return []string{"EdDSA"}
	}
	return nil
}

func curveAlgorithm(curve string) []string {
	switch curve {
	case "P-256":
		return []string{"ES256"}
	case "P-384":
		return []string{"ES384"}
	case "P-521":
		return []string{"ES512"}
	}
	return nil
}

// Resolve reads the caller from r's bearer token.
func (p *JWTProvider) Resolve(r *http.Request) Principal {
	token := bearer(r.Header.Get("Authorization"))
	if token == "" {
		return Principal{}
	}
	claims, bypassed, err := p.verify(token)
	if err != nil {
		// Never log the token or the key material: the request simply goes on anonymous.
		label := "JWKS"
		if p.algorithms != nil {
			label = strings.Join(p.algorithms, ", ")
		}
		p.logger.Warn("JWT verification failed (" + label + "): " + err.Error())
		return Principal{}
	}
	username, _ := resolvePath(claims, or(p.claims.Username, "sub")).(string)
	if username == "" && bypassed {
		// A bypassing token may lack the username claim — a service account has no `preferred_username`: its `sub` names it.
		username, _ = claims["sub"].(string)
	}
	tenant, _ := resolvePath(claims, or(p.claims.Tenant, "tenant")).(string)
	return Principal{
		Username: username,
		Roles:    stringsOf(resolvePath(claims, or(p.claims.Roles, "roles"))),
		Tenant:   tenant,
		Bypassed: bypassed,
		Claim:    func(name string) any { return resolvePath(claims, name) },
	}
}

// bearer is the token after the scheme of an Authorization header.
func bearer(header string) string {
	fields := strings.Fields(header)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

// verifyError is a token that failed verification.
type verifyError string

func (e verifyError) Error() string { return string(e) }

// claimsError is a token whose signature matched, refused for its dates,
// issuer or audience: no other key can do better, and no re-fetch is needed.
type claimsError string

func (e claimsError) Error() string { return string(e) }

func signatureMatched(err error) bool {
	var matched claimsError
	return errors.As(err, &matched)
}

// token is a compact JWS, decoded but not verified: enough to route it.
type token struct {
	alg     string
	kid     string
	payload map[string]any
}

func parseToken(compact string) (token, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return token{}, verifyError("jwt malformed")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	var payload map[string]any
	if decodeSegment(parts[0], &header) != nil || decodeSegment(parts[1], &payload) != nil || payload == nil {
		return token{}, verifyError("jwt malformed")
	}
	return token{alg: header.Alg, kid: header.Kid, payload: payload}, nil
}

func decodeSegment(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(segment, "="))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func (p *JWTProvider) verify(compact string) (map[string]any, bool, error) {
	t, err := parseToken(compact)
	if err != nil {
		return nil, false, err
	}
	if p.unverified {
		return t.payload, false, nil
	}
	if len(p.sources) == 0 {
		if !slices.Contains(p.algorithms, t.alg) {
			return nil, false, verifyError("invalid algorithm")
		}
		claims, err := p.checkSignature(compact, t.alg, p.key)
		if err != nil {
			return nil, false, err
		}
		return claims, false, p.validate(claims, p.issuer, p.audience)
	}
	return p.verifyWithJWKS(compact, t)
}

// checkSignature verifies the signature with alg — chosen by the caller, from
// the key or the configuration — and returns the signed claims.
func (p *JWTProvider) checkSignature(compact, alg string, key any) (map[string]any, error) {
	algorithm, ok := jwa.LookupSignatureAlgorithm(alg)
	if !ok {
		return nil, verifyError("invalid algorithm")
	}
	signed, err := jws.Verify([]byte(compact), jws.WithKey(algorithm, key))
	if err != nil {
		return nil, verifyError("invalid signature")
	}
	var claims map[string]any
	if json.Unmarshal(signed, &claims) != nil || claims == nil {
		return nil, verifyError("jwt malformed")
	}
	return claims, nil
}

// validate checks the claims of a token whose signature matched: its dates,
// then its audience and issuer when they are expected.
func (p *JWTProvider) validate(claims map[string]any, issuer []string, audience Audience) error {
	now := float64(p.now().Unix())
	if value, ok := claims["nbf"]; ok {
		nbf, isNumber := value.(float64)
		if !isNumber {
			return verifyError("invalid nbf value")
		}
		if nbf > now {
			return claimsError("jwt not active")
		}
	}
	if value, ok := claims["exp"]; ok {
		exp, isNumber := value.(float64)
		if !isNumber {
			return verifyError("invalid exp value")
		}
		if now >= exp {
			return claimsError("jwt expired")
		}
	}
	if audience.set() && !audience.accepts(claims["aud"]) {
		return claimsError("jwt audience invalid. expected: " + audience.String())
	}
	if len(issuer) > 0 {
		if iss, _ := claims["iss"].(string); !slices.Contains(issuer, iss) {
			return claimsError("jwt issuer invalid. expected: " + strings.Join(issuer, ","))
		}
	}
	return nil
}

func orDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}
