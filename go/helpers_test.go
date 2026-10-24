package granted

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// logs captures what a logger writes, for a test to check what was — and
// wasn't — logged.
type logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logs) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.Reset()
}

// newLogger logs without timestamps: a test looking for a value that must not
// be logged doesn't trip on the digits of the time.
func newLogger() (*slog.Logger, *logs) {
	captured := &logs{}
	return slog.New(slog.NewTextHandler(captured, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}})), captured
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// clock is a time a test moves by hand, to cross a cooldown or a cache age without waiting.
type clock struct {
	mu      sync.Mutex
	elapsed time.Duration
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.elapsed)
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.elapsed += d
}

// testKey is a signing key and the public JWK the identity provider publishes for it.
type testKey struct {
	kid     string
	alg     string
	private any
	public  any
}

func rsaKey(t *testing.T, kid string) testKey {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{kid: kid, alg: "RS256", private: private, public: &private.PublicKey}
}

func ecKey(t *testing.T, kid string) testKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{kid: kid, alg: "ES256", private: private, public: &private.PublicKey}
}

func edKey(t *testing.T, kid string) testKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{kid: kid, alg: "EdDSA", private: private, public: public}
}

// jwkOf is the key as a JWK Set publishes it, with `kid`, `use` and `alg`.
func jwkOf(t *testing.T, k testKey) map[string]any {
	t.Helper()
	imported, err := jwk.Import(k.public)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(imported)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	out["kid"], out["use"], out["alg"] = k.kid, "sig", k.alg
	return out
}

// withoutAlg is the same JWK published without `alg` — as Microsoft Entra ID does.
func withoutAlg(jwk map[string]any) map[string]any {
	out := map[string]any{}
	for name, value := range jwk {
		if name != "alg" {
			out[name] = value
		}
	}
	return out
}

func pemOf(t *testing.T, public any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func segment(value any) string {
	raw, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// sign builds a compact JWS by hand, with the standard library: the tokens
// don't depend on the library under test, and any header can be forged.
func sign(t *testing.T, alg string, key any, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	input := segment(header) + "." + segment(claims)
	var hash crypto.Hash
	switch {
	case strings.HasSuffix(alg, "256"):
		hash = crypto.SHA256
	case strings.HasSuffix(alg, "384"):
		hash = crypto.SHA384
	case strings.HasSuffix(alg, "512"):
		hash = crypto.SHA512
	}
	digest := func() []byte {
		h := hash.New()
		h.Write([]byte(input))
		return h.Sum(nil)
	}
	var signature []byte
	var err error
	switch {
	case alg == "none":
	case alg == "EdDSA":
		signature = ed25519.Sign(key.(ed25519.PrivateKey), []byte(input))
	case strings.HasPrefix(alg, "HS"):
		mac := hmac.New(hash.New, key.([]byte))
		mac.Write([]byte(input))
		signature = mac.Sum(nil)
	case strings.HasPrefix(alg, "RS"):
		signature, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), hash, digest())
	case strings.HasPrefix(alg, "PS"):
		signature, err = rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), hash, digest(), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case strings.HasPrefix(alg, "ES"):
		private := key.(*ecdsa.PrivateKey)
		r, s, signErr := ecdsa.Sign(rand.Reader, private, digest())
		err = signErr
		size := (private.Curve.Params().BitSize + 7) / 8
		signature = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	default:
		t.Fatalf("sign: unsupported %s", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// signWith signs with the key's own algorithm and kid.
func signWith(t *testing.T, k testKey, claims map[string]any) string {
	t.Helper()
	return sign(t, k.alg, k.private, k.kid, claims)
}

// whoami answers the caller as the handler reads it.
var whoami = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{"username": Username(r.Context()), "roles": Roles(r.Context()), "tenant": Tenant(r.Context())})
})

type identity struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Tenant   string   `json:"tenant"`
}

func call(t *testing.T, handler http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

// callerOf runs a request through the middleware and returns the caller the handler saw.
func callerOf(t *testing.T, g *Granted, r *http.Request) identity {
	t.Helper()
	recorder := call(t, g.Middleware(whoami), r)
	var got identity
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("whoami: %v (%s)", err, recorder.Body.String())
	}
	return got
}

func request(method, target string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	return r
}

func bearerHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}
