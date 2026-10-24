package granted

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// contextFor runs a request through g and returns the context its handler gets.
func contextFor(t *testing.T, g *Granted, r *http.Request) context.Context {
	t.Helper()
	var ctx context.Context
	call(t, g.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() })), r)
	return ctx
}

// claimsProvider is a provider whose claims are already typed, as a verified JWT's are.
func claimsProvider(claims map[string]any) Provider {
	return ProviderFunc(func(*http.Request) Principal {
		return Principal{Username: "alice", Claim: func(name string) any { return resolvePath(claims, name) }}
	})
}

func TestClaimsFromTypedValues(t *testing.T) {
	logger, logged := newLogger()
	ctx := contextFor(t, New(Options{Logger: logger, Provider: claimsProvider(map[string]any{
		"territories":  []any{"FR", "GP"},
		"single":       "FR",
		"maxAmount":    5000.0,
		"codes":        []any{1.0, 2.0},
		"auditor":      true,
		"realm_access": map[string]any{"territories": []any{"MQ"}},
		"mixed":        []any{"FR", 42.0, "GP"},
		"numbers":      []any{1.0, "two", 3.0},
		"asStrings":    []any{"1", 2.0},
		"wrong":        []any{41.0, 42.0},
		"amountText":   "a-lot",
		"half":         42.5,
		"stringAmount": "5000",
		"flag":         "false",
		"yes":          "yes",
	})}), request("GET", "/", nil))

	t.Run("reads a list, a number and a boolean", func(t *testing.T) {
		if got := Claims[string](ctx, "territories"); !reflect.DeepEqual(got, []string{"FR", "GP"}) {
			t.Error(got)
		}
		if got, ok := Claim[float64](ctx, "maxAmount"); !ok || got != 5000 {
			t.Error(got, ok)
		}
		if got, ok := Claim[int](ctx, "maxAmount"); !ok || got != 5000 {
			t.Error(got, ok)
		}
		if got := Claims[int](ctx, "codes"); !reflect.DeepEqual(got, []int{1, 2}) {
			t.Error(got)
		}
		if got, ok := Claim[bool](ctx, "auditor"); !ok || !got {
			t.Error(got, ok)
		}
	})

	t.Run("reads a nested claim by its dotted path, as is", func(t *testing.T) {
		if got := RawClaim(ctx, "realm_access.territories"); !reflect.DeepEqual(got, []any{"MQ"}) {
			t.Error(got)
		}
	})

	t.Run("takes a single value as a list of one", func(t *testing.T) {
		if got := Claims[string](ctx, "single"); !reflect.DeepEqual(got, []string{"FR"}) {
			t.Error(got)
		}
	})

	t.Run("gives the zero value, or an empty list, for a missing claim, without a warning", func(t *testing.T) {
		logged.reset()
		if got, ok := Claim[float64](ctx, "missing"); ok || got != 0 {
			t.Error(got, ok)
		}
		if got := Claims[string](ctx, "missing"); got == nil || len(got) != 0 {
			t.Errorf("%#v", got)
		}
		if logged.String() != "" {
			t.Error(logged)
		}
	})

	t.Run("ignores a value of the wrong type, with a warning that never shows it", func(t *testing.T) {
		logged.reset()
		if got := Claims[string](ctx, "wrong"); len(got) != 0 {
			t.Error(got)
		}
		if _, ok := Claim[float64](ctx, "amountText"); ok {
			t.Error("amountText")
		}
		if _, ok := Claim[bool](ctx, "yes"); ok {
			t.Error("yes")
		}
		if _, ok := Claim[int](ctx, "half"); ok {
			t.Error("half")
		}
		if _, ok := Claim[string](ctx, "territories"); ok {
			t.Error("a list where one value is expected")
		}
		out := logged.String()
		for _, want := range []string{"claim 'wrong' is not of the expected type (string[]): ignored", "claim 'amountText' is not of the expected type (number): ignored", "claim 'yes' is not of the expected type (boolean): ignored", "claim 'territories' is not of the expected type (string): ignored"} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in %s", want, out)
			}
		}
		for _, value := range []string{"a-lot", "41", "42"} {
			if strings.Contains(out, value) {
				t.Errorf("value %s logged: %s", value, out)
			}
		}
	})

	t.Run("drops only the elements of the wrong type from a list", func(t *testing.T) {
		logged.reset()
		if got := Claims[string](ctx, "mixed"); !reflect.DeepEqual(got, []string{"FR", "GP"}) {
			t.Error(got)
		}
		if got := Claims[int](ctx, "numbers"); !reflect.DeepEqual(got, []int{1, 3}) {
			t.Error(got)
		}
		out := logged.String()
		if !strings.Contains(out, "claim 'mixed': 1 element(s) not of the expected type (string) ignored") || !strings.Contains(out, "claim 'numbers': 1 element(s) not of the expected type (number) ignored") {
			t.Error(out)
		}
		if strings.Contains(out, "42") || strings.Contains(out, "two") {
			t.Error(out)
		}
	})

	t.Run("converts a number or a boolean given as a string — it is not of the wrong type", func(t *testing.T) {
		logged.reset()
		if got := Claims[int](ctx, "asStrings"); !reflect.DeepEqual(got, []int{1, 2}) {
			t.Error(got)
		}
		if got, ok := Claim[int64](ctx, "stringAmount"); !ok || got != 5000 {
			t.Error(got, ok)
		}
		if got, ok := Claim[bool](ctx, "flag"); !ok || got {
			t.Error(got, ok)
		}
		if logged.String() != "" {
			t.Error(logged)
		}
	})
}

func TestClaimsFromHeaders(t *testing.T) {
	logger, logged := newLogger()
	g := New(Options{Logger: logger})
	ctx := func(headers map[string]string) context.Context { return contextFor(t, g, request("GET", "/", headers)) }

	t.Run("parses a list given as JSON or as CSV", func(t *testing.T) {
		for _, header := range []string{`["FR","GP"]`, "FR, GP", " FR,GP , "} {
			if got := Claims[string](ctx(map[string]string{"territories": header}), "territories"); !reflect.DeepEqual(got, []string{"FR", "GP"}) {
				t.Errorf("%q: %v", header, got)
			}
		}
	})

	t.Run("converts numbers and booleans strictly", func(t *testing.T) {
		c := ctx(map[string]string{"maxAmount": "5000", "auditor": "false", "bad": "a-lot", "one": "1", "codes": "1, two", "words": "one, two"})
		if got, ok := Claim[int](c, "maxAmount"); !ok || got != 5000 {
			t.Error(got, ok)
		}
		if got, ok := Claim[bool](c, "auditor"); !ok || got {
			t.Error(got, ok)
		}
		if _, ok := Claim[float64](c, "bad"); ok {
			t.Error("bad")
		}
		if _, ok := Claim[bool](c, "one"); ok {
			t.Error("one")
		}
		if got := Claims[int](c, "codes"); !reflect.DeepEqual(got, []int{1}) {
			t.Error(got)
		}
		if got := Claims[int](c, "words"); len(got) != 0 {
			t.Error(got)
		}
	})

	t.Run("ignores a malformed JSON list", func(t *testing.T) {
		logged.reset()
		if got := Claims[string](ctx(map[string]string{"territories": `["FR",`}), "territories"); len(got) != 0 {
			t.Error(got)
		}
		if !strings.Contains(logged.String(), "claim 'territories' is not of the expected type (string[]): ignored") {
			t.Error(logged)
		}
	})

	t.Run("treats an empty header as missing", func(t *testing.T) {
		logged.reset()
		r := request("GET", "/", nil)
		r.Header["Territories"] = []string{""}
		if got := Claims[string](contextFor(t, g, r), "territories"); len(got) != 0 {
			t.Error(got)
		}
		if logged.String() != "" {
			t.Error(logged)
		}
	})

	t.Run("reads nothing without a caller in the context", func(t *testing.T) {
		if got := Claims[string](context.Background(), "territories"); got == nil || len(got) != 0 {
			t.Errorf("%#v", got)
		}
		if RawClaim(context.Background(), "territories") != nil || Username(context.Background()) != Anonymous {
			t.Error("no caller")
		}
	})
}

func TestHasClaims(t *testing.T) {
	g := New(Options{Logger: discard()})
	handler := g.Require(HasClaims[string]("territories"), HasClaim[int]("maxAmount"))(whoami)
	cases := []struct {
		headers map[string]string
		want    int
	}{
		{map[string]string{"territories": "FR", "maxAmount": "5000"}, http.StatusOK},
		{map[string]string{"maxAmount": "5000"}, http.StatusForbidden},
		{map[string]string{"territories": "FR", "maxAmount": "a-lot"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		if code := call(t, handler, request("GET", "/", tc.headers)).Code; code != tc.want {
			t.Errorf("%v: %d", tc.headers, code)
		}
	}
	typed := New(Options{Logger: discard(), Provider: claimsProvider(map[string]any{"territories": []any{"FR", 42.0}, "none": []any{42.0}})})
	if code := call(t, typed.Require(HasClaims[string]("territories"))(whoami), request("GET", "/", nil)).Code; code != http.StatusOK {
		t.Errorf("partial list: %d", code)
	}
	if code := call(t, typed.Require(HasClaims[string]("none"))(whoami), request("GET", "/", nil)).Code; code != http.StatusForbidden {
		t.Errorf("nothing left: %d", code)
	}
}
