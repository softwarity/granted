package granted

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// Spec is a rule a route requires of its caller.
type Spec struct {
	// ID names the rule in a refusal, e.g. `hasRole(ADMIN)`.
	ID string
	// Check reports whether the caller of r satisfies the rule.
	Check func(r *http.Request, c *Caller) bool

	// How [Describe] reads the rule; nil for a spec built by hand, which reads
	// as an authenticated caller, labelled by its ID.
	description *description
}

// And passes when every spec passes.
func And(specs ...Spec) Spec {
	return Spec{
		ID: "and(" + ids(specs) + ")",
		Check: func(r *http.Request, c *Caller) bool {
			for _, spec := range specs {
				if !spec.Check(r, c) {
					return false
				}
			}
			return true
		},
		description: &description{alternatives: andAlternatives(specs), label: joinLabels(specs, "and"), compound: len(specs) > 1},
	}
}

// Or passes when at least one spec passes.
func Or(specs ...Spec) Spec {
	return Spec{
		ID: "or(" + ids(specs) + ")",
		Check: func(r *http.Request, c *Caller) bool {
			for _, spec := range specs {
				if spec.Check(r, c) {
					return true
				}
			}
			return false
		},
		description: &description{alternatives: orAlternatives(specs), label: joinLabels(specs, "or"), compound: len(specs) > 1},
	}
}

// Not passes when spec fails.
func Not(spec Spec) Spec {
	return Spec{
		ID:    "not(" + spec.ID + ")",
		Check: func(r *http.Request, c *Caller) bool { return !spec.Check(r, c) },
		// Not of a role is no role to grant: an authenticated caller.
		description: &description{alternatives: []alternative{{}}, label: "not(" + joinLabels([]Spec{spec}, "and") + ")"},
	}
}

// IsTrue always passes.
func IsTrue() Spec {
	return Spec{ID: "isTrue()", Check: func(*http.Request, *Caller) bool { return true }, description: &description{alternatives: []alternative{nil}, label: "isTrue()"}}
}

// IsFalse never passes.
func IsFalse() Spec {
	return Spec{ID: "isFalse()", Check: func(*http.Request, *Caller) bool { return false }, description: &description{alternatives: []alternative{}, label: "isFalse()"}}
}

// HasRole passes when the caller holds role, after the hierarchy.
func HasRole(role string) Spec {
	return Spec{
		ID:          "hasRole(" + role + ")",
		Check:       func(_ *http.Request, c *Caller) bool { return c.HasRole(role) },
		description: &description{alternatives: []alternative{{role}}, label: "hasRole(" + role + ")"},
	}
}

// IsAuthenticated passes when something identified the caller.
func IsAuthenticated() Spec {
	return Spec{ID: "isAuthenticated()", Check: func(_ *http.Request, c *Caller) bool { return c.Authenticated() }}
}

// Source is where [IsUser] and [IsTenant] read the value they compare.
type Source string

const (
	// Param is a path parameter, as r.PathValue reads it (the standard mux's
	// `{name}` wildcards; routers that set path values, too).
	Param Source = "Param"
	// Query is a query-string parameter.
	Query Source = "Query"
	// Body is a field of a JSON body, by dotted path (`customer.id`). The body
	// stays readable by the handler.
	Body Source = "Body"
)

// IsUser passes when the request names the caller: the value at field is its username.
// A caller only touches its own records.
func IsUser(from Source, field string) Spec {
	return Spec{
		ID: "isUser(" + string(from) + ", " + field + ")",
		Check: func(r *http.Request, c *Caller) bool {
			value, ok := requestValue(r, from, field)
			return ok && value == c.Username
		},
	}
}

// IsTenant passes when the value at field is the caller's tenant — e.g. a user
// of tenant A hitting /tenants/B/... is refused. A caller without a tenant is refused.
func IsTenant(from Source, field string) Spec {
	return Spec{
		ID: "isTenant(" + string(from) + ", " + field + ")",
		Check: func(r *http.Request, c *Caller) bool {
			value, ok := requestValue(r, from, field)
			return ok && c.Tenant != "" && value == c.Tenant
		},
	}
}

// HasClaim passes when the caller has the claim name, of type T — what
// [Claim] would return with ok. The refusal names the claim, never its value.
func HasClaim[T ClaimType](name string) Spec {
	return Spec{
		ID: "hasClaim(" + name + ")",
		Check: func(_ *http.Request, c *Caller) bool {
			_, ok := claimOf[T](c, name)
			return ok
		},
	}
}

// HasClaims passes when the caller has the list claim name with at least one
// element of type T — what [Claims] would return, not empty.
func HasClaims[T ClaimType](name string) Spec {
	return Spec{
		ID: "hasClaims(" + name + ")",
		Check: func(_ *http.Request, c *Caller) bool {
			return len(claimsOf[T](c, name)) > 0
		},
	}
}

func ids(specs []Spec) string {
	names := make([]string, len(specs))
	for i, spec := range specs {
		names[i] = spec.ID
	}
	return strings.Join(names, ",")
}

// maxBody bounds what [Body] reads: a rule doesn't buffer an upload.
const maxBody = 1 << 20

// requestValue reads a string from the request; ok is false when the value is
// absent, not a string, or unreadable.
func requestValue(r *http.Request, from Source, field string) (string, bool) {
	switch from {
	case Param:
		value := r.PathValue(field)
		return value, value != ""
	case Query:
		values, ok := r.URL.Query()[field]
		if !ok || len(values) == 0 {
			return "", false
		}
		return values[0], true
	case Body:
		return bodyValue(r, field)
	}
	return "", false
}

func bodyValue(r *http.Request, path string) (string, bool) {
	if r.Body == nil {
		return "", false
	}
	read, _ := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	// Put back what was read in front of what wasn't: the handler reads the body whole.
	r.Body = readCloser{io.MultiReader(bytes.NewReader(read), r.Body), r.Body}
	if len(read) > maxBody {
		return "", false
	}
	var body any
	if json.Unmarshal(read, &body) != nil {
		return "", false
	}
	value, ok := resolvePath(body, path).(string)
	return value, ok
}

type readCloser struct {
	io.Reader
	io.Closer
}

// resolvePath reads a dotted path (`realm_access.roles`) in decoded JSON.
func resolvePath(value any, path string) any {
	if path == "" {
		return nil
	}
	for _, key := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[key]
	}
	return value
}
