// Package granted decides, route by route, who may call an HTTP service.
//
// Something in front of the service — a gateway, an identity provider — has
// authenticated the caller and passes the identity on, as HTTP headers or as a
// signed JWT. A [Provider] reads it, [Granted.Require] checks what a route
// requires, and the handler reads the caller from its request's context:
// [Username], [Roles], [Tenant], and any other claim with [Claim] / [Claims].
//
// It is the Go implementation of softwarity/granted: the NestJS and Quarkus
// ones read the caller and decide the same way.
package granted

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// Anonymous is the username of a caller nothing identified.
const Anonymous = "anonymous"

// Principal is the caller as a [Provider] read it, before the role hierarchy
// and the known roles are applied.
type Principal struct {
	// Username, empty for a caller nothing identified (it then reads as [Anonymous]).
	Username string
	// Roles as the provider found them.
	Roles []string
	// Tenant, empty when the caller has none.
	Tenant string
	// Bypassed callers pass every [Granted.Require] without their specs being
	// evaluated — e.g. a trusted service account. Only a provider sets it, from
	// what it verified; never from a claim alone.
	Bypassed bool
	// Claim returns any other attribute of the caller, as found — a JWT claim
	// (dotted paths for nested claims), a gateway header. Nil when the provider
	// reads none. [Claim] and [Claims] convert what it returns.
	Claim func(name string) any
}

// Provider reads the caller from a request. It never fails: a caller it can't
// identify — no token, an invalid one — is anonymous, and it is up to the
// specs to refuse it.
type Provider interface {
	Resolve(r *http.Request) Principal
}

// ProviderFunc adapts a function to a [Provider].
type ProviderFunc func(r *http.Request) Principal

// Resolve calls f.
func (f ProviderFunc) Resolve(r *http.Request) Principal { return f(r) }

// Options configure [New]. The zero value reads the caller from the
// `username`, `roles` and `tenant` headers and enforces every spec.
type Options struct {
	// Provider reads the caller. Defaults to a [HeaderProvider] with its default header names.
	Provider Provider
	// RoleHierarchy maps a role to the roles it implies, expanded transitively:
	// {"ADMIN": {"MANAGER"}, "MANAGER": {"USER"}} makes an ADMIN a MANAGER and a USER.
	RoleHierarchy map[string][]string
	// KnownRoles, when set, drops every role outside it — after the hierarchy
	// is expanded — so a token carrying roles meant for other services doesn't
	// pollute this one's view.
	KnownRoles []string
	// Disabled lets every request through: the specs are not evaluated. The
	// caller is still read, for the handlers.
	Disabled bool
	// Logger receives the refusals and the claim warnings. Defaults to slog.Default().
	Logger *slog.Logger
	// OnDenied writes the refusal. Defaults to a bare 403 whose body tells the
	// caller nothing about the rules: {"statusCode":403,"message":"Forbidden resource","error":"Forbidden"}.
	// The refusal is logged before it is called, either way.
	OnDenied func(w http.ResponseWriter, r *http.Request, d Denial)
}

// Granted reads the caller of each request and enforces the specs of each route.
type Granted struct {
	opts     Options
	provider Provider
	logger   *slog.Logger
}

// New returns a Granted configured by opts.
func New(opts Options) *Granted {
	g := &Granted{opts: opts, provider: opts.Provider, logger: opts.Logger}
	if g.provider == nil {
		g.provider = HeaderProvider{Logger: opts.Logger}
	}
	if g.logger == nil {
		g.logger = slog.Default()
	}
	return g
}

// Caller is the caller of a request, as the specs see it: its roles are the
// ones after the hierarchy and the known roles.
type Caller struct {
	Username string
	Roles    []string
	Tenant   string
	Bypassed bool

	claim  func(name string) any
	logger *slog.Logger
	owner  *Granted
}

// Authenticated reports whether something identified the caller.
func (c *Caller) Authenticated() bool {
	return c.Username != "" && c.Username != Anonymous
}

// HasRole reports whether the caller holds role, after the hierarchy.
func (c *Caller) HasRole(role string) bool {
	for _, held := range c.Roles {
		if held == role {
			return true
		}
	}
	return false
}

type callerKey struct{}

// Middleware reads the caller of every request and puts it in the request's
// context, for the handlers to read with [Username], [Roles], [Tenant],
// [Claim]… It checks nothing: [Granted.Require] does, route by route.
func (g *Granted) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, _ = g.caller(r)
		next.ServeHTTP(w, r)
	})
}

// Require wraps a handler that only callers satisfying every spec reach; the
// others get a 403. Without [Granted.Middleware] in front, it reads the caller
// itself. A handler without Require is open.
func (g *Granted) Require(specs ...Spec) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r, c := g.caller(r)
			if g.opts.Disabled || len(specs) == 0 || c.Bypassed {
				next.ServeHTTP(w, r)
				return
			}
			for _, spec := range specs {
				if !spec.Check(r, c) {
					g.deny(w, r, Denial{Spec: spec.ID, Username: c.Username, Roles: c.Roles, Tenant: c.Tenant})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// caller returns the request's caller, reading it once: a request that went
// through this Granted's middleware already carries it.
func (g *Granted) caller(r *http.Request) (*http.Request, *Caller) {
	if c, ok := r.Context().Value(callerKey{}).(*Caller); ok && c.owner == g {
		return r, c
	}
	p := g.provider.Resolve(r)
	username := p.Username
	if username == "" {
		username = Anonymous
	}
	c := &Caller{
		Username: username,
		Roles:    resolveRoles(p.Roles, g.opts.RoleHierarchy, g.opts.KnownRoles),
		Tenant:   p.Tenant,
		Bypassed: p.Bypassed,
		claim:    p.Claim,
		logger:   g.logger,
		owner:    g,
	}
	return r.WithContext(context.WithValue(r.Context(), callerKey{}, c)), c
}

// Denial says why a request was refused: the first spec that failed, and the
// caller it failed for. Don't send it back to the caller — it tells an attacker
// what to forge.
type Denial struct {
	// Spec is the ID of the first spec that failed, e.g. `hasRole(ADMIN)`; an
	// `and(...)` / `or(...)` is reported whole.
	Spec     string
	Username string
	// Roles the spec was evaluated against: after the hierarchy and the known roles.
	Roles  []string
	Tenant string
}

// String spells the refusal: `hasRole(ADMIN) not met by 'jdoe' (roles: USER; tenant: acme)`.
func (d Denial) String() string {
	roles := "none"
	if len(d.Roles) > 0 {
		roles = strings.Join(d.Roles, ", ")
	}
	tenant := ""
	if d.Tenant != "" {
		tenant = "; tenant: " + d.Tenant
	}
	return d.Spec + " not met by '" + d.Username + "' (roles: " + roles + tenant + ")"
}

var forbiddenBody, _ = json.Marshal(map[string]any{"statusCode": http.StatusForbidden, "message": "Forbidden resource", "error": "Forbidden"})

func (g *Granted) deny(w http.ResponseWriter, r *http.Request, d Denial) {
	attrs := []any{
		slog.String("http.request.method", r.Method),
		slog.String("url.path", r.URL.Path),
		slog.String("denied.spec", d.Spec),
		slog.String("denied.username", d.Username),
		slog.String("denied.roles", strings.Join(d.Roles, ",")),
	}
	if d.Tenant != "" {
		attrs = append(attrs, slog.String("denied.tenant", d.Tenant))
	}
	g.logger.Warn(r.Method+" "+r.URL.Path+" denied: "+d.String(), attrs...)
	if g.opts.OnDenied != nil {
		g.opts.OnDenied(w, r, d)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(forbiddenBody)
}

// FromContext returns the caller [Granted.Middleware] or [Granted.Require] put
// in ctx, or nil.
func FromContext(ctx context.Context) *Caller {
	c, _ := ctx.Value(callerKey{}).(*Caller)
	return c
}

// Username returns the caller's username, [Anonymous] when nothing identified it.
func Username(ctx context.Context) string {
	if c := FromContext(ctx); c != nil {
		return c.Username
	}
	return Anonymous
}

// Roles returns the caller's roles after the hierarchy and the known roles —
// the ones the specs see. Empty, never nil, when it has none.
func Roles(ctx context.Context) []string {
	if c := FromContext(ctx); c != nil {
		return c.Roles
	}
	return []string{}
}

// Tenant returns the caller's tenant, empty when it has none. The specs don't
// use it — roles decide which actions are allowed, the tenant scopes which
// data they touch (a `WHERE tenant_id = ?`).
func Tenant(ctx context.Context) string {
	if c := FromContext(ctx); c != nil {
		return c.Tenant
	}
	return ""
}
