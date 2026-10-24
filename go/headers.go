package granted

import (
	"log/slog"
	"net/http"
)

// HeaderProvider reads the caller from the HTTP headers a gateway forwards
// once it has authenticated the caller. Nothing is verified here: the service
// must not be reachable except through that gateway, which must strip these
// headers from inbound requests.
//
// The zero value reads `username`, `roles` and `tenant`. The roles header is a
// JSON array (`["ADMIN","USER"]`) when it starts with `[`, a comma-separated
// list (`ADMIN, USER`) otherwise. A claim is the header of the same name.
type HeaderProvider struct {
	// UsernameHeader carries the username. Defaults to `username`.
	UsernameHeader string
	// RolesHeader carries the roles. Defaults to `roles`.
	RolesHeader string
	// TenantHeader carries the tenant. Defaults to `tenant`.
	TenantHeader string
	// Logger receives a warning for a roles header that doesn't parse. Defaults to slog.Default().
	Logger *slog.Logger
}

// Resolve reads the caller from r's headers.
func (h HeaderProvider) Resolve(r *http.Request) Principal {
	return Principal{
		Username: r.Header.Get(or(h.UsernameHeader, "username")),
		Roles:    h.roles(r.Header.Get(or(h.RolesHeader, "roles"))),
		Tenant:   r.Header.Get(or(h.TenantHeader, "tenant")),
		Claim: func(name string) any {
			if value := r.Header.Get(name); value != "" {
				return value
			}
			return nil
		},
	}
}

func (h HeaderProvider) roles(raw string) []string {
	if raw == "" {
		return nil
	}
	if _, ok := parseList(raw); !ok {
		// Never log the value: it comes from the request.
		logger := h.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("roles header is not a JSON array: no roles read")
		return nil
	}
	return stringsOf(raw)
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
