package granted

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestHeaderProvider(t *testing.T) {
	logger, logged := newLogger()
	g := New(Options{Logger: logger, Provider: HeaderProvider{Logger: logger}})

	t.Run("reads username, roles as a JSON array, and tenant", func(t *testing.T) {
		got := callerOf(t, g, request("GET", "/", map[string]string{"username": "alice", "roles": `["ADMIN","USER"]`, "tenant": "acme"}))
		want := identity{Username: "alice", Roles: []string{"ADMIN", "USER"}, Tenant: "acme"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("reads roles as a comma-separated list", func(t *testing.T) {
		got := callerOf(t, g, request("GET", "/", map[string]string{"username": "bob", "roles": " USER , AUDITOR,"}))
		if !reflect.DeepEqual(got.Roles, []string{"USER", "AUDITOR"}) {
			t.Fatalf("roles %v", got.Roles)
		}
	})

	t.Run("gives an anonymous caller without headers", func(t *testing.T) {
		got := callerOf(t, g, request("GET", "/", nil))
		want := identity{Username: Anonymous, Roles: []string{}, Tenant: ""}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("reads no roles from a roles header that doesn't parse, without logging it", func(t *testing.T) {
		logged.reset()
		got := callerOf(t, g, request("GET", "/", map[string]string{"username": "bob", "roles": `["ADMIN",`}))
		if len(got.Roles) != 0 {
			t.Fatalf("roles %v", got.Roles)
		}
		if !strings.Contains(logged.String(), "roles header is not a JSON array") || strings.Contains(logged.String(), "ADMIN") {
			t.Fatalf("log: %s", logged)
		}
	})

	t.Run("reads the header names it is given", func(t *testing.T) {
		custom := New(Options{Provider: HeaderProvider{UsernameHeader: "X-User", RolesHeader: "X-Roles", TenantHeader: "X-Tenant"}})
		got := callerOf(t, custom, request("GET", "/", map[string]string{"x-user": "carol", "x-roles": "ADMIN", "x-tenant": "globex", "username": "mallory"}))
		want := identity{Username: "carol", Roles: []string{"ADMIN"}, Tenant: "globex"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
}

func TestRequire(t *testing.T) {
	logger, logged := newLogger()
	g := New(Options{Logger: logger})
	admin := g.Require(HasRole("ADMIN"))(whoami)

	t.Run("lets through a caller that satisfies the spec", func(t *testing.T) {
		recorder := call(t, admin, request("GET", "/reports", map[string]string{"username": "alice", "roles": `["ADMIN"]`}))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status %d", recorder.Code)
		}
	})

	t.Run("refuses the others with a bare 403, and logs why", func(t *testing.T) {
		logged.reset()
		recorder := call(t, admin, request("GET", "/reports", map[string]string{"username": "bob", "roles": "USER", "tenant": "acme"}))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status %d", recorder.Code)
		}
		if body := recorder.Body.String(); body != `{"error":"Forbidden","message":"Forbidden resource","statusCode":403}` {
			t.Fatalf("body %s", body)
		}
		if !strings.Contains(logged.String(), "GET /reports denied: hasRole(ADMIN) not met by 'bob' (roles: USER; tenant: acme)") {
			t.Fatalf("log: %s", logged)
		}
		if !strings.Contains(logged.String(), "denied.spec=hasRole(ADMIN)") {
			t.Fatalf("log fields: %s", logged)
		}
	})

	t.Run("says none for a caller without roles", func(t *testing.T) {
		if got := (Denial{Spec: "isAuthenticated()", Username: Anonymous}).String(); got != "isAuthenticated() not met by 'anonymous' (roles: none)" {
			t.Fatal(got)
		}
	})

	t.Run("leaves a handler without specs open", func(t *testing.T) {
		recorder := call(t, g.Require()(whoami), request("GET", "/", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status %d", recorder.Code)
		}
	})

	t.Run("reads the caller itself without the middleware, for the handler too", func(t *testing.T) {
		got := callerOf(t, New(Options{}), request("GET", "/", map[string]string{"username": "alice"}))
		if got.Username != "alice" {
			t.Fatal(got)
		}
		recorder := call(t, New(Options{}).Require(IsAuthenticated())(whoami), request("GET", "/", map[string]string{"username": "alice"}))
		if !strings.Contains(recorder.Body.String(), `"username":"alice"`) {
			t.Fatal(recorder.Body.String())
		}
	})

	t.Run("requires every spec of nested Require", func(t *testing.T) {
		handler := g.Middleware(g.Require(IsAuthenticated())(g.Require(HasRole("ADMIN"))(whoami)))
		if code := call(t, handler, request("GET", "/", map[string]string{"username": "bob", "roles": "USER"})).Code; code != http.StatusForbidden {
			t.Fatalf("status %d", code)
		}
	})

	t.Run("lets everything through when disabled", func(t *testing.T) {
		disabled := New(Options{Disabled: true})
		if code := call(t, disabled.Require(IsFalse())(whoami), request("GET", "/", nil)).Code; code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
	})

	t.Run("lets a bypassed caller through every spec", func(t *testing.T) {
		trusted := New(Options{Provider: ProviderFunc(func(*http.Request) Principal {
			return Principal{Username: "system:serviceaccount:ns:svc", Bypassed: true}
		})})
		if code := call(t, trusted.Require(IsFalse())(whoami), request("GET", "/", nil)).Code; code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
	})

	t.Run("writes the refusal with OnDenied", func(t *testing.T) {
		var denial Denial
		custom := New(Options{Logger: logger, OnDenied: func(w http.ResponseWriter, _ *http.Request, d Denial) {
			denial = d
			w.WriteHeader(http.StatusNotFound)
		}})
		recorder := call(t, custom.Require(HasRole("ADMIN"))(whoami), request("GET", "/", map[string]string{"username": "bob"}))
		if recorder.Code != http.StatusNotFound || denial.Spec != "hasRole(ADMIN)" || denial.Username != "bob" {
			t.Fatalf("status %d, denial %+v", recorder.Code, denial)
		}
	})
}

func TestRoles(t *testing.T) {
	t.Run("expands the hierarchy transitively, cycles included", func(t *testing.T) {
		got := resolveRoles([]string{"ADMIN"}, map[string][]string{"ADMIN": {"MANAGER"}, "MANAGER": {"USER"}, "USER": {"ADMIN"}}, nil)
		if !reflect.DeepEqual(got, []string{"ADMIN", "MANAGER", "USER"}) {
			t.Fatal(got)
		}
	})

	t.Run("keeps only the known roles, after the expansion", func(t *testing.T) {
		got := resolveRoles([]string{"ADMIN", "billing:READ", "ADMIN"}, map[string][]string{"ADMIN": {"USER"}}, []string{"USER", "ADMIN"})
		if !reflect.DeepEqual(got, []string{"ADMIN", "USER"}) {
			t.Fatal(got)
		}
	})

	t.Run("are the ones the specs and the handler see", func(t *testing.T) {
		g := New(Options{RoleHierarchy: map[string][]string{"ADMIN": {"USER"}}, KnownRoles: []string{"ADMIN", "USER"}})
		handler := g.Require(HasRole("USER"))(whoami)
		recorder := call(t, handler, request("GET", "/", map[string]string{"username": "alice", "roles": `["ADMIN","other:ROLE"]`}))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"roles":["ADMIN","USER"]`) {
			t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
		}
	})
}

func TestSpecs(t *testing.T) {
	g := New(Options{})
	caller := func(headers map[string]string) *Caller {
		_, c := g.caller(request("GET", "/", headers))
		return c
	}
	admin := caller(map[string]string{"username": "alice", "roles": "ADMIN"})
	anonymous := caller(nil)

	t.Run("name themselves like the other implementations", func(t *testing.T) {
		spec := Or(HasRole("A"), And(IsAuthenticated(), Not(HasRole("B"))), IsTrue(), IsFalse(), IsUser(Param, "id"), IsTenant(Body, "customer.tenant"), HasClaim[string]("x"), HasClaims[int]("y"))
		want := "or(hasRole(A),and(isAuthenticated(),not(hasRole(B))),isTrue(),isFalse(),isUser(Param, id),isTenant(Body, customer.tenant),hasClaim(x),hasClaims(y))"
		if spec.ID != want {
			t.Fatal(spec.ID)
		}
	})

	t.Run("combine", func(t *testing.T) {
		r := request("GET", "/", nil)
		cases := []struct {
			spec Spec
			c    *Caller
			want bool
		}{
			{IsAuthenticated(), admin, true},
			{IsAuthenticated(), anonymous, false},
			{And(IsAuthenticated(), HasRole("ADMIN")), admin, true},
			{And(IsAuthenticated(), HasRole("USER")), admin, false},
			{Or(HasRole("USER"), HasRole("ADMIN")), admin, true},
			{Or(), admin, false},
			{And(), anonymous, true},
			{Not(HasRole("ADMIN")), admin, false},
		}
		for _, tc := range cases {
			if got := tc.spec.Check(r, tc.c); got != tc.want {
				t.Errorf("%s for %s: %v", tc.spec.ID, tc.c.Username, got)
			}
		}
	})

	t.Run("compare the caller with a path parameter, a query parameter or a body field", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.Handle("PATCH /users/{id}", g.Require(IsUser(Param, "id"))(whoami))
		mux.Handle("GET /orders", g.Require(IsUser(Query, "customer"))(whoami))
		mux.Handle("POST /orders", g.Require(IsUser(Body, "customer.id"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body) // the rule read the body: the handler still gets it whole
			_, _ = w.Write(body)
		})))
		alice := map[string]string{"username": "alice"}
		cases := []struct {
			r    *http.Request
			want int
		}{
			{request("PATCH", "/users/alice", alice), http.StatusOK},
			{request("PATCH", "/users/bob", alice), http.StatusForbidden},
			{request("GET", "/orders?customer=alice", alice), http.StatusOK},
			{request("GET", "/orders", alice), http.StatusForbidden},
			{httptest.NewRequest("POST", "/orders", strings.NewReader(`{"customer":{"id":"bob"}}`)), http.StatusForbidden},
		}
		for _, tc := range cases {
			tc.r.Header.Set("username", "alice")
			if code := call(t, mux, tc.r).Code; code != tc.want {
				t.Errorf("%s %s: %d", tc.r.Method, tc.r.URL, code)
			}
		}
		ok := httptest.NewRequest("POST", "/orders", strings.NewReader(`{"customer":{"id":"alice"}}`))
		ok.Header.Set("username", "alice")
		recorder := call(t, mux, ok)
		if recorder.Code != http.StatusOK || recorder.Body.String() != `{"customer":{"id":"alice"}}` {
			t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("refuse a caller without a tenant", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.Handle("POST /tenants/{tenant}/invoices", g.Require(IsTenant(Param, "tenant"))(whoami))
		cases := map[string]int{"acme": http.StatusOK, "globex": http.StatusForbidden, "": http.StatusForbidden}
		for tenant, want := range cases {
			headers := map[string]string{"username": "alice"}
			if tenant != "" {
				headers["tenant"] = tenant
			}
			if code := call(t, mux, request("POST", "/tenants/acme/invoices", headers)).Code; code != want {
				t.Errorf("tenant %q: %d", tenant, code)
			}
		}
	})
}
