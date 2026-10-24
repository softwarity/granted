import { Component } from '@angular/core';
import { CodeComponent } from '../code/code.component';

@Component({
  selector: 'app-go',
  imports: [CodeComponent],
  template: `
    <h2>Go</h2>
    <div class="callout">Published with the next release of granted, alongside the NestJS package.</div>
    <p>
      <strong>github.com/softwarity/granted/go/v5</strong> reads the caller of a Go service the way
      nestjs-granted does — from the gateway's headers or from a verified JWT — and checks each route with the
      same specs. Plain <code>net/http</code>: a middleware is a <code>func(http.Handler) http.Handler</code>, so
      it fits the standard mux, chi, and anything that takes one.
    </p>
    <app-code lang="bash">go get github.com/softwarity/granted/go/v5</app-code>
    <p>
      No registry: a version is a git tag, <code>go/vX.Y.Z</code>, posted with the npm and Maven packages'
      <code>vX.Y.Z</code>. The path ends with the major version, as Go requires from v2 on.
    </p>

    <h3>Protect a route</h3>
    <app-code lang="go">g := granted.New(granted.Options&#123;&#125;) // the caller from the username, roles and tenant headers

mux := http.NewServeMux()
mux.Handle("GET /reports", g.Require(granted.HasRole("ADMIN"))(reports))
mux.Handle("PATCH /users/&#123;id&#125;", g.Require(granted.Or(granted.HasRole("ADMIN"), granted.IsUser(granted.Param, "id")))(update))

http.ListenAndServe(":8080", g.Middleware(mux))</app-code>
    <p>
      <code>HasRole</code>, <code>IsAuthenticated</code>, <code>IsUser</code>, <code>IsTenant</code>,
      <code>HasClaim</code> / <code>HasClaims</code>, combined with <code>And</code>, <code>Or</code>,
      <code>Not</code>. A refused caller gets a bare <code>403</code>; the reason goes to <code>log/slog</code>:
      <code>hasRole(ADMIN) not met by 'bob' (roles: USER; tenant: acme)</code>.
    </p>

    <h3>Read the caller</h3>
    <app-code lang="go">func list(w http.ResponseWriter, r *http.Request) &#123;
	ctx := r.Context()
	user := granted.Username(ctx)                          // "anonymous" when nothing identified the caller
	roles := granted.Roles(ctx)                            // after the hierarchy and the known roles
	territories := granted.Claims[string](ctx, "territories") // any other claim, typed
	…
&#125;</app-code>

    <h3>A JWT</h3>
    <app-code lang="go">provider, err := granted.NewJWTProvider(granted.JWTConfig&#123;
	Claims:  granted.Keycloak,
	JWKSURI: "https://sso.example.com/realms/acme/protocol/openid-connect/certs",
&#125;)
g := granted.New(granted.Options&#123;Provider: provider&#125;)</app-code>
    <p>
      The same options as nestjs-granted, under Go names: a PEM key or a JWK Set, several OpenID Providers by
      their discovery document (<code>DiscoveryURIs</code>, with a bearer token file and a <code>sub</code>
      bypass for the services of your cluster), issuer and audience, the cache, cooldown and timeout of the
      fetches. Each JWK Set key verifies with its own algorithm, never the one the token announces.
    </p>
  `,
})
export class GoComponent {}
