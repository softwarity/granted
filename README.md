<p align="center">
  <a href="https://www.softwarity.io/">
    <img src="https://www.softwarity.io/img/softwarity.svg" alt="Softwarity" height="60">
  </a>
</p>

# granted

<p align="center">
  <a href="https://github.com/softwarity/granted/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license">
  </a>
  <a href="https://github.com/softwarity/granted/actions/workflows/unit-tests.yml">
    <img src="https://github.com/softwarity/granted/actions/workflows/unit-tests.yml/badge.svg" alt="Unit tests">
  </a>
</p>

**Decide, route by route, who may call your service.**

A gateway or an identity provider has authenticated the caller and passes the identity on — as HTTP headers, or as a signed JWT. granted reads it, checks what each route requires, and hands your code the caller: username, roles, tenant, and any other claim.

```ts
// NestJS
@Get('stations')
@GrantedTo(hasRole('FORECASTER'))
list(@GrantedClaim('territories', { type: 'string', array: true }) territories: string[]) {
  return this.stations.find({ where: { territory: In(territories) } });
}
```

Roles decide *which actions* a caller may take; claims scope *which data*. Each route's rule also reads in the service's OpenAPI document.

| Package | |
|---|---|
| [`@softwarity/nestjs-granted`](./packages/nestjs) | NestJS |
| [`io.softwarity:quarkus-granted`](./quarkus) | Quarkus |
| [`github.com/softwarity/granted/go/v5`](./go) | Go (`net/http`) |

Every package carries one version: they implement the same behaviour, so a service in one language and a service in another, on the same number, decide the same way.

📚 **Documentation:** [softwarity.github.io/granted](https://softwarity.github.io/granted/)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Changes go under `## NEXT RELEASE` in [RELEASE_NOTES.md](./RELEASE_NOTES.md).

## License

[Apache-2.0](./LICENSE)
