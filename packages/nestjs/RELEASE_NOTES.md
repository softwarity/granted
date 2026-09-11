# Release Notes

## NEXT RELEASE

---

## 5.0.0

### Changes

- **Relicensed under Apache-2.0** (previously MIT), for its explicit patent grant — easier to adopt for companies whose legal teams pre-approve Apache over MIT. `LICENSE` and the `package.json` `license` field are updated; versions up to 4.1.0 stay MIT.

- **NestJS 12 support.** The `@nestjs/common` / `@nestjs/core` / `@nestjs/platform-express` peer range is widened to `>=10.0.0 <13.0.0`. NestJS 12 ships as ESM only; the library stays CommonJS and loads it through Node's `require(esm)`, so with NestJS 12 the host app needs Node.js ≥ 20.19 or ≥ 22.12 (the same requirement NestJS 12 itself has for CommonJS apps). ESM host apps work too. No API change; NestJS 10 and 11 remain supported.

### Internal changes

- Dev dependencies moved to NestJS 12 (`@nestjs/common`, `@nestjs/core`, `@nestjs/platform-express`, `@nestjs/testing` `^12.0.1`) and Jest 30 (`jest`, `@types/jest` `^30`, `ts-jest` `^29.4`).
- Jest can only load the ESM-only NestJS packages through its `require(esm)` support, which needs `--experimental-vm-modules` and Node.js ≥ 24.9. `npm test`, `test:watch` and `test:cov` now run `node --experimental-vm-modules node_modules/jest/bin/jest.js`; running the test suite locally requires Node 24.9+.
- CI workflows that run Jest (unit tests, publish) now use Node 24.
- Releases now go through [`softwarity/release-flow`](https://github.com/softwarity/release-flow): the *Create Tag/Release* workflow takes a `patch` / `minor` / `major` choice, checks lint, tests and build before tagging, resolves this `## NEXT RELEASE` section into the version and publishes the GitHub Release from it. This file is new — earlier versions have no release notes.
- Doc site: icons migrated to Material Symbols (license badge now Apache-2.0).

---
