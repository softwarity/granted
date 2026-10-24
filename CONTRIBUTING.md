# Contributing

Thanks for considering a contribution to **granted**.

## Repository layout

| Path | What | Published as |
|---|---|---|
| `packages/nestjs/` | The NestJS library | [`@softwarity/nestjs-granted`](https://www.npmjs.com/package/@softwarity/nestjs-granted) on npm |
| `docs/` | The documentation site (Angular) | [softwarity.github.io/granted](https://softwarity.github.io/granted/) |
| `scripts/` | Release helpers: `version-all.mjs`, `publish.sh` | — |

Every package carries the same version: they implement one behaviour, and a NestJS and a Quarkus service on the same number must decide the same way.

## Local setup

```bash
git clone https://github.com/softwarity/granted.git
cd granted
npm ci
npm test
npm run build
```

`npm ci`, `npm test`, `npm run lint` and `npm run build` at the root run in every package of the npm workspace.

The test suites need **Node.js ≥ 24.9**: NestJS 12 ships as ESM only, and Jest loads it through its `require(esm)` support (the `test` scripts pass `--experimental-vm-modules` for you).

## Documentation site

The doc site is an Angular app under `docs/`, outside the npm workspace. To run it locally:

```bash
cd docs
npm ci
npm start
```

It is deployed to GitHub Pages by the `deploy-doc.yml` workflow, on a push to `main` that changes `docs/`, or by hand (**Actions → Deploy Doc to GitHub Pages → Run workflow**).

## Code style

- TypeScript strict mode, 2-space indent, single quotes, trailing commas.
- Comments explain *why*, not *what*. Don't restate the code.
- `npm run lint` must pass with 0 errors.
- `npm test` must pass.

## Releasing

Releases go through the [`softwarity/release-flow`](https://github.com/softwarity/release-flow) action. Never bump a version or write a version heading by hand.

1. Describe every change under `## NEXT RELEASE` in `RELEASE_NOTES.md` — one file for the whole repository.
2. **Actions → Create Tag/Release → Run workflow**, then pick `patch` / `minor` / `major`.
3. The workflow checks the npm token, puts every package on the new version (`scripts/version-all.mjs`), then lints, tests and builds.
4. release-flow bumps the root `package.json`, renames `## NEXT RELEASE` to the new version and commits and tags `vX.Y.Z` on the runner. It then runs `scripts/publish.sh`, which publishes every package. Only if that succeeds does it push the commit and the tag, publish the GitHub Release and reopen an empty `## NEXT RELEASE`.

### Secrets

The repository needs, in **Settings → Secrets and variables → Actions**:

- `NPM_TOKEN` — an npmjs.com **Granular Access Token** with publish permission on `@softwarity/nestjs-granted`.
- `PAT_TOKEN` — a token release-flow pushes the release commit and tag with, past the branch protection.
