# Contributing

Thanks for considering a contribution to `@softwarity/nestjs-granted`.

## Local setup

```bash
git clone https://github.com/softwarity/nestjs-granted.git
cd nestjs-granted
npm ci
npm test
npm run build
```

## Documentation site

The doc site is an Angular app under `docs/`. To run it locally:

```bash
cd docs
npm ci
npm start
```

It is deployed to GitHub Pages automatically on push to `main` via the
`deploy-doc.yml` workflow.

## Code style

- TypeScript strict mode, 2-space indent, single quotes, trailing commas.
- Comments explain *why*, not *what*. Don't restate the code.
- `npm run lint` must pass with 0 errors.
- `npm test` must pass.

## Releasing

Releases are tag-driven via GitHub Actions.

1. Bump the version in `package.json`.
2. Commit: `git commit -am "chore: release vX.Y.Z"`
3. Tag: `git tag vX.Y.Z`
4. Push: `git push && git push --tags`

The `tag.yml` workflow lints, tests, builds, and runs `npm publish`.

### npm token

The repository must have an `NPM_TOKEN` secret set in **Settings → Secrets and
variables → Actions**. Create it on npmjs.com under **Access Tokens → Granular
Access Token**, scoped to `@softwarity/nestjs-granted` with publish permission.
