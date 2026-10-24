#!/usr/bin/env node
/**
 * Puts every package of the repository on the same version.
 *
 * The packages implement one behaviour - which headers carry the caller, how a
 * token is verified, how a spec decides - in each language. A NestJS service and
 * a Quarkus service on the same number must decide the same way, so there is one
 * version for the repository, and every package follows it.
 *
 *   node scripts/version-all.mjs 5.9.0
 *
 * The root manifest is not touched: softwarity/release-flow owns it - it is what
 * it bumps, and what it reads to know the version before.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version ?? '')) {
  console.error('usage: version-all.mjs <version>');
  process.exit(1);
}

for (const dir of ['packages/nestjs'].filter((path) => existsSync(join(path, 'package.json')))) {
  const path = join(dir, 'package.json');
  const manifest = JSON.parse(readFileSync(path, 'utf8'));
  manifest.version = version;
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`${manifest.name} → ${version}`);
}

// The Quarkus extension, a Maven reactor (runtime, deployment, and the test applications): the parent's version and the one each module names as
// its parent. Only those - the first <version> of the parent pom, and the one inside <parent> -
// so a dependency's version is never touched.
for (const pom of ['quarkus/pom.xml', 'quarkus/runtime/pom.xml', 'quarkus/deployment/pom.xml', 'quarkus/integration-tests/pom.xml', 'quarkus/integration-tests-jwt/pom.xml'].filter((path) => existsSync(path))) {
  const before = readFileSync(pom, 'utf8');
  const after =
    pom === 'quarkus/pom.xml'
      ? before.replace(/(<artifactId>quarkus-granted-parent<\/artifactId>\s*<version>)[^<]+(<\/version>)/, `$1${version}$2`)
      : before.replace(/(<parent>[\s\S]*?<version>)[^<]+(<\/version>[\s\S]*?<\/parent>)/, `$1${version}$2`);
  if (after === before && !before.includes(`<version>${version}</version>`)) {
    console.error(`${pom}: no version to set`);
    process.exit(1);
  }
  writeFileSync(pom, after);
  console.log(`${pom} → ${version}`);
}

// The Go module's path carries its major version from v2 on (`…/go/v5`), as Go
// requires: a major release changes it. Its imports are its own package only.
if (existsSync('go/go.mod')) {
  const major = Number(version.split('.')[0]);
  const before = readFileSync('go/go.mod', 'utf8');
  const after = before.replace(/^module github\.com\/softwarity\/granted\/go(\/v\d+)?$/m, `module github.com/softwarity/granted/go${major >= 2 ? `/v${major}` : ''}`);
  writeFileSync('go/go.mod', after);
  console.log(`go/go.mod → ${after.match(/^module .*$/m)[0]}`);
}
