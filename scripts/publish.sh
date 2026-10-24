#!/usr/bin/env bash
# Publishes one release everywhere: run by softwarity/release-flow (its `publish`
# input) once the release commit and tag exist on the runner, before anything is
# pushed. A failure here pushes nothing - no tag, no GitHub Release, no commit.
#
# Maven Central first, once quarkus/ exists: it is the registry that validates what
# it is given (signatures, javadoc, pom metadata) and can refuse. npm takes whatever
# it is handed, and no registry gives a version back.
set -euo pipefail

echo "Publishing ${RELEASE_VERSION} (${RELEASE_TAG})"

if [ -f quarkus/pom.xml ]; then
  (cd quarkus && ./mvnw -B -Prelease -DskipTests deploy)
fi

npm publish --workspace @softwarity/nestjs-granted
