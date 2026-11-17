#!/usr/bin/env bash
#
# Run the Go tests in Docker.
#
# There is no go.mod in this repo and no CI: api/Dockerfile runs `go mod init`
# at image build time and copies only main.go, so the module is assembled on the
# fly and the test file is never part of the image. That keeps the deployed
# artefact exactly as it was, but it also means there is no obvious way to run a
# test -- hence this script. It needs Docker and nothing else; no Go toolchain
# on the host.
#
#   ./run-tests.sh            # run them
#   ./run-tests.sh -v         # ... with per-test output
#
# CGO is required: main.go pulls in mattn/go-sqlite3, so the image needs a C
# compiler and the SQLite headers. A run without them fails to BUILD, and a
# build failure prints "FAIL" too -- which is indistinguishable from a failing
# assertion if you only look for that word. Caught exactly that way on
# 17 Nov 2026 while checking that these tests could fail at all.
set -euo pipefail

cd "$(dirname "$0")"

IMAGE=drumscore-version-api-test
# A named volume, not a directory in the repo: Go marks everything in the module
# cache read-only and the container runs as root, so a bind mount leaves a
# root-owned, undeletable tree in the working copy.
CACHE=drumscore-version-api-gomod

docker build -q -t "$IMAGE" - >/dev/null <<'DOCKERFILE'
FROM golang:1.21-alpine
RUN apk add --no-cache gcc musl-dev sqlite-dev
DOCKERFILE

docker volume create "$CACHE" >/dev/null

docker run --rm \
	-v "$PWD/api:/src" \
	-v "$CACHE:/go/pkg/mod" \
	-w /src \
	"$IMAGE" sh -c '
		set -e
		# Assembled in a scratch copy so the working tree gains no go.mod/go.sum,
		# which would then be copied into a release image build.
		mkdir -p /build && cp -r /src/. /build/
		cd /build
		[ -f go.mod ] || {
			go mod init version-api >/dev/null
			go get github.com/mattn/go-sqlite3 >/dev/null 2>&1
			go mod tidy >/dev/null 2>&1
		}
		CGO_ENABLED=1 go vet .
		CGO_ENABLED=1 go test '"${1:-}"' .
	'
