#!/bin/sh
# Builds and tests recheck. Every Go command runs inside a toolchain container by default, so no
# local Go is needed; with GO_LOCAL=1 (what CI does) the same commands run with the go on PATH.
#
#   ./build.sh test      go vet + go test ./...
#   ./build.sh build     native binary for this machine -> dist/recheck[.exe]
#   ./build.sh release   linux/amd64, linux/arm64, darwin/arm64, windows/amd64 -> dist/
#   ./build.sh wasm      wasm/recheck.wasm + wasm_exec.js, copied into npm/wasm/, plus the
#                        spec/vectors/receipt-valid.json fixture the smoke test uses
#   ./build.sh smoke     the native binary and the npm wrapper against the vectors (needs node)
#   ./build.sh all       test, build, wasm, smoke
#
# GO_IMAGE overrides the toolchain image (default golang:1.23-alpine). VERSION overrides the
# version compiled in (default: the tag on HEAD, else npm/package.json's version plus the short
# commit id).
set -eu
cd "$(dirname "$0")"

GO_IMAGE="${GO_IMAGE:-golang:1.23-alpine}"
pkg_version() { sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' npm/package.json | head -n 1; }
VERSION="${VERSION:-$(git describe --tags --exact-match 2>/dev/null || echo "$(pkg_version)+$(git rev-parse --short HEAD 2>/dev/null || echo dev)")}"
LDFLAGS="-s -w -X github.com/20012001amiramir/recheck/internal/build.Version=$VERSION"

# git-bash on Windows rewrites /src into a Windows path unless told not to.
export MSYS_NO_PATHCONV=1

# gorun [NAME=value ...] -- command args...: runs the command with those variables set, inside
# the toolchain container or (GO_LOCAL=1) directly.
gorun() {
  vars=""
  while [ "$1" != "--" ]; do vars="$vars $1"; shift; done
  shift
  if [ "${GO_LOCAL:-}" = 1 ]; then
    # shellcheck disable=SC2086
    env $vars "$@"
  else
    flags=""
    for kv in $vars; do flags="$flags -e $kv"; done
    # shellcheck disable=SC2086
    docker run --rm -v "$PWD":/src -v recheck-gocache:/root/.cache/go-build -w /src $flags "$GO_IMAGE" "$@"
  fi
}

host_target() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*|Windows*) echo "windows amd64 .exe" ;;
    Darwin) if [ "$(uname -m)" = "arm64" ]; then echo "darwin arm64"; else echo "darwin amd64"; fi ;;
    *) if [ "$(uname -m)" = "aarch64" ]; then echo "linux arm64"; else echo "linux amd64"; fi ;;
  esac
}

build_one() { # os arch suffix
  mkdir -p dist
  echo "building $1/$2"
  gorun GOOS="$1" GOARCH="$2" CGO_ENABLED=0 -- go build -trimpath -ldflags "$LDFLAGS" -o "dist/recheck-$1-$2$3" ./cmd/recheck
}

cmd_test() {
  gorun -- go vet ./...
  gorun GOOS=js GOARCH=wasm -- go vet ./cmd/wasm
  gorun GOOS=js GOARCH=wasm -- go vet -tags nocli ./cmd/wasm
  gorun -- go test ./...
}

cmd_build() {
  set -- $(host_target)
  build_one "$1" "$2" "${3:-}"
  cp "dist/recheck-$1-$2${3:-}" "dist/recheck${3:-}"
  echo "dist/recheck${3:-}"
}

cmd_release() {
  build_one linux amd64 ""
  build_one linux arm64 ""
  build_one darwin arm64 ""
  build_one windows amd64 .exe
  ls -l dist
}

cmd_wasm() {
  mkdir -p wasm npm/wasm
  echo "building wasm (standard Go, GOOS=js GOARCH=wasm)"
  # The page's module has no command line in it; the npm package's does.
  gorun GOOS=js GOARCH=wasm -- go build -trimpath -tags nocli -ldflags "$LDFLAGS" -o wasm/recheck.wasm ./cmd/wasm
  gorun GOOS=js GOARCH=wasm -- go build -trimpath -ldflags "$LDFLAGS" -o npm/wasm/recheck.wasm ./cmd/wasm
  # The runtime shim moved from misc/wasm to lib/wasm in Go 1.24.
  gorun -- sh -c 'cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" wasm/ 2>/dev/null || cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" wasm/'
  cp wasm/wasm_exec.js npm/wasm/
  cp LICENSE npm/LICENSE
  # The valid receipt from the vectors as a plain file, for the smoke test and for readers.
  gorun -- go run ./cmd/recheck vectors-extract spec/vectors/receipt.json receipt > spec/vectors/receipt-valid.json
  ls -l wasm/recheck.wasm npm/wasm/recheck.wasm
}

# expect_exit N command...: runs the command and insists on exit status N.
expect_exit() {
  want="$1"
  shift
  got=0
  "$@" || got=$?
  if [ "$got" -ne "$want" ]; then
    echo "smoke: '$*' exited $got, expected $want" >&2
    exit 1
  fi
}

cmd_smoke() {
  set -- $(host_target)
  bin="dist/recheck${3:-}"
  [ -x "$bin" ] || { echo "smoke: $bin is missing, run ./build.sh build first" >&2; exit 1; }
  [ -f spec/vectors/receipt-valid.json ] || { echo "smoke: spec/vectors/receipt-valid.json is missing, run ./build.sh wasm first" >&2; exit 1; }
  sed 's/"seq": 1,/"seq": 2,/' spec/vectors/receipt-valid.json > dist/receipt-tampered.json
  echo "smoke: the vector receipt with the fixture key passed in -> 0"
  expect_exit 0 "$bin" verify spec/vectors/receipt-valid.json --keys spec/vectors/test-key.json
  echo "smoke: the same receipt against the compiled-in keys only -> 2 (fixture key not pinned)"
  expect_exit 2 "$bin" verify spec/vectors/receipt-valid.json
  echo "smoke: a tampered copy -> 1"
  expect_exit 1 "$bin" verify dist/receipt-tampered.json --keys spec/vectors/test-key.json
  echo "smoke: --help -> 0"
  expect_exit 0 "$bin" --help
  if command -v node >/dev/null 2>&1; then
    echo "smoke: the npm wrapper -> 0, 2, 1"
    expect_exit 0 node npm/bin/exhibitb.js verify spec/vectors/receipt-valid.json --keys spec/vectors/test-key.json
    expect_exit 2 node npm/bin/exhibitb.js verify spec/vectors/receipt-valid.json
    expect_exit 1 node npm/bin/exhibitb.js verify dist/receipt-tampered.json --keys spec/vectors/test-key.json
    echo "smoke: the browser API of the same module -> 0"
    expect_exit 0 node wasm/check.js
  else
    echo "smoke: node not found, the npm wrapper was not exercised" >&2
  fi
  echo "smoke: ok"
}

case "${1:-all}" in
  test) cmd_test ;;
  build) cmd_build ;;
  release) cmd_release ;;
  wasm) cmd_wasm ;;
  smoke) cmd_smoke ;;
  all) cmd_test; cmd_build; cmd_wasm; cmd_smoke ;;
  *) echo "usage: $0 {test|build|release|wasm|smoke|all}" >&2; exit 64 ;;
esac
