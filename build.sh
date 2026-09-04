#!/bin/sh
# Builds and tests recheck through Docker, so no local Go toolchain is needed.
#
#   ./build.sh test      go test ./...
#   ./build.sh build     native binary for this machine -> dist/recheck[.exe]
#   ./build.sh release   linux/amd64, linux/arm64, darwin/arm64, windows/amd64 -> dist/
#   ./build.sh wasm      wasm/recheck.wasm + wasm_exec.js, copied into npm/wasm/, plus the
#                        spec/vectors/receipt-valid.json fixture the npm smoke test uses
#   ./build.sh all       test, build, wasm
#
# GO_IMAGE overrides the toolchain image (default golang:1.23-alpine).
set -eu
cd "$(dirname "$0")"

GO_IMAGE="${GO_IMAGE:-golang:1.23-alpine}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X github.com/20012001amiramir/recheck/cli.Version=$VERSION"

# git-bash on Windows rewrites /src into a Windows path unless told not to.
export MSYS_NO_PATHCONV=1

dock() {
  docker run --rm \
    -v "$PWD":/src \
    -v recheck-gocache:/root/.cache/go-build \
    -w /src \
    -e GOFLAGS=-mod=mod \
    "$@"
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
  dock -e GOOS="$1" -e GOARCH="$2" -e CGO_ENABLED=0 "$GO_IMAGE" \
    go build -trimpath -ldflags "$LDFLAGS" -o "dist/recheck-$1-$2$3" ./cmd/recheck
}

cmd_test() { dock "$GO_IMAGE" go test ./...; }

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
  dock -e GOOS=js -e GOARCH=wasm "$GO_IMAGE" \
    go build -trimpath -ldflags "$LDFLAGS" -o wasm/recheck.wasm ./cmd/wasm
  dock "$GO_IMAGE" sh -c 'cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" wasm/ 2>/dev/null || cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" wasm/'
  cp wasm/recheck.wasm wasm/wasm_exec.js npm/wasm/
  # The valid receipt from the vectors, as a plain file, for `exhibitb verify`.
  dock "$GO_IMAGE" go run ./cmd/recheck vectors-extract spec/vectors/receipt.json receipt > spec/vectors/receipt-valid.json
  ls -l wasm/recheck.wasm
}

case "${1:-all}" in
  test) cmd_test ;;
  build) cmd_build ;;
  release) cmd_release ;;
  wasm) cmd_wasm ;;
  all) cmd_test; cmd_build; cmd_wasm ;;
  *) echo "usage: $0 {test|build|release|wasm|all}" >&2; exit 64 ;;
esac
