# Every target runs through build.sh, which uses Docker so no local Go is needed
# (GO_LOCAL=1 make test uses the go on PATH instead).
.PHONY: test build release wasm smoke all clean

test:
	./build.sh test

build:
	./build.sh build

release:
	./build.sh release

wasm:
	./build.sh wasm

smoke:
	./build.sh smoke

all:
	./build.sh all

clean:
	rm -rf dist wasm/recheck.wasm wasm/wasm_exec.js npm/wasm npm/LICENSE spec/vectors/receipt-valid.json
