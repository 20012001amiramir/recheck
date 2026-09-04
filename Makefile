# Every target runs through build.sh, which uses Docker so no local Go is needed.
.PHONY: test build release wasm all clean

test:
	./build.sh test

build:
	./build.sh build

release:
	./build.sh release

wasm:
	./build.sh wasm

all:
	./build.sh all

clean:
	rm -rf dist wasm/recheck.wasm wasm/wasm_exec.js npm/wasm spec/vectors/receipt-valid.json
