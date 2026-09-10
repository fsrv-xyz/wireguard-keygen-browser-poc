WASM      := serve/web/main.wasm
WASM_EXEC := serve/web/wasm_exec.js
SERVE     := serve/serve

.PHONY: all build test clean

all: build

build:
	GOOS=js GOARCH=wasm go build -o $(WASM) .
	cp $(shell go env GOROOT)/lib/wasm/wasm_exec.js $(WASM_EXEC)
	go build -o $(SERVE) ./serve

# The root package is js/wasm only, so its tests need a JavaScript runtime.
test:
	go test ./profile ./serve
	GOOS=js GOARCH=wasm go test -exec="$(shell go env GOROOT)/lib/wasm/go_js_wasm_exec" .

clean:
	rm -f $(WASM) $(WASM_EXEC) $(SERVE)
