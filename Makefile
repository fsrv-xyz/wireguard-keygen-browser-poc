WASM      := serve/web/main.wasm
WASM_EXEC := serve/web/wasm_exec.js
SERVE     := serve/serve

.PHONY: all build clean

all: build

build:
	GOOS=js GOARCH=wasm go build -o $(WASM) .
	cp $(shell go env GOROOT)/lib/wasm/wasm_exec.js $(WASM_EXEC)
	go build -o $(SERVE) ./serve

clean:
	rm -f $(WASM) $(WASM_EXEC) $(SERVE)
