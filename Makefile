WASM      := serve/web/main.wasm
WASM_EXEC := serve/web/wasm_exec.js
PROFILE   := serve/web/profile.zip
SERVE     := serve/serve

.PHONY: all build test clean

all: build

build: $(PROFILE)
	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -trimpath -o $(WASM) .
	cp $(shell go env GOROOT)/lib/wasm/wasm_exec.js $(WASM_EXEC)
	go build -o $(SERVE) ./serve

# zip updates an existing archive in place and would keep files that
# wg0.conf no longer accounts for, so start from nothing.
$(PROFILE): wg0.conf
	rm -f $@
	zip -q -X -j $@ $<

# The root package is js/wasm only, so its tests need a JavaScript runtime.
# That runtime caps argv plus environment at 8 KB, which a nix devshell or a CI
# runner exceeds, so the wasm test gets a pruned environment.
test: $(PROFILE)
	go test ./ca ./profile ./serve
	@env -i PATH="$(PATH)" HOME="$(HOME)" GOOS=js GOARCH=wasm \
		go test -exec="$(shell go env GOROOT)/lib/wasm/go_js_wasm_exec" .

clean:
	rm -f $(WASM) $(WASM_EXEC) $(PROFILE) $(SERVE)
