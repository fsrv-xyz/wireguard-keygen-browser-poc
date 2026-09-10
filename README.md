# WireGuard Keygen (Go + WebAssembly)

Generates WireGuard X25519 keypairs entirely in the browser — no key ever leaves the machine.

## Profile

The embedded `profile.zip` ships with the config carrying a `<PRIVATEKEY>`
placeholder. The "Download profile with key" button fetches it, rewrites
every placeholder occurrence with the generated private key (client-side,
in the wasm module) and saves the result as `profile.zip`.

## Build

Builds the wasm module and `wasm_exec.js` into `serve/web/` and the server
with all runtime files embedded, as `serve/serve`. `make clean` removes the
generated files.

```sh
make
```

## Run

All runtime files are embedded in the server binary, so it runs from any
directory without external files.

```sh
./serve/serve
```

Then open http://localhost:8080.
