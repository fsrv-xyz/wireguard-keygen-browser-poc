# WireGuard Keygen (Go + WebAssembly)

Generates WireGuard X25519 keypairs entirely in the browser — no key ever leaves the machine.

## Profile

`profile.zip` is built from `wg0.conf`, which carries a `<PRIVATEKEY>`
placeholder. The "Download profile with key" button fetches it, rewrites
every placeholder occurrence with the generated private key (client-side,
in the wasm module) and saves the result as `profile.zip`. A zip without
that placeholder is refused with a message instead of producing a keyless
profile.

## X.509 certificates

The browser generates an ECDSA P-256 key and a certificate request for the
common name that was entered, `POST`s the request to `/sign` and shows the
returned certificate. The private key never leaves the machine.

The signing authority is generated at server start and held in memory only,
so every restart invalidates all certificates it ever issued.

## Development

`flake.nix` provides a dev shell with Go, node, make and zip. With direnv it
loads on entering the directory, after a one-time `direnv allow`; without it,
use `nix develop`.

## Build

Packs `wg0.conf` into `serve/web/profile.zip`, builds the wasm module and
`wasm_exec.js` into `serve/web/` and the server with all runtime files
embedded, as `serve/serve`. `make clean` removes the
generated files.

```sh
make
```

## Test

`go test ./...` cannot build the root package (it is `js/wasm` only), so use:

```sh
make test
```

That runs the server and profile tests natively and the wasm module tests
under node.

## Run

All runtime files are embedded in the server binary, so it runs from any
directory without external files.

```sh
./serve/serve
```

Then open http://localhost:8080.
