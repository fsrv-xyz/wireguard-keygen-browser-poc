# Browser Keygen (Go + WebAssembly)

Generates private keys in the browser, in a Go wasm module. No private key
ever leaves the machine. Two independent branches share the page: WireGuard
keypairs and X.509 client certificates.

## WireGuard

The "Generate keypair" button derives an X25519 keypair in the wasm module.

`profile.zip` is built from `wg0.conf`, which carries a `<PRIVATEKEY>`
placeholder. The "Download profile with key" button fetches it from
`/api/wireguard/profile.zip`, rewrites every placeholder occurrence with the
generated private key (client-side, in the wasm module) and saves the result
as `profile.zip`. A zip without that placeholder is refused with a message
instead of producing a keyless profile.

## X.509

The browser generates an ECDSA P-256 key and a certificate request for the
common name that was entered, `POST`s the request to `/api/x509/sign` and
shows the returned certificate. "Download key, certificate and CA" adds the
authority certificate from `/api/x509/ca.pem` and packs all three as
`key.pem`, `cert.pem` and `ca.pem` into `certificate.zip`. The zip is built
in the wasm module, so the private key never leaves the machine.

The signing authority is generated at server start and held in memory only,
so every restart invalidates all certificates it ever issued.

## Routes

The two branches are separated by path; only the page shell is shared.

```
/, /main.wasm, /wasm_exec.js   shared shell
GET  /api/wireguard/profile.zip
GET  /api/x509/ca.pem
POST /api/x509/sign
```

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
