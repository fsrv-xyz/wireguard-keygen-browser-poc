// Package web holds the files the web interface needs at runtime.
package web

import "embed"

// The embedded build artifacts must be in place before this package
// compiles, so run the build steps from the README first.

// Files is the shared shell, served from the root path.
//
//go:embed index.html main.wasm wasm_exec.js
var Files embed.FS

// Profile is served under the WireGuard API branch, so it stays out of
// Files and off the root path.
//
//go:embed profile.zip
var Profile []byte
