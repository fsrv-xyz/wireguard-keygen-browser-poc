// Package web holds the files the web interface needs at runtime.
package web

import "embed"

// The embedded build artifacts must be in place before this package
// compiles, so run the build steps from the README first.
//
//go:embed index.html main.wasm wasm_exec.js profile.zip
var Files embed.FS
