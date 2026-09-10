package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"syscall/js"

	"wireguard-keygen/profile"
)

func generateKeyPair(js.Value, []js.Value) any {
	var seed [32]byte
	rand.Read(seed[:])
	seed[0] &= 248
	seed[31] &= 127
	seed[31] |= 64

	priv, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		return map[string]any{"error": err.Error()}
	}

	return map[string]any{
		"privateKey": base64.StdEncoding.EncodeToString(priv.Bytes()),
		"publicKey":  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}
}

// buildProfile re-injects a private key into a profile zip. The zip
// travels as base64 because the Go/JS bridge in Go >= 1.27 only
// carries strings, numbers and objects.
func buildProfile(_ js.Value, args []js.Value) any {
	raw, err := base64.StdEncoding.DecodeString(args[0].String())
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	out, err := profile.WithKey(raw, args[1].String())
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"zip": base64.StdEncoding.EncodeToString(out)}
}

func main() {
	js.Global().Set("wgGenerateKeyPair", js.FuncOf(generateKeyPair))
	js.Global().Set("wgBuildProfile", js.FuncOf(buildProfile))
	select {}
}
