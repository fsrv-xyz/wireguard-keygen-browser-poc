package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall/js"

	"wireguard-keygen/profile"
)

// keyLen is the length of a WireGuard private key, in bytes.
const keyLen = 32

func generateKeyPair(js.Value, []js.Value) any {
	var seed [keyLen]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return errorResult(fmt.Errorf("read key seed: %w", err))
	}
	// crypto/ecdh clamps internally, so the public key is the same with or
	// without this; clamping keeps one byte pattern per key pair.
	seed[0] &= 248
	seed[31] &= 127
	seed[31] |= 64

	priv, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		return errorResult(err)
	}
	return map[string]any{
		"privateKey": base64.StdEncoding.EncodeToString(priv.Bytes()),
		"publicKey":  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}
}

// buildProfile re-injects a private key into a profile zip. The zip
// travels as base64 because the Go/JS bridge only carries strings,
// numbers, booleans and objects.
func buildProfile(_ js.Value, args []js.Value) any {
	zipB64, err := stringArg(args, 0, "zip")
	if err != nil {
		return errorResult(err)
	}
	key, err := stringArg(args, 1, "privateKey")
	if err != nil {
		return errorResult(err)
	}
	raw, err := base64.StdEncoding.DecodeString(zipB64)
	if err != nil {
		return errorResult(err)
	}
	out, err := profile.WithKey(raw, key)
	if err != nil {
		return errorResult(err)
	}
	return map[string]any{"zip": base64.StdEncoding.EncodeToString(out)}
}

// generateCSR creates an X.509 client key pair and a certificate
// request for it. Only the request is meant to leave the browser.
func generateCSR(_ js.Value, args []js.Value) any {
	commonName, err := stringArg(args, 0, "commonName")
	if err != nil {
		return errorResult(err)
	}
	commonName = strings.TrimSpace(commonName)
	if commonName == "" {
		return errorResult(errors.New("common name must not be empty"))
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errorResult(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return errorResult(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		return errorResult(err)
	}
	return map[string]any{
		"privateKey": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		"csr":        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	}
}

// buildBundle packs the client key, its certificate and the issuing CA
// certificate into a zip. The key is only ever assembled here, in the
// browser; the zip travels back as base64 for the same reason the
// profile zip does.
func buildBundle(_ js.Value, args []js.Value) any {
	names := []string{"privateKey", "certificate", "caCertificate"}
	files := []string{"key.pem", "cert.pem", "ca.pem"}

	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for i, name := range names {
		content, err := stringArg(args, i, name)
		if err != nil {
			return errorResult(err)
		}
		f, err := w.Create(files[i])
		if err != nil {
			return errorResult(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			return errorResult(err)
		}
	}
	if err := w.Close(); err != nil {
		return errorResult(err)
	}
	return map[string]any{"zip": base64.StdEncoding.EncodeToString(out.Bytes())}
}

// errorResult ends the error chain: the bridge carries the message to
// JavaScript, which shows it verbatim.
func errorResult(err error) map[string]any {
	return map[string]any{"error": err.Error()}
}

func stringArg(args []js.Value, i int, name string) (string, error) {
	if i >= len(args) {
		return "", fmt.Errorf("missing argument %s", name)
	}
	if got := args[i].Type(); got != js.TypeString {
		return "", fmt.Errorf("argument %s: want a string, got %s", name, got)
	}
	return args[i].String(), nil
}

func main() {
	js.Global().Set("wgGenerateKeyPair", js.FuncOf(generateKeyPair))
	js.Global().Set("wgBuildProfile", js.FuncOf(buildProfile))
	js.Global().Set("x509GenerateCSR", js.FuncOf(generateCSR))
	js.Global().Set("x509BuildBundle", js.FuncOf(buildBundle))
	select {}
}
