//go:build js && wasm

package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"syscall/js"
	"testing"

	"wireguard-keygen/profile"
)

func zipB64(t *testing.T, name, content string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// resultError returns the message of an error result, or "" when the
// callback reported success.
func resultError(t *testing.T, got any) string {
	t.Helper()
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("result %#v is not an object", got)
	}
	msg, _ := m["error"].(string)
	return msg
}

func newKey(t *testing.T) string {
	t.Helper()
	m, ok := generateKeyPair(js.Undefined(), nil).(map[string]any)
	if !ok {
		t.Fatal("keygen did not return an object")
	}
	key, ok := m["privateKey"].(string)
	if !ok {
		t.Fatalf("privateKey missing from %#v", m)
	}
	return key
}

func TestGenerateKeyPair(t *testing.T) {
	m, ok := generateKeyPair(js.Undefined(), nil).(map[string]any)
	if !ok {
		t.Fatal("keygen did not return an object")
	}
	if msg, _ := m["error"].(string); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}

	for _, tc := range []struct{ name, value string }{
		{"privateKey", m["privateKey"].(string)},
		{"publicKey", m["publicKey"].(string)},
	} {
		raw, err := base64.StdEncoding.DecodeString(tc.value)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(raw) != keyLen {
			t.Errorf("%s: %d bytes, want %d", tc.name, len(raw), keyLen)
		}
	}
	if m["privateKey"] == m["publicKey"] {
		t.Error("private and public key are identical")
	}

	seed, err := base64.StdEncoding.DecodeString(m["privateKey"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if seed[0]&0x07 != 0 || seed[31]&0x80 != 0 || seed[31]&0x40 == 0 {
		t.Errorf("private key %x was not clamped", seed)
	}
}

func TestBuildProfile_argumentErrors(t *testing.T) {
	key := newKey(t)

	for _, tc := range []struct {
		name string
		args []js.Value
		want string
	}{
		{"no_args", nil, "missing argument zip"},
		{"zip_only", []js.Value{js.ValueOf(zipB64(t, "wg0.conf", profile.Placeholder))}, "missing argument privateKey"},
		{"zip_not_a_string", []js.Value{js.ValueOf(7), js.ValueOf(key)}, "argument zip: want a string, got number"},
		{"key_not_a_string", []js.Value{js.ValueOf(zipB64(t, "wg0.conf", profile.Placeholder)), js.ValueOf(true)}, "argument privateKey: want a string, got boolean"},
		{"zip_not_base64", []js.Value{js.ValueOf("!! not base64"), js.ValueOf(key)}, "illegal base64 data"},
		{"zip_not_a_zip", []js.Value{js.ValueOf(base64.StdEncoding.EncodeToString([]byte("not a zip"))), js.ValueOf(key)}, "not a valid zip file"},
		{"zip_without_marker", []js.Value{js.ValueOf(zipB64(t, "wg0.conf", "PrivateKey = none\n")), js.ValueOf(key)}, "profile zip contains no " + profile.Placeholder},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := resultError(t, buildProfile(js.Undefined(), tc.args))
			if !strings.Contains(msg, tc.want) {
				t.Errorf("got %q, want it to mention %q", msg, tc.want)
			}
		})
	}
}

func TestBuildProfile(t *testing.T) {
	key := newKey(t)
	in := zipB64(t, "wg0.conf", "PrivateKey = "+profile.Placeholder+"\n")

	got, ok := buildProfile(js.Undefined(), []js.Value{js.ValueOf(in), js.ValueOf(key)}).(map[string]any)
	if !ok {
		t.Fatal("buildProfile did not return an object")
	}
	if msg, _ := got["error"].(string); msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}

	raw, err := base64.StdEncoding.DecodeString(got["zip"].(string))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if zr.File[0].Name != "wg0.conf" {
		t.Fatalf("archived %q, want wg0.conf", zr.File[0].Name)
	}
	src, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()

	content, err := io.ReadAll(src)
	if err != nil {
		t.Fatal(err)
	}
	if want := "PrivateKey = " + key + "\n"; string(content) != want {
		t.Errorf("got %q, want %q", content, want)
	}
}
