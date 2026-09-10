package main

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"wireguard-keygen/serve/web"
)

func TestServedContent(t *testing.T) {
	srv := httptest.NewServer(http.FileServerFS(web.Files))
	defer srv.Close()

	get := func(path string) (int, []byte) {
		res, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, body
	}

	if code, body := get("/"); code != 200 || !bytes.Contains(body, []byte("WireGuard Keygen")) {
		t.Errorf("GET /: code %d, want index page", code)
	}
	if code, body := get("/main.wasm"); code != 200 || len(body) < 4 || !bytes.Equal(body[:4], []byte("\x00asm")) {
		t.Errorf("GET /main.wasm: code %d, want wasm magic", code)
	}
	if code, _ := get("/wasm_exec.js"); code != 200 {
		t.Errorf("GET /wasm_exec.js: code %d, want 200", code)
	}

	// The profile zip must serve as a parseable zip whose config still
	// carries the placeholder.
	code, body := get("/profile.zip")
	if code != 200 {
		t.Fatalf("GET /profile.zip: code %d, want 200", code)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil || len(zr.File) != 1 {
		t.Fatalf("profile.zip: files %d, err %v", len(zr.File), err)
	}
	conf, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	confContent, _ := io.ReadAll(conf)
	if !bytes.Contains(confContent, []byte("<PRIVATEKEY>")) {
		t.Errorf("wg0.conf: %q, want placeholder", confContent)
	}

	// Anything that is not one of the embedded files stays out,
	// including repository sources and path traversal.
	for _, path := range []string{"/go.mod", "/wg0.conf", "/../go.mod"} {
		if code, _ := get(path); code == 200 {
			t.Errorf("GET %s: served, want 4xx", path)
		}
	}
}
