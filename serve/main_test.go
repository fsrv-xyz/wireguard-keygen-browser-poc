package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"wireguard-keygen/ca"
)

func TestServedContent(t *testing.T) {
	authority, err := ca.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler(authority))
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

	// Anything that is not one of the shared shell files stays out:
	// repository sources, path traversal, and the profile zip, which
	// belongs to the WireGuard API branch alone.
	for _, path := range []string{"/go.mod", "/wg0.conf", "/../go.mod", "/profile.zip"} {
		if code, _ := get(path); code == 200 {
			t.Errorf("GET %s: served, want 4xx", path)
		}
	}
}

func TestProfile(t *testing.T) {
	authority, err := ca.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler(authority))
	defer srv.Close()

	res, err := srv.Client().Get(srv.URL + "/api/wireguard/profile.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("GET /api/wireguard/profile.zip: code %d", res.StatusCode)
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

	post, err := srv.Client().Post(srv.URL+"/api/wireguard/profile.zip", "application/zip", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != 405 {
		t.Errorf("POST /api/wireguard/profile.zip: code %d, want 405", post.StatusCode)
	}
}

func TestCACertificate(t *testing.T) {
	authority, err := ca.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler(authority))
	defer srv.Close()

	res, err := srv.Client().Get(srv.URL + "/api/x509/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("GET /api/x509/ca.pem: code %d", res.StatusCode)
	}

	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("got %q, want a CERTIFICATE block", body)
	}
	served, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !served.Equal(authority.Cert) {
		t.Errorf("served %q, want the running authority", served.Subject)
	}

	post, err := srv.Client().Post(srv.URL+"/api/x509/ca.pem", "application/x-pem-file", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != 405 {
		t.Errorf("POST /api/x509/ca.pem: code %d, want 405", post.StatusCode)
	}
}

func csrPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestSign(t *testing.T) {
	authority, err := ca.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler(authority))
	defer srv.Close()

	res, err := srv.Client().Post(srv.URL+"/api/x509/sign", "application/x-pem-file", strings.NewReader(csrPEM(t, "alice")))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("POST /api/x509/sign: code %d, body %q", res.StatusCode, body)
	}

	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatalf("POST /api/x509/sign returned %q, want a PEM certificate", body)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(authority.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("verify against the CA: %v", err)
	}
}

func TestSign_rejects(t *testing.T) {
	authority, err := ca.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler(authority))
	defer srv.Close()

	res, err := srv.Client().Post(srv.URL+"/api/x509/sign", "application/x-pem-file", strings.NewReader("not a csr"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Errorf("POST /api/x509/sign with garbage: code %d, want 400", res.StatusCode)
	}

	get, err := srv.Client().Get(srv.URL + "/api/x509/sign")
	if err != nil {
		t.Fatal(err)
	}
	get.Body.Close()
	if get.StatusCode != 405 {
		t.Errorf("GET /api/x509/sign: code %d, want 405", get.StatusCode)
	}
}
