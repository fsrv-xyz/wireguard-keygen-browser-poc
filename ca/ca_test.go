package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func csrPEM(t *testing.T, cn string) []byte {
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSign(t *testing.T) {
	authority, err := New()
	if err != nil {
		t.Fatal(err)
	}

	certPEM, err := authority.Sign(csrPEM(t, "alice"))
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("got %q, want a CERTIFICATE block", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "alice" {
		t.Errorf("common name %q, want alice", cert.Subject.CommonName)
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

func TestSign_serialsDiffer(t *testing.T) {
	authority, err := New()
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.Sign(csrPEM(t, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := authority.Sign(csrPEM(t, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) == string(second) {
		t.Error("two certificates for the same common name are identical")
	}
}

func TestSign_errors(t *testing.T) {
	authority, err := New()
	if err != nil {
		t.Fatal(err)
	}

	tampered := csrPEM(t, "alice")
	block, _ := pem.Decode(tampered)
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	tampered = pem.EncodeToMemory(block)

	noCN := csrPEM(t, "")

	for _, tc := range []struct {
		name string
		csr  []byte
		want string
	}{
		{"not_pem", []byte("hello"), "no certificate request"},
		{"wrong_block_type", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), "no certificate request"},
		{"not_a_csr", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("x")}), "asn1"},
		{"bad_signature", tampered, "signature"},
		{"empty_common_name", noCN, "common name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := authority.Sign(tc.csr); err == nil {
				t.Fatal("signed, want an error")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestNew_selfSignedAuthority(t *testing.T) {
	authority, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if !authority.Cert.IsCA {
		t.Error("CA certificate is not marked as a CA")
	}
	if time.Now().After(authority.Cert.NotAfter) {
		t.Errorf("CA certificate already expired at %v", authority.Cert.NotAfter)
	}

	// A leaf that outlives its issuer would stop verifying before its own
	// expiry, so the authority has to outlast everything it signs.
	certPEM, err := authority.Sign(csrPEM(t, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if margin := authority.Cert.NotAfter.Sub(leaf.NotAfter); margin < 24*time.Hour {
		t.Errorf("CA outlasts the leaf by %v, want at least 24h", margin)
	}
}
