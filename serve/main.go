package main

import (
	"encoding/pem"
	"io"
	"log"
	"net/http"

	"browser-keygen/ca"
	"browser-keygen/serve/web"
)

// maxCSRSize bounds the request body; a P-256 certificate request in PEM
// is well under a kilobyte.
const maxCSRSize = 8 << 10

// statusRecorder captures the status code, which the ResponseWriter
// does not otherwise expose.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d", r.RemoteAddr, r.URL.RequestURI(), rec.status)
	})
}

// onlyMethod answers every other method with 405. The mux cannot do it:
// the FileServer catch-all matches those requests too and would turn them
// into a 404.
func onlyMethod(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			http.Error(w, "only "+method+" is allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

func profile(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Write(web.Profile)
}

func caCertificate(authority *ca.CA) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.Cert.Raw}))
	}
}

func sign(authority *ca.CA) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csrPEM, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCSRSize))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		certPEM, err := authority.Sign(csrPEM)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(certPEM)
	}
}

func handler(authority *ca.CA) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/wireguard/profile.zip", onlyMethod(http.MethodGet, profile))
	mux.HandleFunc("/api/x509/ca.pem", onlyMethod(http.MethodGet, caCertificate(authority)))
	mux.HandleFunc("/api/x509/sign", onlyMethod(http.MethodPost, sign(authority)))
	mux.Handle("/", http.FileServerFS(web.Files))
	return mux
}

func main() {
	authority, err := ca.New()
	if err != nil {
		log.Fatalf("generate certificate authority: %v", err)
	}
	log.Println("listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", accessLog(handler(authority))))
}
