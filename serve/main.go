package main

import (
	"log"
	"net/http"

	"wireguard-keygen/serve/web"
)

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

func main() {
	log.Println("listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", accessLog(http.FileServerFS(web.Files))))
}
