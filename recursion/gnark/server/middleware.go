package server

import (
	"fmt"
	"net/http"
	"time"
)

// Custom response writer to capture the status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware logs details about the HTTP request and response.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lrw := &loggingResponseWriter{w, http.StatusOK}

		fmt.Printf("Received request: %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)

		startTime := time.Now()
		next.ServeHTTP(lrw, r)

		fmt.Printf("Response status: %d, time taken: %v", lrw.statusCode, time.Since(startTime))
	})
}
