package server

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
)

// ProgressTrackingWriter wraps a `WriterAt` to track progress.
type ProgressTrackingWriter struct {
	underlying io.WriterAt
	totalBytes int64
}

func (ptw *ProgressTrackingWriter) WriteAt(p []byte, offset int64) (int, error) {
	n, err := ptw.underlying.WriteAt(p, offset)
	atomic.AddInt64(&ptw.totalBytes, int64(n))
	if os.Getenv("VERBOSE") == "true" {
		offsetGB := bytesToGigabytes(offset)
		fmt.Printf("Downloaded %.6f GB\n", offsetGB)
	}
	return n, err
}

func bytesToGigabytes(bytes int64) float64 {
	const bytesPerGigabyte = 1024 * 1024 * 1024
	return float64(bytes) / float64(bytesPerGigabyte)
}

// Creates a new `ProgressTrackingWriter` given an underlying `WriterAt`.
func NewProgressTrackingWriter(writer io.WriterAt) *ProgressTrackingWriter {
	return &ProgressTrackingWriter{
		underlying: writer,
		totalBytes: 0,
	}
}
