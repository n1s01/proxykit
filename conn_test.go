package proxykit

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type partialWriter struct{ bytes.Buffer }

func (w *partialWriter) Write(data []byte) (int, error) {
	if len(data) > 2 {
		data = data[:2]
	}
	return w.Buffer.Write(data)
}

type stalledWriter struct{}

func (stalledWriter) Write([]byte) (int, error) { return 0, nil }

func TestWireWriterCompletesPartialFrames(t *testing.T) {
	writer := &partialWriter{}
	if err := writeAll(writer, []byte("wire-packet")); err != nil || writer.String() != "wire-packet" {
		t.Fatalf("short writes truncated a protocol frame: %v", err)
	}
	if err := writeAll(stalledWriter{}, []byte("packet")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero progress did not terminate: %v", err)
	}
}
