package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// testTB is a minimal interface implemented by *testing.T and *testing.B.
// It allows sharing helpers between tests and benchmarks without duplication.
type testTB interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// fixedQuoteProvider is a lightweight stub for tests/benchmarks.
type fixedQuoteProvider struct{ q string }

func (f fixedQuoteProvider) Random() string { return f.q }

// startTestServerTB starts the TCP server using handleConn and returns its address.
// It works for both tests and benchmarks.
func startTestServerTB(tb testTB) (addr string, stop func()) {
	tb.Helper()

	// Deterministic secret for reproducible signatures.
	_ = os.Setenv("WOW_HMAC_SECRET", "test-secret")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	qp := fixedQuoteProvider{q: "wisdom\n"}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go handleConn(conn, qp)
		}
	}()

	stop = func() {
		close(done)
		_ = ln.Close()
	}

	tb.Cleanup(stop)
	return ln.Addr().String(), stop
}

// requestSignedChallengeTB performs a CHALLENGE request and returns signedChallenge.
func requestSignedChallengeTB(tb testTB, addr string) signedChallenge {
	tb.Helper()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintln(conn, "CHALLENGE"); err != nil {
		tb.Fatalf("send CHALLENGE: %v", err)
	}

	dec := json.NewDecoder(bufio.NewReader(conn))
	dec.DisallowUnknownFields()

	var sc signedChallenge
	if err := dec.Decode(&sc); err != nil {
		tb.Fatalf("decode signed challenge: %v", err)
	}
	if sc.Challenge == nil {
		tb.Fatalf("empty challenge")
	}
	if sc.Sig == "" {
		tb.Fatalf("empty signature")
	}
	if sc.ExpiresAt <= 0 {
		tb.Fatalf("invalid expires_at")
	}

	return sc
}
