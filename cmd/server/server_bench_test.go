package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func BenchmarkServer_CHALLENGE(b *testing.B) {
	addr, _ := startTestServerTB(b)

	// Warm-up one request so failures are obvious early.
	_ = requestSignedChallengeTB(b, addr)

	var okCount int64

	b.ResetTimer()
	start := time.Now()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

			if _, err := fmt.Fprintln(conn, "CHALLENGE"); err != nil {
				_ = conn.Close()
				continue
			}

			dec := json.NewDecoder(bufio.NewReader(conn))
			dec.DisallowUnknownFields()

			var sc signedChallenge
			if err := dec.Decode(&sc); err == nil && sc.Challenge != nil {
				atomic.AddInt64(&okCount, 1)
			}

			_ = conn.Close()
		}
	})

	elapsed := time.Since(start)
	if elapsed > 0 {
		b.ReportMetric(float64(okCount)/elapsed.Seconds(), "req/s")
	}
}

func BenchmarkServer_QUOTE(b *testing.B) {
	addr, _ := startTestServerTB(b)

	// Prepare a valid signed challenge and solution once.
	sc := requestSignedChallengeTB(b, addr)

	// Extend expiry to avoid flakiness on long benches and re-sign.
	sc.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
	sc.Sig = signChallenge(sc.Challenge, sc.ExpiresAt)

	sol, err := powAlgo.Solve(sc.Challenge, rand.Reader)
	if err != nil {
		b.Fatalf("solve: %v", err)
	}

	var okCount int64

	b.ResetTimer()
	start := time.Now()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

			if _, err := fmt.Fprintln(conn, "QUOTE"); err != nil {
				_ = conn.Close()
				continue
			}

			enc := json.NewEncoder(conn)
			if err := enc.Encode(&sc); err != nil {
				_ = conn.Close()
				continue
			}
			if err := enc.Encode(sol); err != nil {
				_ = conn.Close()
				continue
			}

			r := bufio.NewReader(conn)
			if _, err := r.ReadString('\n'); err == nil {
				atomic.AddInt64(&okCount, 1)
			}

			_ = conn.Close()
		}
	})

	elapsed := time.Since(start)
	if elapsed > 0 {
		b.ReportMetric(float64(okCount)/elapsed.Seconds(), "req/s")
	}
}
