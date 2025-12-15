package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"pow-example/internal"
	"pow-example/internal/pow"
	"pow-example/internal/pow/algo/hash_pow"
)

const (
	defaultAddr = "localhost:4000"
)

var powAlgo = hash_pow.NewHashcash_SHA256()

// signedChallenge mirrors the server payload.
// It allows the server to verify the challenge was issued by the server and not modified.
type signedChallenge struct {
	Challenge *pow.Challenge `json:"challenge"`
	ExpiresAt int64          `json:"expires_at"` // unix seconds
	Sig       string         `json:"sig"`        // hex(HMAC-SHA256)
}

func main() {
	addr := internal.GetEnv("WOW_SERVER_ADDR", defaultAddr)

	// Step 1: request a signed challenge.
	sc := requestChallenge(addr)
	log.Printf("received challenge: %s", sc.Challenge.Challenge)

	start := time.Now()
	sol, err := powAlgo.Solve(sc.Challenge, rand.Reader)
	if err != nil {
		log.Fatalf("failed to solve challenge: %v", err)
	}
	elapsed := time.Since(start)
	log.Printf("solution found: nonce=%s, took=%s", sol.Nonce, elapsed)

	// Step 2: request a quote by sending back the signed challenge + solution.
	quote := requestQuote(addr, sc, sol)
	fmt.Printf("Quote from server:\n%s\n", quote)
}

func requestChallenge(addr string) signedChallenge {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Fatalf("failed to connect to server: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := fmt.Fprintln(conn, "CHALLENGE"); err != nil {
		log.Fatalf("failed to send CHALLENGE: %v", err)
	}

	dec := json.NewDecoder(conn)
	var sc signedChallenge
	if err := dec.Decode(&sc); err != nil {
		log.Fatalf("failed to decode signed challenge: %v", err)
	}
	if sc.Challenge == nil {
		log.Fatalf("server returned empty challenge")
	}
	return sc
}

func requestQuote(addr string, sc signedChallenge, sol *pow.Solution) string {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Fatalf("failed to connect to server: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := fmt.Fprintln(conn, "QUOTE"); err != nil {
		log.Fatalf("failed to send QUOTE: %v", err)
	}

	enc := json.NewEncoder(conn)
	if err := enc.Encode(&sc); err != nil {
		log.Fatalf("failed to send signed challenge: %v", err)
	}
	if err := enc.Encode(sol); err != nil {
		log.Fatalf("failed to send solution: %v", err)
	}

	// Server replies with a single line quote.
	r := bufio.NewReader(conn)
	quote, err := r.ReadString('\n')
	if err != nil {
		log.Fatalf("failed to read quote: %v", err)
	}
	return quote
}
