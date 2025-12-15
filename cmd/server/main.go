package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/net/netutil"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"pow-example/internal"
	"pow-example/internal/pow"
	"pow-example/internal/pow/algo/hash_pow"
	"pow-example/internal/quotes"
)

const (
	defaultAddr = ":4000"

	maxRequestLineBytes = 32  // e.g. "CHALLENGE" or "QUOTE"
	maxJSONPayloadBytes = 400 // max size for signed challenge + solution JSON
	bufSize             = 512 // buffered reader size
)

var powAlgo = hash_pow.NewHashcash_SHA256()

// activeConns is a simple load indicator used to calibrate PoW difficulty.
var activeConns = &atomic.Int64{}

var secret = []byte(internal.GetEnv("WOW_HMAC_SECRET", "dev-secret-change-me"))

// signedChallenge is sent to clients. The signature allows the server to verify
// that the challenge parameters were issued by the server and not modified by the client.
type signedChallenge struct {
	Challenge *pow.Challenge `json:"challenge"`
	ExpiresAt int64          `json:"expires_at"` // unix seconds
	Sig       string         `json:"sig"`        // hex(HMAC-SHA256)
}
type QuoteProvider interface{ Random() string }

func main() {
	addr := internal.GetEnv("WOW_SERVER_ADDR", defaultAddr)
	connLimit := internal.GetEnvInt("WOW_CONN_LIMIT", 5000)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", addr, err)
	}
	ln = netutil.LimitListener(ln, connLimit)

	log.Printf("Word-of-Wisdom server is listening on %s", addr)

	qp := quotes.NewProvider(nil)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn, qp)
	}
}

func handleConn(conn net.Conn, qp QuoteProvider) {
	activeConns.Add(1)
	defer activeConns.Add(-1)

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Printf("failed to close connection: %v", err)
		}
	}(conn)

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))

	// Stateless text protocol:
	// 1) Client sends:  "CHALLENGE\n" -> server replies with signed challenge JSON and closes.
	// 2) Client sends:  "QUOTE\n" -> server reads signed challenge JSON + solution JSON, verifies, replies with quote.
	r := bufio.NewReaderSize(conn, bufSize)

	// Read command with a hard size limit to avoid buffering large input.
	line, isPrefix, err := r.ReadLine()
	if err != nil {
		log.Printf("failed to read request line: %v", err)
		return
	}
	if isPrefix || len(line) > maxRequestLineBytes {
		log.Printf("request line too large from %s", conn.RemoteAddr())
		return
	}

	cmd := strings.ToUpper(strings.TrimSpace(string(line)))

	switch cmd {
	case "CHALLENGE":
		d := calibrateDifficulty(activeConns.Load())

		ch, err := powAlgo.NewChallenge(d)
		if err != nil {
			log.Printf("failed to create challenge: %v", err)
			return
		}

		exp := time.Now().Add(15 * time.Second).Unix()
		sig := signChallenge(ch, exp)

		resp := signedChallenge{
			Challenge: ch,
			ExpiresAt: exp,
			Sig:       sig,
		}

		enc := json.NewEncoder(conn)
		if err := enc.Encode(&resp); err != nil {
			log.Printf("failed to send signed challenge: %v", err)
			return
		}
		return

	case "QUOTE":
		lr := &io.LimitedReader{R: r, N: maxJSONPayloadBytes}
		dec := json.NewDecoder(lr)
		dec.DisallowUnknownFields()

		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		var sc signedChallenge
		if err := dec.Decode(&sc); err != nil {
			log.Printf("failed to decode signed challenge: %v", err)
			return
		}
		if lr.N <= 0 {
			log.Printf("request payload too large from %s", conn.RemoteAddr())
			return
		}
		if sc.ExpiresAt <= 0 || time.Now().Unix() > sc.ExpiresAt {
			log.Printf("expired challenge from %s", conn.RemoteAddr())
			return
		}
		if !verifyChallengeSig(sc.Challenge, sc.ExpiresAt, sc.Sig) {
			log.Printf("invalid challenge signature from %s", conn.RemoteAddr())
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		var sol pow.Solution
		if err := dec.Decode(&sol); err != nil {
			log.Printf("failed to decode solution: %v", err)
			return
		}
		if lr.N <= 0 {
			log.Printf("request payload too large from %s", conn.RemoteAddr())
			return
		}

		if !powAlgo.Verify(sc.Challenge, &sol) {
			log.Printf("invalid solution from %s", conn.RemoteAddr())
			return
		}

		quote := qp.Random()

		if _, err := fmt.Fprintln(conn, quote); err != nil {
			log.Printf("failed to send quote: %v", err)
			return
		}

		return

	default:
		log.Printf("unknown command %q from %s", cmd, conn.RemoteAddr())
		return
	}
}

func calibrateDifficulty(active int64) uint8 {
	// Convex-ish function: as active connections grow, make the challenge harder.
	// Difficulty is interpreted by pow.GenerateTarget as "percent harder than base".
	// Clamp to keep UX reasonable.
	if active <= 1 {
		return 0
	}

	// Linear baseline.
	d := int(active-1) * 10

	// Add a quadratic component after a small threshold to penalize high load more aggressively.
	if active > 10 {
		x := int(active - 10)
		d += x * x
	}

	if d > 200 {
		d = 200
	}
	return uint8(d)
}

func signChallenge(ch *pow.Challenge, expiresAt int64) string {
	mac := hmac.New(sha256.New, secret)
	_, err := io.WriteString(mac, challengeSigPayload(ch, expiresAt))
	if err != nil {
		log.Fatalf("failed to write challenge payload to HMAC: %v", err)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyChallengeSig(ch *pow.Challenge, expiresAt int64, sigHex string) bool {
	want := signChallenge(ch, expiresAt)
	// Constant-time compare over bytes.
	a, err1 := hex.DecodeString(want)
	b, err2 := hex.DecodeString(sigHex)
	if err1 != nil || err2 != nil {
		return false
	}
	return hmac.Equal(a, b)
}

func challengeSigPayload(ch *pow.Challenge, expiresAt int64) string {
	// Build a deterministic payload that does not depend on JSON key ordering.
	// Include all fields that affect verification and security.
	var paramsHex string
	if len(ch.Params) > 0 {
		paramsHex = hex.EncodeToString(ch.Params)
	}

	return fmt.Sprintf(
		"v=%s|challenge=%s|target=%s|params=%s|exp=%d",
		ch.Version,
		ch.Challenge,
		ch.Target,
		paramsHex,
		expiresAt,
	)
}
