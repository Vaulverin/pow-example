package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"pow-example/internal/pow"
)

func requestQuote(t *testing.T, addr string, sc signedChallenge, sol *pow.Solution) (string, error) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintln(conn, "QUOTE"); err != nil {
		return "", err
	}

	enc := json.NewEncoder(conn)
	if err := enc.Encode(&sc); err != nil {
		return "", err
	}
	if err := enc.Encode(sol); err != nil {
		return "", err
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return line, nil
}

func TestCalculateQuoteRequestSize(t *testing.T) {
	ch, err := powAlgo.NewChallenge(50)
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	exp := time.Now().Add(10 * time.Second).Unix()
	sig := signChallenge(ch, exp)

	sc := signedChallenge{
		Challenge: ch,
		ExpiresAt: exp,
		Sig:       sig,
	}

	sol, err := powAlgo.Solve(ch, rand.Reader)
	if err != nil {
		t.Fatalf("solve: %v", err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(&sc); err != nil {
		t.Fatalf("encode signed challenge: %v", err)
	}
	if err := enc.Encode(sol); err != nil {
		t.Fatalf("encode solution: %v", err)
	}

	size := buf.Len()
	t.Logf("Calculated quote request size: %d bytes", size)
}

func TestServer_HappyPath(t *testing.T) {
	addr, _ := startTestServerTB(t)

	sc := requestSignedChallengeTB(t, addr)
	sol, err := powAlgo.Solve(sc.Challenge, rand.Reader)
	if err != nil {
		t.Fatalf("solve: %v", err)
	}

	quote, err := requestQuote(t, addr, sc, sol)
	if err != nil {
		t.Fatalf("request quote: %v", err)
	}
	if quote != "wisdom\n" {
		t.Fatalf("unexpected quote: %q", quote)
	}
}

func TestServer_UnknownCommand_Closed(t *testing.T) {
	addr, _ := startTestServerTB(t)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprintln(conn, "HELLO")

	buf := make([]byte, 1)
	_, rerr := conn.Read(buf)
	if rerr == nil {
		t.Fatalf("expected close/EOF")
	}
}

func TestServer_TamperedChallengeSignatureRejected(t *testing.T) {
	addr, _ := startTestServerTB(t)

	sc := requestSignedChallengeTB(t, addr)
	sol, err := powAlgo.Solve(sc.Challenge, rand.Reader)
	if err != nil {
		t.Fatalf("solve: %v", err)
	}

	// Tamper with a signed field.
	sc2 := sc
	sc2.Challenge.Target = strings.Repeat("f", 64)

	_, qerr := requestQuote(t, addr, sc2, sol)
	if qerr == nil {
		t.Fatalf("expected failure (server should reject tampered challenge)")
	}
}

func TestServer_ExpiredChallengeRejectedEvenIfSignatureValid(t *testing.T) {
	addr, _ := startTestServerTB(t)

	sc := requestSignedChallengeTB(t, addr)

	// Make it expired and recompute signature so HMAC is still valid.
	sc2 := sc
	sc2.ExpiresAt = time.Now().Add(-5 * time.Second).Unix()
	sc2.Sig = signChallenge(sc2.Challenge, sc2.ExpiresAt)

	sol, err := powAlgo.Solve(sc2.Challenge, rand.Reader)
	if err != nil {
		t.Fatalf("solve: %v", err)
	}

	_, qerr := requestQuote(t, addr, sc2, sol)
	if qerr == nil {
		t.Fatalf("expected failure (expired challenge)")
	}
}

func TestServer_InvalidSolutionRejected(t *testing.T) {
	addr, _ := startTestServerTB(t)

	sc := requestSignedChallengeTB(t, addr)
	sol, err := powAlgo.Solve(sc.Challenge, rand.Reader)
	if err != nil {
		t.Fatalf("solve: %v", err)
	}

	bad := *sol
	bad.Nonce = sol.Nonce + "-tamper"

	_, qerr := requestQuote(t, addr, sc, &bad)
	if qerr == nil {
		t.Fatalf("expected failure (invalid solution)")
	}
}

func TestServer_MalformedJSONRejected(t *testing.T) {
	addr, _ := startTestServerTB(t)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprintln(conn, "QUOTE")
	_, _ = conn.Write([]byte("{not-json}\n"))

	b := make([]byte, 1)
	_, rerr := conn.Read(b)
	if rerr == nil {
		t.Fatalf("expected close/EOF")
	}
}

func TestServer_ChallengeDoesNotHoldConnectionOpen(t *testing.T) {
	addr, _ := startTestServerTB(t)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprintln(conn, "CHALLENGE")

	var sc signedChallenge
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&sc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Server should close after responding.
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatalf("expected connection to be closed")
	}
}

func TestServer_SignatureCoversAllVerificationFields(t *testing.T) {
	addr, _ := startTestServerTB(t)

	sc := requestSignedChallengeTB(t, addr)
	if !verifyChallengeSig(sc.Challenge, sc.ExpiresAt, sc.Sig) {
		t.Fatalf("expected signature to verify")
	}

	// ExpiresAt change breaks signature.
	sc2 := sc
	sc2.ExpiresAt++
	if verifyChallengeSig(sc2.Challenge, sc2.ExpiresAt, sc2.Sig) {
		t.Fatalf("expected signature to fail after expires_at change")
	}

	// Challenge id change breaks signature.
	sc3 := sc
	sc3.Challenge.Challenge = sc3.Challenge.Challenge + "x"
	if verifyChallengeSig(sc3.Challenge, sc3.ExpiresAt, sc3.Sig) {
		t.Fatalf("expected signature to fail after challenge change")
	}

	// Target change breaks signature.
	sc4 := sc
	sc4.Challenge.Target = strings.Repeat("0", 63) + "1"
	if verifyChallengeSig(sc4.Challenge, sc4.ExpiresAt, sc4.Sig) {
		t.Fatalf("expected signature to fail after target change")
	}

	// Params change breaks signature.
	sc5 := sc
	sc5.Challenge.Params = append([]byte(nil), sc5.Challenge.Params...)
	sc5.Challenge.Params = append(sc5.Challenge.Params, 0x01)
	if verifyChallengeSig(sc5.Challenge, sc5.ExpiresAt, sc5.Sig) {
		t.Fatalf("expected signature to fail after params change")
	}
}

func TestServer_ReplayIsPossibleInStatelessMode_DocumentedBehavior(t *testing.T) {
	addr, _ := startTestServerTB(t)

	sc := requestSignedChallengeTB(t, addr)
	sol, err := powAlgo.Solve(sc.Challenge, rand.Reader)
	if err != nil {
		t.Fatalf("solve: %v", err)
	}

	q1, err := requestQuote(t, addr, sc, sol)
	if err != nil {
		t.Fatalf("quote1: %v", err)
	}
	if q1 != "wisdom\n" {
		t.Fatalf("unexpected quote1: %q", q1)
	}

	q2, err := requestQuote(t, addr, sc, sol)
	if err != nil {
		t.Fatalf("quote2: %v", err)
	}
	if q2 != "wisdom\n" {
		t.Fatalf("unexpected quote2: %q", q2)
	}
}

func TestServer_VerifyRejectsInvalidTargetLength(t *testing.T) {
	addr, _ := startTestServerTB(t)

	sc := requestSignedChallengeTB(t, addr)

	// Force a bad target length and recompute signature so HMAC passes.
	sc2 := sc
	sc2.Challenge.Target = "abcd" // invalid length
	sc2.Sig = signChallenge(sc2.Challenge, sc2.ExpiresAt)

	sol := &pow.Solution{Nonce: "x"}
	_, err := requestQuote(t, addr, sc2, sol)
	if err == nil {
		t.Fatalf("expected failure")
	}
}

func TestServer_QuoteRequestWithPartialPayloadRejected(t *testing.T) {
	addr, _ := startTestServerTB(t)

	sc := requestSignedChallengeTB(t, addr)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprintln(conn, "QUOTE")
	enc := json.NewEncoder(conn)
	_ = enc.Encode(&sc)
	// Do not send solution.

	b := make([]byte, 1)
	_, rerr := conn.Read(b)
	if rerr == nil {
		t.Fatalf("expected close/EOF")
	}
}

func TestServer_ChallengeSignaturePayloadStable(t *testing.T) {
	ch := &pow.Challenge{Version: "1", Challenge: "abc", Target: strings.Repeat("0", 63) + "1", Params: []byte{0x01, 0x02}}
	exp := time.Now().Add(10 * time.Second).Unix()
	p1 := challengeSigPayload(ch, exp)
	p2 := challengeSigPayload(ch, exp)
	if p1 != p2 {
		t.Fatalf("payload must be stable")
	}

	ch2 := *ch
	ch2.Target = strings.Repeat("f", 64)
	if challengeSigPayload(&ch2, exp) == p1 {
		t.Fatalf("payload should change when target changes")
	}
}

func TestServer_SignedChallengeJSONRoundTrip(t *testing.T) {
	addr, _ := startTestServerTB(t)

	sc := requestSignedChallengeTB(t, addr)

	b, err := json.Marshal(&sc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var sc2 signedChallenge
	if err := json.Unmarshal(b, &sc2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if sc2.Sig != sc.Sig || sc2.ExpiresAt != sc.ExpiresAt || sc2.Challenge == nil {
		t.Fatalf("signed challenge mismatch after roundtrip")
	}
}

func TestServer_RejectsVeryLargeSignedChallenge(t *testing.T) {
	addr, _ := startTestServerTB(t)

	sc := requestSignedChallengeTB(t, addr)
	// Inflate params to a large size and recompute signature.
	sc.Challenge.Params = bytes.Repeat([]byte{0x01}, 1<<20) // 1 MiB
	sc.Sig = signChallenge(sc.Challenge, sc.ExpiresAt)

	sol := &pow.Solution{Nonce: "x"}
	_, err := requestQuote(t, addr, sc, sol)
	if err == nil {
		t.Fatalf("expected failure for oversized payload")
	}
}
