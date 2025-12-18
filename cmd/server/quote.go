package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"pow-example/internal/pow"
)

func handleQuote(conn net.Conn, r *bufio.Reader, qp QuoteProvider) {
	lr := &io.LimitedReader{R: r, N: maxJSONPayloadBytes}
	dec := json.NewDecoder(lr)
	dec.DisallowUnknownFields()

	var sc signedChallenge
	if err := dec.Decode(&sc); err != nil || lr.N <= 0 || sc.ExpiresAt <= time.Now().Unix() ||
		!verifyChallengeSig(sc.Challenge, sc.ExpiresAt, sc.Sig) {
		log.Printf("invalid challenge from %s", conn.RemoteAddr())
		return
	}

	var sol pow.Solution
	if err := dec.Decode(&sol); err != nil || lr.N <= 0 || !powAlgo.Verify(sc.Challenge, &sol) {
		log.Printf("invalid solution from %s", conn.RemoteAddr())
		return
	}

	if _, err := fmt.Fprintln(conn, qp.Random()); err != nil {
		log.Printf("failed to send quote: %v", err)
	}
}
