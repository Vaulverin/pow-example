package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"pow-example/internal/pow"
)

func handleChallenge(conn net.Conn) {
	difficulty := calibrateDifficulty(activeConns.Load())
	ch, err := powAlgo.NewChallenge(difficulty)
	if err != nil {
		log.Printf("failed to create challenge: %v", err)
		return
	}

	exp := time.Now().Add(challengeExpirySecs * time.Second).Unix()
	resp := signedChallenge{
		Challenge: ch,
		ExpiresAt: exp,
		Sig:       signChallenge(ch, exp),
	}

	if err := json.NewEncoder(conn).Encode(&resp); err != nil {
		log.Printf("failed to send challenge: %v", err)
	}
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
	a, _ := hex.DecodeString(want)
	b, _ := hex.DecodeString(sigHex)
	return hmac.Equal(a, b)
}

func challengeSigPayload(ch *pow.Challenge, expiresAt int64) string {
	paramsHex := ""
	if len(ch.Params) > 0 {
		paramsHex = hex.EncodeToString(ch.Params)
	}
	return fmt.Sprintf("v=%s|challenge=%s|target=%s|params=%s|exp=%d", ch.Version, ch.Challenge, ch.Target, paramsHex, expiresAt)
}
