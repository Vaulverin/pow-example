package main

import "pow-example/internal/pow"

type signedChallenge struct {
	Challenge *pow.Challenge `json:"challenge"`
	ExpiresAt int64          `json:"expires_at"`
	Sig       string         `json:"sig"`
}

type QuoteProvider interface{ Random() string }
