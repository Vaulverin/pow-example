package main

import (
	"sync/atomic"

	"pow-example/internal"
	"pow-example/internal/pow/algo/hash_pow"
)

const (
	defaultAddr          = ":4000"
	maxRequestLineBytes  = 32
	maxJSONPayloadBytes  = 400
	bufSize              = 512
	challengeExpirySecs  = 15
	connReadDeadlineSecs = 5
)

var (
	powAlgo     = hash_pow.NewHashcash_SHA256()
	activeConns = &atomic.Int64{}
	secret      = []byte(internal.GetEnv("WOW_HMAC_SECRET", "dev-secret-change-me"))
)
