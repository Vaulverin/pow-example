package hash_pow

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"

	"pow-example/internal/pow"
)

type algo struct {
	hashFunc string
}

const (
	SHA3_256        = "sha3-256"
	BLAKE3_256      = "blake3-256"
	HASHCASH_SHA256 = "hashcash-sha256"
)

func newAlgo(hashFunc string) pow.Algorithm {
	switch hashFunc {
	case SHA3_256, BLAKE3_256, HASHCASH_SHA256:
		return algo{hashFunc: hashFunc}
	default:
		// fallback to the simplest/most available option
		return algo{hashFunc: HASHCASH_SHA256}
	}
}

func NewSha3_256() pow.Algorithm { return newAlgo(SHA3_256) }

func NewBlake3_256() pow.Algorithm { return newAlgo(BLAKE3_256) }

func NewHashcash_SHA256() pow.Algorithm { return newAlgo(HASHCASH_SHA256) }

func (a algo) Name() string { return a.hashFunc }

func (a algo) hash256(challenge, nonce string) []byte {
	msg := []byte(fmt.Sprintf("%s:%s", challenge, nonce))

	switch a.hashFunc {
	case SHA3_256:
		s := sha3.Sum256(msg)
		return s[:]
	case BLAKE3_256:
		s := blake3.Sum256(msg)
		return s[:]
	case HASHCASH_SHA256:
		fallthrough
	default:
		s := sha256.Sum256(msg)
		return s[:]
	}
}

func (a algo) NewChallenge(difficulty uint8) (*pow.Challenge, error) {
	ch, err := pow.RandomHex(16)
	if err != nil {
		return nil, err
	}

	target, err := pow.GenerateTarget(difficulty)
	if err != nil {
		return nil, err
	}

	return &pow.Challenge{
		Version:   pow.DefaultVersion,
		Challenge: ch,
		Target:    target,
	}, nil
}

func (a algo) Verify(ch *pow.Challenge, sol *pow.Solution) bool {
	if ch == nil || sol == nil {
		return false
	}
	if ch.Target == "" {
		return false
	}

	sum := a.hash256(ch.Challenge, sol.Nonce)
	ok, err := pow.HashLessThan(sum, ch.Target)
	return err == nil && ok
}

func (a algo) Solve(ch *pow.Challenge, rng io.Reader) (*pow.Solution, error) {
	if ch == nil {
		return nil, fmt.Errorf("nil challenge")
	}
	if ch.Target == "" {
		return nil, fmt.Errorf("empty target")
	}

	const maxIterations = 10_000_000 // safety bound to avoid infinite work

	for counter := uint64(0); counter < maxIterations; counter++ {
		nonce, err := pow.NextNonce(counter, rng)
		if err != nil {
			return nil, err
		}

		sum := a.hash256(ch.Challenge, nonce)
		ok, err := pow.HashLessThan(sum, ch.Target)
		if err != nil {
			return nil, err
		}
		if ok {
			return &pow.Solution{Nonce: nonce}, nil
		}
	}

	return nil, fmt.Errorf("solution not found after %d iterations", maxIterations)
}
