package scrypt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"

	"pow-example/internal/pow"
)

type Params struct {
	N      int `json:"n"`
	R      int `json:"r"`
	P      int `json:"p"`
	KeyLen int `json:"keyLen"`
	Salt   int `json:"saltBytes"`
}

func defaultParams() Params {
	return Params{
		N:      1 << 15, // 32768
		R:      8,
		P:      1,
		KeyLen: 32,
		Salt:   16,
	}
}

// algo implements a Hashcash-style PoW using scrypt:
// derive key = scrypt(challenge ":" nonce, salt) and require derivedKey < target.
type algo struct{}

func New() pow.Algorithm { return algo{} }

func (a algo) Name() string { return "scrypt" }

func (a algo) NewChallenge(difficulty uint8) (*pow.Challenge, error) {
	p := defaultParams()

	ch, err := pow.RandomHex(16)
	if err != nil {
		return nil, err
	}

	// NOTE: we keep salt constant per challenge to make verification deterministic.
	saltHex, err := pow.RandomHex(p.Salt)
	if err != nil {
		return nil, err
	}

	paramsRaw, _ := json.Marshal(p)

	target, err := pow.GenerateTarget(difficulty)
	if err != nil {
		return nil, err
	}

	return &pow.Challenge{
		Version:   pow.DefaultVersion,
		Challenge: ch + "|" + saltHex,
		Target:    target,
		Params:    paramsRaw, // includes N/r/p/keyLen/saltBytes (salt value is carried in Challenge string)
	}, nil
}

func (a algo) Verify(ch *pow.Challenge, sol *pow.Solution) bool {
	if ch == nil || sol == nil {
		return false
	}
	if ch.Target == "" {
		return false
	}

	p := defaultParams()
	if ch.Params != nil {
		_ = json.Unmarshal(ch.Params, &p)
	}

	base, saltHex, ok := splitChallenge(ch.Challenge)
	if !ok {
		// Backward compatibility: no salt in Challenge.
		base = ch.Challenge
		saltHex = ""
	}

	payload := []byte(fmt.Sprintf("%s:%s", base, sol.Nonce))
	key, err := derive(payload, saltHex, p)
	if err != nil {
		return false
	}

	ok2, err := pow.HashLessThan(key, ch.Target)
	return err == nil && ok2
}

func (a algo) Solve(ch *pow.Challenge, rng io.Reader) (*pow.Solution, error) {
	if ch == nil {
		return nil, fmt.Errorf("nil challenge")
	}
	if ch.Target == "" {
		return nil, fmt.Errorf("empty target")
	}

	p := defaultParams()
	if ch.Params != nil {
		_ = json.Unmarshal(ch.Params, &p)
	}

	base, saltHex, ok := splitChallenge(ch.Challenge)
	if !ok {
		// In normal flow, server includes salt in Challenge.
		s, err := pow.RandomHex(p.Salt)
		if err != nil {
			return nil, err
		}
		saltHex = s
		base = ch.Challenge
	}

	const maxIterations = 500_000 // safety bound (scrypt is expensive)

	for counter := uint64(0); counter < maxIterations; counter++ {
		nonce, err := pow.NextNonce(counter, rng)
		if err != nil {
			return nil, err
		}

		payload := []byte(fmt.Sprintf("%s:%s", base, nonce))
		key, err := derive(payload, saltHex, p)
		if err != nil {
			return nil, err
		}

		ok2, err := pow.HashLessThan(key, ch.Target)
		if err != nil {
			return nil, err
		}
		if ok2 {
			return &pow.Solution{Nonce: nonce}, nil
		}
	}

	return nil, fmt.Errorf("solution not found after %d iterations", maxIterations)
}

func derive(payload []byte, saltHex string, p Params) ([]byte, error) {
	var salt []byte
	var err error
	if saltHex != "" {
		salt, err = hex.DecodeString(saltHex)
		if err != nil {
			return nil, err
		}
	} else {
		salt = []byte{}
	}

	// Ensure N is power of 2 and > 1.
	if p.N <= 1 || (p.N&(p.N-1)) != 0 {
		return nil, fmt.Errorf("invalid scrypt N: %d", p.N)
	}
	if p.R <= 0 || p.P <= 0 || p.KeyLen <= 0 {
		return nil, fmt.Errorf("invalid scrypt params")
	}

	return scrypt.Key(payload, salt, p.N, p.R, p.P, p.KeyLen)
}

// splitChallenge expects "base|saltHex".
func splitChallenge(ch string) (base string, saltHex string, ok bool) {
	for i := 0; i < len(ch); i++ {
		if ch[i] == '|' {
			return ch[:i], ch[i+1:], true
		}
	}
	return "", "", false
}
