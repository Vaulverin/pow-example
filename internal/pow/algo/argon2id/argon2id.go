package argon2id

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"pow-example/internal/pow"
)

type Params struct {
	Time    uint32 `json:"t"`      // iterations
	Memory  uint32 `json:"mKiB"`   // memory in KiB
	Threads uint8  `json:"p"`      // parallelism
	KeyLen  uint32 `json:"keyLen"` // derived key length
	Salt    int    `json:"saltBytes"`
}

func defaultParams() Params {
	return Params{
		Time:    1,
		Memory:  8 * 1024,
		Threads: 1,
		KeyLen:  32,
		Salt:    16,
	}
}

// algo implements a Hashcash-style PoW using Argon2id:
// derive key = argon2.IDKey(challenge ":" nonce, salt, t, m, p) and require derivedKey < target.
type algo struct{}

func New() pow.Algorithm { return algo{} }

func (algo) Name() string { return "argon2id" }

func (algo) NewChallenge(difficulty uint8) (*pow.Challenge, error) {
	p := defaultParams()

	ch, err := pow.RandomHex(16)
	if err != nil {
		return nil, err
	}

	saltHex, err := pow.RandomHex(p.Salt)
	if err != nil {
		return nil, err
	}

	paramsRaw, _ := json.Marshal(p)

	// difficulty is interpreted by pow.GenerateTarget as “percent harder than base”.
	// We keep Difficulty in the challenge for visibility/debugging, but the acceptance
	// condition is derivedKey < target.
	target, err := pow.GenerateTarget(difficulty)
	if err != nil {
		return nil, err
	}

	return &pow.Challenge{
		Version:   pow.DefaultVersion,
		Challenge: ch + "|" + saltHex,
		Target:    target,
		Params:    paramsRaw,
	}, nil
}

func (algo) Verify(ch *pow.Challenge, sol *pow.Solution) bool {
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

func (algo) Solve(ch *pow.Challenge, rng io.Reader) (*pow.Solution, error) {
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

	const maxIterations = 2_000_000 // safety bound to avoid infinite work (argon2id is expensive)

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

	// Basic sanity checks
	if p.Time == 0 || p.Memory < 8*1024 || p.Threads == 0 || p.KeyLen == 0 {
		return nil, fmt.Errorf("invalid argon2id params")
	}

	key := argon2.IDKey(payload, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return key, nil
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
