package pow

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

const (
	DefaultVersion = "1"
)

var BaseTarget = big.NewInt(1).Lsh(big.NewInt(1), 256-10) // 2^246

type Challenge struct {
	Version   string          `json:"version"`
	Target    string          `json:"target"`
	Challenge string          `json:"challenge"`
	Params    json.RawMessage `json:"params,omitempty"` // optional, algo-specific params
}

type Solution struct {
	Nonce string `json:"nonce"`
}

// Algorithm defines a pluggable Proof-of-Work implementation.
// The server typically uses NewChallenge + Verify.
// The client typically uses Solve.
type Algorithm interface {
	Name() string
	NewChallenge(difficulty uint8) (*Challenge, error)
	Verify(ch *Challenge, sol *Solution) bool
	Solve(ch *Challenge, rng io.Reader) (*Solution, error)
}

func HashLessThan(hash []byte, targetHex string) (bool, error) {
	targetBytes, err := hex.DecodeString(targetHex)
	if err != nil {
		return false, fmt.Errorf("invalid target hex: %w", err)
	}
	if len(targetBytes) != len(hash) {
		return false, fmt.Errorf("invalid target length: got %d bytes, want %d bytes", len(targetBytes), len(hash))
	}

	return bytes.Compare(hash, targetBytes) < 0, nil
}

func GenerateTarget(difficulty uint8) (string, error) {
	// difficulty is "percent harder than base":
	//  - difficulty=0   -> base target (no change)
	//  - difficulty=50  -> ~1.5x harder (target reduced by 1.5)
	//  - difficulty=100 -> 2x harder (target reduced by 2)
	// - difficulty=200 -> 3x harder (target reduced by 3)
	// We keep difficulty in [0..200] for now to avoid extreme values in the demo.
	if difficulty > 200 {
		return "", fmt.Errorf("invalid difficulty: %d", difficulty)
	}

	// target = base * 100 / (100 + difficulty)
	// Smaller target => lower success probability => harder.
	num := big.NewInt(100)
	den := big.NewInt(100 + int64(difficulty))

	t := new(big.Int).Mul(BaseTarget, num)
	t.Div(t, den)

	// Return fixed-width 32-byte (256-bit) hex string (big-endian), lowercase, no 0x prefix.
	return hex256(t), nil
}

func hex256(x *big.Int) string {
	b := x.Bytes()
	b = leftPad32(b)
	return hex.EncodeToString(b)
}

func leftPad32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	if len(b) > 32 {
		// Keep the least significant 32 bytes (should not happen for a 256-bit target,
		// but makes the function robust if the base target changes).
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func EncodeChallenge(w io.Writer, ch *Challenge) error {
	enc := json.NewEncoder(w)
	return enc.Encode(ch)
}

func DecodeChallenge(r io.Reader) (*Challenge, error) {
	var ch Challenge
	dec := json.NewDecoder(r)
	if err := dec.Decode(&ch); err != nil {
		return nil, err
	}
	return &ch, nil
}

func EncodeSolution(w io.Writer, sol *Solution) error {
	enc := json.NewEncoder(w)
	return enc.Encode(sol)
}

func DecodeSolution(r io.Reader) (*Solution, error) {
	var sol Solution
	dec := json.NewDecoder(r)
	if err := dec.Decode(&sol); err != nil {
		return nil, err
	}
	return &sol, nil
}

func RandomHex(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func NextNonce(counter uint64, rng io.Reader) (string, error) {
	// Deterministic counter + some randomness to avoid identical work across clients.
	n, err := rand.Int(rng, big.NewInt(1<<62))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%d", counter, n.Int64()), nil
}
