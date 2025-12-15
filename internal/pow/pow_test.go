package pow_test

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"math/big"

	"testing"
	"time"

	"pow-example/internal/pow"
	"pow-example/internal/pow/algo/argon2id"
	"pow-example/internal/pow/algo/hash_pow"
	"pow-example/internal/pow/algo/scrypt"
)

type algoCase struct {
	newAlgo    func() pow.Algorithm
	difficulty uint8
	timeout    time.Duration
}

var cases = []algoCase{
	{newAlgo: hash_pow.NewHashcash_SHA256, difficulty: 0, timeout: 2 * time.Second},
	{newAlgo: hash_pow.NewBlake3_256, difficulty: 0, timeout: 2 * time.Second},
	{newAlgo: hash_pow.NewSha3_256, difficulty: 0, timeout: 2 * time.Second},
	{newAlgo: scrypt.New, difficulty: 0, timeout: 120 * time.Second},
	{newAlgo: argon2id.New, difficulty: 0, timeout: 120 * time.Second},
}

func TestAlgorithms_SolveAndVerify(t *testing.T) {
	for _, tc := range cases {
		algo := tc.newAlgo()
		t.Run(algo.Name(), func(t *testing.T) {
			if tc.timeout > 5*time.Second {
				t.Skip()
			}
			if tc.timeout < 5*time.Second {
				t.Parallel()
			}
			ch, err := algo.NewChallenge(tc.difficulty)
			if err != nil {
				t.Fatalf("NewChallenge error: %v", err)
			}
			if ch == nil || ch.Challenge == "" {
				t.Fatalf("invalid challenge: %+v", ch)
			}

			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()

			solCh := make(chan *pow.Solution, 1)
			errCh := make(chan error, 1)

			go func() {
				sol, err := algo.Solve(ch, crand.Reader)
				if err != nil {
					errCh <- err
					return
				}
				solCh <- sol
			}()

			select {
			case <-ctx.Done():
				t.Fatalf("Solve timeout after %s (difficulty=%d)", tc.timeout, tc.difficulty)
			case err := <-errCh:
				t.Fatalf("Solve error: %v", err)
			case sol := <-solCh:
				if sol == nil || sol.Nonce == "" {
					t.Fatalf("invalid solution: %+v", sol)
				}
				if ok := algo.Verify(ch, sol); !ok {
					t.Fatalf("VerifySolution failed for solved nonce")
				}
			}
		})
	}
}

func TestAlgorithms_InvalidSolutionRejected(t *testing.T) {

	for _, tc := range cases {
		algo := tc.newAlgo()
		t.Run(algo.Name(), func(t *testing.T) {
			if tc.timeout > 5*time.Second {
				t.Skip()
			}
			t.Parallel()
			ch, err := algo.NewChallenge(tc.difficulty)
			if err != nil {
				t.Fatalf("NewChallenge error: %v", err)
			}

			bad := &pow.Solution{Nonce: "definitely-not-a-valid-nonce"}
			if ok := algo.Verify(ch, bad); ok {
				t.Fatalf("expected invalid solution to be rejected")
			}
		})
	}
}

func TestChallengeAndSolution_JSONRoundtrip(t *testing.T) {
	for _, tc := range cases {
		algo := tc.newAlgo()
		t.Run(algo.Name(), func(t *testing.T) {
			if tc.timeout > 5*time.Second {
				t.Skip()
			}
			if tc.timeout < 5*time.Second {
				t.Parallel()
			}
			ch, err := algo.NewChallenge(tc.difficulty)
			if err != nil {
				t.Fatalf("NewChallenge error: %v", err)
			}

			// Roundtrip challenge through JSON encoder/decoder.
			var chBuf bytes.Buffer
			if err := pow.EncodeChallenge(&chBuf, ch); err != nil {
				t.Fatalf("EncodeChallenge error: %v", err)
			}
			ch2, err := pow.DecodeChallenge(&chBuf)
			if err != nil {
				t.Fatalf("DecodeChallenge error: %v", err)
			}
			if ch2 == nil || ch2.Challenge == "" {
				t.Fatalf("invalid decoded challenge: %+v", ch2)
			}

			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()

			solCh := make(chan *pow.Solution, 1)
			errCh := make(chan error, 1)

			go func() {
				sol, err := algo.Solve(ch2, crand.Reader)
				if err != nil {
					errCh <- err
					return
				}
				solCh <- sol
			}()

			var sol *pow.Solution
			select {
			case <-ctx.Done():
				t.Fatalf("Solve timeout after %s (difficulty=%d)", tc.timeout, tc.difficulty)
			case err := <-errCh:
				t.Fatalf("Solve error: %v", err)
			case sol = <-solCh:
				if sol == nil || sol.Nonce == "" {
					t.Fatalf("invalid solution: %+v", sol)
				}
			}

			// Roundtrip solution through JSON encoder/decoder.
			var solBuf bytes.Buffer
			if err := pow.EncodeSolution(&solBuf, sol); err != nil {
				t.Fatalf("EncodeSolution error: %v", err)
			}
			sol2, err := pow.DecodeSolution(&solBuf)
			if err != nil {
				t.Fatalf("DecodeSolution error: %v", err)
			}

			if ok := algo.Verify(ch2, sol2); !ok {
				t.Fatalf("VerifySolution failed after JSON roundtrip")
			}
		})
	}
}

func TestGenerateTarget_BaseIsReturnedForZeroDifficulty(t *testing.T) {
	target, err := pow.GenerateTarget(0)
	if err != nil {
		t.Fatalf("GenerateTarget(0) error: %v", err)
	}

	targetInt, ok := new(big.Int).SetString(target, 16)
	if !ok {
		t.Fatalf("GenerateTarget(0) returned invalid hex: %s", target)
	}

	if targetInt.Cmp(pow.BaseTarget) != 0 {
		t.Fatalf("GenerateTarget(0) = %s, want %s", targetInt.Text(16), pow.BaseTarget.Text(16))
	}
}

func TestGenerateTarget_MonotonicDecreasingWithDifficulty(t *testing.T) {
	last := pow.BaseTarget
	testLevels := make([]uint8, 200)
	for i := range testLevels {
		testLevels[i] = uint8(i + 1)
	}
	for _, d := range testLevels {
		tHex, err := pow.GenerateTarget(d)
		if err != nil {
			t.Fatalf("GenerateTarget(%d) error: %v", d, err)
		}

		nextTarget, ok := new(big.Int).SetString(tHex, 16)
		if !ok {
			t.Fatalf("GenerateTarget(%d) returned invalid hex: %s", d, tHex)
		}

		if nextTarget.Cmp(last) >= 0 {
			t.Fatalf("GenerateTarget(%d) returned target not less than previous difficulty target. Previous: %s, Current: %s", d, last.Text(10), nextTarget.Text(10))
		}

		last = nextTarget
	}
}
