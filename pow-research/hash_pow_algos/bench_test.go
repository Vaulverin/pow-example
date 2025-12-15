package hash_pow_algos

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"pow-example/internal/pow"
	"pow-example/internal/pow/algo/hash_pow"
)

var hashAlgos = []func() pow.Algorithm{
	hash_pow.NewBlake3_256,
	hash_pow.NewHashcash_SHA256,
	hash_pow.NewSha3_256,
}

var hashDifficulties = []uint8{0, 25, 50, 75, 100, 200}

func BenchmarkHashPoW_Verify_ByDifficulty(b *testing.B) {
	for _, newAlgo := range hashAlgos {
		for _, diff := range hashDifficulties {
			algo := newAlgo()
			b.Run(fmt.Sprintf("%s/d=%d", algo.Name(), diff), func(b *testing.B) {
				ch, err := algo.NewChallenge(diff)
				if err != nil {
					b.Fatalf("NewChallenge: %v", err)
				}

				// Produce a valid solution once; verify is the hot path we want to measure.
				sol, err := algo.Solve(ch, crand.Reader)
				if err != nil {
					b.Fatalf("Solve: %v", err)
				}

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					if ok := algo.Verify(ch, sol); !ok {
						b.Fatalf("Verify failed")
					}
				}
			})
		}
	}
}

func BenchmarkHashPoW_Solve_ByDifficulty(b *testing.B) {
	for _, newAlgo := range hashAlgos {
		for _, diff := range hashDifficulties {
			algo := newAlgo()
			b.Run(fmt.Sprintf("%s/d=%d", algo.Name(), diff), func(b *testing.B) {
				ch, err := algo.NewChallenge(diff)
				if err != nil {
					b.Fatalf("NewChallenge: %v", err)
				}

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					if _, err := algo.Solve(ch, crand.Reader); err != nil {
						b.Fatalf("Solve: %v", err)
					}
				}
			})
		}
	}
}
