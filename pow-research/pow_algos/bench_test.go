package pow_algos

import (
	crand "crypto/rand"
	"encoding/json"
	"pow-example/internal/pow"
	"pow-example/internal/pow/algo/argon2id"
	"pow-example/internal/pow/algo/hash_pow"
	"pow-example/internal/pow/algo/scrypt"
	"testing"
)

type benchCase struct {
	name       string
	newAlgo    func() pow.Algorithm
	difficulty uint8
	tweak      func(ch *pow.Challenge)
}

func tweakScrypt(ch *pow.Challenge) {
	// Keep it reasonably fast for benchmarks while still exercising scrypt.
	p := scrypt.Params{
		N:      1 << 13, // 8192
		R:      8,
		P:      1,
		KeyLen: 32,
		Salt:   16,
	}
	raw, _ := json.Marshal(p)
	ch.Params = raw
}

func tweakArgon2id(ch *pow.Challenge) {
	// Keep it reasonably fast for benchmarks (lower memory than default).
	p := argon2id.Params{
		Time:    1,
		Memory:  16 * 1024, // 16 MiB
		Threads: 1,
		KeyLen:  32,
		Salt:    16,
	}
	raw, _ := json.Marshal(p)
	ch.Params = raw
}

var benchCases = []benchCase{
	{name: "hashcash", newAlgo: hash_pow.NewHashcash_SHA256, difficulty: 0},
	{name: "blake3", newAlgo: hash_pow.NewBlake3_256, difficulty: 0},
	{name: "sha3_256", newAlgo: hash_pow.NewSha3_256, difficulty: 0},
	{name: "scrypt", newAlgo: scrypt.New, difficulty: 0, tweak: tweakScrypt},
	{name: "argon2id", newAlgo: argon2id.New, difficulty: 0, tweak: tweakArgon2id},
}

func BenchmarkNewChallenge(b *testing.B) {
	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			algo := tc.newAlgo()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				ch, err := algo.NewChallenge(tc.difficulty)
				if err != nil {
					b.Fatalf("NewChallenge: %v", err)
				}
				if ch == nil || ch.Challenge == "" {
					b.Fatalf("invalid challenge")
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			algo := tc.newAlgo()

			ch, err := algo.NewChallenge(tc.difficulty)
			if err != nil {
				b.Fatalf("NewChallenge: %v", err)
			}
			if tc.tweak != nil {
				tc.tweak(ch)
			}

			sol, err := algo.Solve(ch, crand.Reader)
			if err != nil {
				b.Fatalf("Solve: %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if ok := algo.Verify(ch, sol); !ok {
					b.Fatalf("VerifySolution failed")
				}
			}
		})
	}
}

func BenchmarkSolve(b *testing.B) {
	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			algo := tc.newAlgo()

			ch, err := algo.NewChallenge(tc.difficulty)
			if err != nil {
				b.Fatalf("NewChallenge: %v", err)
			}
			if tc.tweak != nil {
				tc.tweak(ch)
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
