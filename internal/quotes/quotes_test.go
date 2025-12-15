package quotes_test

import (
	"pow-example/internal/quotes"
	"testing"
)

func TestNewProvider_DefaultQuotes(t *testing.T) {
	tp := quotes.NewProvider(nil)
	if tp == nil {
		t.Fatal("expected non-nil Provider")
	}
}

func TestNewProvider_CustomQuotes(t *testing.T) {
	customQuotes := []string{"Quote 1", "Quote 2"}
	tp := quotes.NewProvider(customQuotes)
	if tp == nil {
		t.Fatal("expected non-nil Provider")
	}
}

func TestProvider_Random(t *testing.T) {
	tests := []struct {
		name         string
		quotes       []string
		expectOneOf  []string
		allowDefault bool
	}{
		{
			name:        "should return non-empty quote with default quotes",
			quotes:      nil,
			expectOneOf: nil,
		},
		{
			name:        "should return one of custom quotes",
			quotes:      []string{"Quote 1", "Quote 2"},
			expectOneOf: []string{"Quote 1", "Quote 2"},
		},
		{
			name:        "should fallback to default quotes when empty slice provided",
			quotes:      []string{},
			expectOneOf: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := quotes.NewProvider(tt.quotes)
			if tp == nil {
				t.Fatal("expected non-nil Provider")
			}

			quote := tp.Random()
			if quote == "" {
				t.Fatal("expected non-empty quote")
			}

			if len(tt.expectOneOf) > 0 {
				found := false
				for _, q := range tt.expectOneOf {
					if quote == q {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected quote to be one of %v, got: %q", tt.expectOneOf, quote)
				}
			}
		})
	}
}

func TestProvider_Random_UniformDistribution(t *testing.T) {
	quotesArr := []string{"Quote A", "Quote B", "Quote C", "Quote D"}
	tp := quotes.NewProvider(quotesArr)
	counts := map[string]int{}
	for _, q := range quotesArr {
		counts[q] = 0
	}

	samples := 100000
	for i := 0; i < samples; i++ {
		quote := tp.Random()
		if quote == "" {
			t.Fatal("expected non-empty quote")
		}
		counts[quote]++
	}

	// each quote should appear roughly in 20%-33% of samples
	for quote, count := range counts {
		if count < samples/5 {
			t.Errorf("quote %q appeared too few times: %d", quote, count)
		}
		if count > samples/3 {
			t.Errorf("quote %q appeared too many times: %d", quote, count)
		}
	}
}
