package quotes

import (
	"embed"
	"encoding/json"
	"math/rand"
	"time"
)

//go:embed quotes.json
var quotesJSON embed.FS

var defaultQuotes []string

func init() {
	data, err := quotesJSON.ReadFile("quotes.json")
	if err != nil {
		panic("failed to read embedded quotes: " + err.Error())
	}

	err = json.Unmarshal(data, &defaultQuotes)
	if err != nil {
		panic("failed to unmarshal embedded quotes: " + err.Error())
	}
}

type Provider struct {
	quotes []string
	rnd    *rand.Rand
}

func NewProvider(quotes []string) *Provider {
	if len(quotes) == 0 {
		quotes = defaultQuotes
	}
	return &Provider{
		quotes: quotes,
		rnd:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (p *Provider) Random() string {
	if len(p.quotes) == 0 {
		return ""
	}
	i := p.rnd.Intn(len(p.quotes))
	return p.quotes[i]
}
