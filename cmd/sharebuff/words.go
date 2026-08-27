package main

import (
	"crypto/rand"
	"embed"
	"math/big"
	"sort"
	"strings"
)

// words/ holds one diceware-style list per language, all ASCII, 4–8 lowercase
// letters, deduplicated:
//
//	en  EFF long list filtered (6,134 words)
//	es, fr, it, pt  BIP-39 lists, accents folded to ASCII (≈1.9–2.0 k each)
//
// A PIN takes each word from a *different* language, in a random language
// order, so it reads like "basil-tundra-koala" but with, e.g., an English, a
// Spanish and an Italian word. Only the CLI needs the lists; the recipient
// just types what they were told and the page normalizes it.
//
//go:embed words/*.txt
var wordFS embed.FS

var wordlists = func() map[string][]string {
	out := map[string][]string{}
	entries, _ := wordFS.ReadDir("words")
	for _, e := range entries {
		b, _ := wordFS.ReadFile("words/" + e.Name())
		out[strings.TrimSuffix(e.Name(), ".txt")] = strings.Fields(string(b))
	}
	return out
}()

// languageOrder returns the language codes, sorted for determinism.
func languageOrder() []string {
	keys := make([]string, 0, len(wordlists))
	for k := range wordlists {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return int(v.Int64())
}

// newWordPIN returns n words joined by dashes. Languages are drawn without
// replacement in a random order (Fisher–Yates over the language set); when n
// exceeds the number of languages the cycle restarts with a fresh shuffle.
// Each word is uniform within its list (rejection-free big.Int sampling).
func newWordPIN(n int) string {
	langs := languageOrder()
	words := make([]string, 0, n)
	var order []string
	for len(words) < n {
		if len(order) == 0 {
			order = append([]string(nil), langs...)
			for i := len(order) - 1; i > 0; i-- {
				j := randInt(i + 1)
				order[i], order[j] = order[j], order[i]
			}
		}
		list := wordlists[order[0]]
		order = order[1:]
		words = append(words, list[randInt(len(list))])
	}
	return strings.Join(words, "-")
}
