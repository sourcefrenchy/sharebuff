package main

import (
	"crypto/rand"
	_ "embed"
	"math/big"
	"strings"
)

// wordlist.txt is the EFF long diceware list (7,776 words, curated for
// memorability and typo resistance) filtered to 4–8 lowercase ASCII letters:
// 6,134 words, 12.58 bits each. Only the CLI needs it — the recipient just
// types the words; the page normalizes and hashes whatever is entered.
//
//go:embed wordlist.txt
var wordlistRaw string

var wordlist = strings.Fields(wordlistRaw)

// newWordPIN returns n words joined by dashes, each chosen uniformly with
// crypto/rand (rejection-sampled via big.Int, so no modulo bias).
func newWordPIN(n int) string {
	words := make([]string, n)
	max := big.NewInt(int64(len(wordlist)))
	for i := range words {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err) // crypto/rand failure is unrecoverable
		}
		words[i] = wordlist[idx.Int64()]
	}
	return strings.Join(words, "-")
}
