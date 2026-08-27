package main

import (
	"math"
	"regexp"
	"strings"
	"testing"
)

func TestWordlistProperties(t *testing.T) {
	re := regexp.MustCompile(`^[a-z]{4,8}$`)
	if len(wordlists) < 5 {
		t.Fatalf("expected ≥5 language lists, got %d", len(wordlists))
	}
	for lang, list := range wordlists {
		if len(list) < 1500 {
			t.Fatalf("%s list too small: %d", lang, len(list))
		}
		seen := map[string]bool{}
		for _, w := range list {
			if !re.MatchString(w) {
				t.Fatalf("%s word %q is not 4-8 lowercase ASCII letters", lang, w)
			}
			if seen[w] {
				t.Fatalf("%s duplicate word %q", lang, w)
			}
			seen[w] = true
		}
	}
	// 3 words from 3 distinct languages in random order: ≥ 37 bits.
	langs := languageOrder()
	var combos float64
	var rec func(depth int, used map[string]bool, prod float64)
	rec = func(depth int, used map[string]bool, prod float64) {
		if depth == 3 {
			combos += prod
			return
		}
		for _, l := range langs {
			if !used[l] {
				used[l] = true
				rec(depth+1, used, prod*float64(len(wordlists[l])))
				used[l] = false
			}
		}
	}
	rec(0, map[string]bool{}, 1)
	if bits := math.Log2(combos); bits < 37 {
		t.Fatalf("3-word PIN entropy %.1f bits, want ≥ 37", bits)
	}
}

func TestNewWordPIN(t *testing.T) {
	pin := newWordPIN(3)
	parts := strings.Split(pin, "-")
	if len(parts) != 3 {
		t.Fatalf("got %q", pin)
	}
	// Each word comes from a different language.
	lang := func(w string) string {
		for l, list := range wordlists {
			for _, x := range list {
				if x == w {
					return l
				}
			}
		}
		return ""
	}
	for i := 0; i < 30; i++ {
		p := strings.Split(newWordPIN(3), "-")
		langsSeen := map[string]int{}
		for _, w := range p {
			if len(w) < 4 || len(w) > 8 {
				t.Fatalf("bad word %q", w)
			}
			langsSeen[lang(w)]++
		}
		for l, n := range langsSeen {
			if n > 1 && !ambiguous(p, l) {
				t.Fatalf("PIN %q repeats language %s", strings.Join(p, "-"), l)
			}
		}
	}
	seen := map[string]bool{pin: true}
	for i := 0; i < 20; i++ {
		seen[newWordPIN(3)] = true
	}
	if len(seen) < 20 {
		t.Fatalf("PINs are not random: only %d distinct in 21 draws", len(seen))
	}
	if n := len(strings.Split(newWordPIN(6), "-")); n != 6 {
		t.Fatalf("6-word PIN has %d words", n)
	}
}

// ambiguous reports whether a word in p exists in more than one language list
// (e.g. "final" is Spanish, Italian and Portuguese), which the language-of
// lookup cannot disambiguate; such repeats are not a selection bug.
func ambiguous(p []string, l string) bool {
	for _, w := range p {
		count := 0
		for _, list := range wordlists {
			for _, x := range list {
				if x == w {
					count++
					break
				}
			}
		}
		if count > 1 {
			return true
		}
	}
	return false
}
