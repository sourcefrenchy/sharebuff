package main

import (
	"math"
	"regexp"
	"strings"
	"testing"
)

func TestWordlistProperties(t *testing.T) {
	if len(wordlist) < 6000 {
		t.Fatalf("wordlist too small: %d", len(wordlist))
	}
	seen := map[string]bool{}
	re := regexp.MustCompile(`^[a-z]{4,8}$`)
	for _, w := range wordlist {
		if !re.MatchString(w) {
			t.Fatalf("word %q is not 4-8 lowercase ASCII letters", w)
		}
		if seen[w] {
			t.Fatalf("duplicate word %q", w)
		}
		seen[w] = true
	}
	if bits := 3 * math.Log2(float64(len(wordlist))); bits < 37 {
		t.Fatalf("3-word PIN entropy %.1f bits, want >= 37", bits)
	}
}

func TestNewWordPIN(t *testing.T) {
	pin := newWordPIN(3)
	parts := strings.Split(pin, "-")
	if len(parts) != 3 {
		t.Fatalf("got %q", pin)
	}
	for _, p := range parts {
		if len(p) < 4 || len(p) > 8 {
			t.Fatalf("bad word %q in %q", p, pin)
		}
	}
	seen := map[string]bool{pin: true}
	for i := 0; i < 20; i++ {
		seen[newWordPIN(3)] = true
	}
	if len(seen) < 20 {
		t.Fatalf("PINs are not random: only %d distinct in 21 draws", len(seen))
	}
}
