package main

import (
	"testing"

	"github.com/sourcefrenchy/sharebuff/internal/wire"
)

func TestChooseTier(t *testing.T) {
	cases := []struct {
		tiny, short, full bool
		env               string
		want              int
		wantErr           bool
	}{
		{false, false, false, "", 0, false}, // nothing explicit → automatic rule
		{true, false, false, "", wire.KeyLenTiny, false},
		{false, true, false, "", wire.KeyLenShort, false},
		{false, false, true, "tiny", wire.KeyLenFull, false}, // flag beats env
		{true, false, false, "full", wire.KeyLenTiny, false}, // flag beats env
		{false, false, false, "tiny", wire.KeyLenTiny, false},
		{false, false, false, " Short ", wire.KeyLenShort, false},
		{false, false, false, "full", wire.KeyLenFull, false},
		{false, false, false, "huge", 0, true},
		{true, true, false, "", 0, true},
	}
	for i, c := range cases {
		got, err := chooseTierExplicit(c.tiny, c.short, c.full, c.env)
		if (err != nil) != c.wantErr || got != c.want {
			t.Fatalf("case %d: got %d err=%v, want %d wantErr=%v", i, got, err, c.want, c.wantErr)
		}
	}
}

func TestChooseTierAutoEscalation(t *testing.T) {
	cases := []struct {
		isFile        bool
		size          int
		env           string
		tiny          bool
		want          int
		wantEscalated bool
	}{
		{false, 100, "", false, wire.KeyLenTiny, false},
		{false, AutoEscalateBytes, "", false, wire.KeyLenTiny, false},
		{false, AutoEscalateBytes + 1, "", false, wire.KeyLenShort, true},
		{true, 10, "", false, wire.KeyLenShort, true},
		{true, 10, "", true, wire.KeyLenTiny, false},      // explicit flag wins
		{true, 10, "tiny", false, wire.KeyLenTiny, false}, // explicit env wins
		{false, 10, "full", false, wire.KeyLenFull, false},
	}
	for i, c := range cases {
		got, esc, err := chooseTier(c.tiny, false, false, c.env, c.isFile, c.size)
		if err != nil || got != c.want || esc != c.wantEscalated {
			t.Fatalf("case %d: got %d esc=%v err=%v, want %d esc=%v", i, got, esc, err, c.want, c.wantEscalated)
		}
	}
}
