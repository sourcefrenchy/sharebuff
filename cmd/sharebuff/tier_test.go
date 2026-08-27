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
		{false, false, false, "", wire.KeyLenTiny, false},
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
		got, err := chooseTier(c.tiny, c.short, c.full, c.env)
		if (err != nil) != c.wantErr || got != c.want {
			t.Fatalf("case %d: got %d err=%v, want %d wantErr=%v", i, got, err, c.want, c.wantErr)
		}
	}
}
