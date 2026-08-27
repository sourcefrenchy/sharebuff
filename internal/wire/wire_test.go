package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "regenerate testdata/vectors.json")

func TestNormalizeCode(t *testing.T) {
	if got := NormalizeCode("o1i-l 2ab"); got != "01112AB" {
		t.Fatalf("got %q", got)
	}
}

func TestTokens(t *testing.T) {
	for _, tok := range []string{NewPIN(6), NewLocator()} {
		for _, r := range tok {
			if !strings.ContainsRune(Alphabet, r) {
				t.Fatalf("char %q outside alphabet in %q", r, tok)
			}
		}
	}
	if len(NewLocator()) != LocatorLen || !ValidLocator(NewLocator()) {
		t.Fatal("bad locator")
	}
	for _, bad := range []string{"", "ABCD", "ABCDEF", "ABCDU", "abcde"} {
		if ValidLocator(bad) {
			t.Fatalf("locator %q accepted", bad)
		}
	}
}

func TestCodeRoundtrip(t *testing.T) {
	for _, n := range []int{KeyLenTiny, KeyLenShort, KeyLenFull} {
		key := NewKey(n)
		loc := NewLocator()
		code := EncodeCode(loc, key)
		wantChars := LocatorLen + map[int]int{KeyLenTiny: 8, KeyLenShort: 26, KeyLenFull: 52}[n]
		if got := len(NormalizeCode(code)); got != wantChars {
			t.Fatalf("keylen %d: code %q has %d chars, want %d", n, code, got, wantChars)
		}
		if !strings.HasPrefix(code, loc+"-") {
			t.Fatalf("code %q does not start with locator %q", code, loc)
		}
		for _, group := range strings.Split(code, "-") {
			if len(group) > 5 || len(group) == 0 {
				t.Fatalf("bad group %q in %q", group, code)
			}
		}
		// Canonical, lowercase, dash-less, and "typo-tolerant" spellings all decode.
		typed := strings.NewReplacer("0", "o", "1", "l").Replace(strings.ToLower(code))
		for _, spelling := range []string{code, strings.ToLower(code), strings.ReplaceAll(code, "-", ""), typed, " " + code + " "} {
			gotLoc, gotKey, err := DecodeCode(spelling)
			if err != nil {
				t.Fatalf("decode %q: %v", spelling, err)
			}
			if gotLoc != loc || !bytes.Equal(gotKey, key) {
				t.Fatalf("decode %q gave wrong locator/key", spelling)
			}
		}
	}
}

func TestCodeRejects(t *testing.T) {
	code := EncodeCode(NewLocator(), NewKey(KeyLenTiny))
	bad := []string{
		"", "ABCDE",
		code[:len(code)-1],                 // key part too short
		code + "A",                         // too long
		strings.Replace(code, "-", "U", 1), // U is not in the alphabet
	}
	for _, b := range bad {
		if _, _, err := DecodeCode(b); err == nil {
			t.Fatalf("code %q accepted", b)
		}
	}
	// Non-canonical spellings of the 26- and 52-char keys (padding bits set).
	for _, n := range []int{KeyLenShort, KeyLenFull} {
		raw := NormalizeCode(EncodeCode(NewLocator(), NewKey(n)))
		last := strings.IndexByte(Alphabet, raw[len(raw)-1])
		nc := raw[:len(raw)-1] + string(Alphabet[last|1])
		if _, _, err := DecodeCode(nc); err == nil {
			t.Fatalf("non-canonical %q accepted", nc)
		}
	}
}

func TestDeriveIsLocatorBound(t *testing.T) {
	key := NewKey(KeyLenFull)
	e1, a1, err := Derive(key, "ABCDEF", "AAAAA")
	if err != nil {
		t.Fatal(err)
	}
	e2, a2, _ := Derive(key, "ABCDEF", "AAAAA")
	if !bytes.Equal(e1, e2) || !bytes.Equal(a1, a2) {
		t.Fatal("Derive not deterministic")
	}
	e3, _, _ := Derive(key, "ABCDEF", "AAAAB")
	if bytes.Equal(e1, e3) {
		t.Fatal("locator does not salt the KDF")
	}
	e4, _, _ := Derive(key, "ABCDEG", "AAAAA")
	if bytes.Equal(e1, e4) {
		t.Fatal("PIN does not affect the KDF")
	}
	if _, _, err := Derive(make([]byte, 20), "ABCDEF", "AAAAA"); err == nil {
		t.Fatal("bad key length accepted")
	}
	if _, _, err := Derive(key, "ABCDEF", "aaaaa"); err == nil {
		t.Fatal("non-normalized locator accepted")
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	key := NewKey(KeyLenTiny)
	pin := NewPIN(6)
	loc := NewLocator()
	encKey, authKey, err := Derive(key, pin, loc)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("hello clipboard éà \U0001f512")
	blob, err := Seal(encKey, loc, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(encKey, loc, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch")
	}
	// Wrong PIN must fail to decrypt.
	badEnc, _, _ := Derive(key, "AAAAAA", loc)
	if _, err := Open(badEnc, loc, blob); err == nil {
		t.Fatal("decrypt with wrong PIN succeeded")
	}
	// AAD binding: a different locator must fail.
	if _, err := Open(encKey, "ZZZZZ", blob); err == nil {
		t.Fatal("decrypt with wrong locator succeeded")
	}
	sum := sha256.Sum256(authKey)
	if VerifierHex(authKey) != hex.EncodeToString(sum[:]) {
		t.Fatal("verifier mismatch")
	}
}

func TestEnvelopeRoundtrip(t *testing.T) {
	cases := []struct {
		h       Header
		payload []byte
	}{
		{Header{T: "text"}, []byte("hello")},
		{Header{T: "file", N: "résumé 🔐.pdf", M: "application/pdf"}, []byte{0x25, 0x50, 0x44, 0x46, 0x00, 0xff, 0xfe}},
		{Header{T: "file", N: "empty.bin", M: "application/octet-stream"}, []byte{}},
		{Header{T: "text"}, bytes.Repeat([]byte{0xa5}, 1<<20)}, // 1 MiB
	}
	for i, c := range cases {
		env, err := EncodeEnvelope(c.h, c.payload)
		if err != nil {
			t.Fatalf("case %d encode: %v", i, err)
		}
		h, payload, err := DecodeEnvelope(env)
		if err != nil {
			t.Fatalf("case %d decode: %v", i, err)
		}
		if h != c.h || !bytes.Equal(payload, c.payload) {
			t.Fatalf("case %d roundtrip mismatch: %+v", i, h)
		}
	}
}

func TestEnvelopeBounds(t *testing.T) {
	if _, err := EncodeEnvelope(Header{T: "weird"}, nil); err == nil {
		t.Fatal("bad type accepted")
	}
	if _, err := EncodeEnvelope(Header{T: "file", N: strings.Repeat("x", MaxHeader)}, nil); err == nil {
		t.Fatal("oversized header accepted")
	}
	if _, err := EncodeEnvelope(Header{T: "text"}, make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("oversized payload accepted")
	}
	for _, bad := range [][]byte{
		{}, {0, 0}, {0, 0, 0, 9, '{', '}'}, // truncated / header past end
		{0xff, 0xff, 0xff, 0xff},                    // absurd header length
		append([]byte{0, 0, 0, 2}, []byte("{}")...), // valid JSON, missing type
	} {
		if _, _, err := DecodeEnvelope(bad); err == nil {
			t.Fatalf("bad envelope %x accepted", bad)
		}
	}
}

func TestSealRejectsOversizedEnvelope(t *testing.T) {
	encKey, _, err := Derive(NewKey(KeyLenTiny), "0123AB", "AAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(encKey, "AAAAA", make([]byte, MaxEnvelope+1)); err == nil {
		t.Fatal("oversized envelope sealed")
	}
}

type vector struct {
	Code      string `json:"code"`
	Locator   string `json:"locator"`
	PIN       string `json:"pin"`
	Header    string `json:"header_json"`
	Payload   string `json:"payload_b64"`
	Envelope  string `json:"envelope_b64"`
	EncKeyHex string `json:"enc_key_hex"`
	AuthHex   string `json:"auth_key_hex"`
	Verifier  string `json:"verifier_hex"`
	CT        string `json:"ct_b64"`
}

// TestVectors pins Go output as the reference and (with -update) writes
// testdata/vectors.json, which tests/parity.mjs replays through the browser
// implementation (web/crypto.js + WebCrypto).
func TestVectors(t *testing.T) {
	fixed := []struct {
		keyByte byte
		keyLen  int
		locator string
		pin     string
		header  Header
		payload []byte
	}{
		{0x01, KeyLenFull, "AB3DE", "0123AB", Header{T: "text"}, []byte("hello world")},
		{0xaa, KeyLenShort, "ZZZZZ", "ZZZZZZ", Header{T: "text"}, []byte("multi\nline\néàü \U0001f511 payload")},
		{0x00, KeyLenTiny, "00000", "o1i-l 2ab", Header{T: "text"}, []byte("PIN normalization case")},
		{0x42, KeyLenTiny, "K7Q4T", "F1LEPN", Header{T: "file", N: "résumé 🔐.pdf", M: "application/pdf"},
			[]byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x00, 0x01, 0xfe, 0xff, 0x80, 0x7f}},
	}
	var vecs []vector
	for _, f := range fixed {
		key := bytes.Repeat([]byte{f.keyByte}, f.keyLen)
		encKey, authKey, err := Derive(key, f.pin, f.locator)
		if err != nil {
			t.Fatal(err)
		}
		env, err := EncodeEnvelope(f.header, f.payload)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := Seal(encKey, f.locator, env)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(encKey, f.locator, blob)
		if err != nil || !bytes.Equal(got, env) {
			t.Fatalf("self-open failed: %v", err)
		}
		h, payload, err := DecodeEnvelope(got)
		if err != nil || h != f.header || !bytes.Equal(payload, f.payload) {
			t.Fatalf("self-decode-envelope failed: %v", err)
		}
		hj, _ := json.Marshal(f.header)
		vecs = append(vecs, vector{
			Code:      EncodeCode(f.locator, key),
			Locator:   f.locator,
			PIN:       f.pin,
			Header:    string(hj),
			Payload:   base64.StdEncoding.EncodeToString(f.payload),
			Envelope:  base64.StdEncoding.EncodeToString(env),
			EncKeyHex: hex.EncodeToString(encKey),
			AuthHex:   hex.EncodeToString(authKey),
			Verifier:  VerifierHex(authKey),
			CT:        base64.StdEncoding.EncodeToString(blob),
		})
	}
	if *update {
		out, _ := json.MarshalIndent(vecs, "", "  ")
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("testdata/vectors.json", append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Skip("testdata/vectors.json missing; run go test -run TestVectors -update")
	}
	var stored []vector
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != len(vecs) {
		t.Fatal("vector count mismatch; regenerate with -update")
	}
	for i := range vecs {
		if vecs[i].Code != stored[i].Code || vecs[i].EncKeyHex != stored[i].EncKeyHex ||
			vecs[i].AuthHex != stored[i].AuthHex || vecs[i].Verifier != stored[i].Verifier {
			t.Fatalf("vector %d KDF/code output drifted from checked-in reference", i)
		}
	}
}
