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

func TestBase58Roundtrip(t *testing.T) {
	cases := [][]byte{
		{}, {0}, {0, 0, 1}, {0xff}, bytes.Repeat([]byte{0xab}, 32),
		{0, 0, 0, 0}, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	for _, c := range cases {
		got, err := Base58Decode(Base58Encode(c))
		if err != nil {
			t.Fatalf("decode(%x): %v", c, err)
		}
		if !bytes.Equal(got, c) {
			t.Fatalf("roundtrip %x -> %x", c, got)
		}
	}
	if _, err := Base58Decode("0OIl"); err == nil {
		t.Fatal("expected error on invalid base58 chars")
	}
}

func TestBase58KnownVector(t *testing.T) {
	// "Hello World!" is a widely used base58 reference vector.
	if got := Base58Encode([]byte("Hello World!")); got != "2NEpo7TZRRrLZSi2U" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeCode(t *testing.T) {
	if got := NormalizeCode("o1i-l 2ab"); got != "01112AB" {
		t.Fatalf("got %q", got)
	}
}

func TestNewPIN(t *testing.T) {
	pin := NewPIN(6)
	if len(pin) != 6 {
		t.Fatalf("len %d", len(pin))
	}
	for _, r := range pin {
		if !strings.ContainsRune(PINAlphabet, r) {
			t.Fatalf("char %q outside alphabet", r)
		}
	}
}

func TestCodeRoundtrip(t *testing.T) {
	for _, short := range []bool{true, false} {
		key := NewKey(short)
		code := EncodeCode(key)
		wantLen := 26 + 5 // 26 chars in 6 groups → 5 dashes
		if !short {
			wantLen = 52 + 10
		}
		if len(code) != wantLen {
			t.Fatalf("short=%v code %q has length %d, want %d", short, code, len(code), wantLen)
		}
		for _, group := range strings.Split(code, "-") {
			if len(group) > 5 || len(group) == 0 {
				t.Fatalf("bad group %q in %q", group, code)
			}
		}
		// Canonical, lowercase, dash-less, and "typo-tolerant" spellings all decode.
		typed := strings.NewReplacer("0", "o", "1", "l").Replace(strings.ToLower(code))
		for _, spelling := range []string{code, strings.ToLower(code), strings.ReplaceAll(code, "-", ""), typed, " " + code + " "} {
			got, err := DecodeCode(spelling)
			if err != nil {
				t.Fatalf("decode %q: %v", spelling, err)
			}
			if !bytes.Equal(got, key) {
				t.Fatalf("decode %q gave wrong key", spelling)
			}
		}
	}
}

func TestCodeRejects(t *testing.T) {
	key := NewKey(true)
	code := EncodeCode(key)
	bad := []string{
		"",
		code[:len(code)-1],                 // too short
		code + "A",                         // too long
		strings.Replace(code, "-", "U", 1), // U is not in the alphabet
	}
	// Non-canonical: flip the padding bits of the last character.
	raw := NormalizeCode(code)
	last := strings.IndexByte(PINAlphabet, raw[len(raw)-1])
	bad = append(bad, raw[:len(raw)-1]+string(PINAlphabet[last|1]))
	for _, b := range bad {
		if _, err := DecodeCode(b); err == nil {
			t.Fatalf("code %q accepted", b)
		}
	}
}

func TestPrepareIsDeterministicAndKeyBound(t *testing.T) {
	key := NewKey(false)
	id1, salt1, err := Prepare(key)
	if err != nil {
		t.Fatal(err)
	}
	id2, salt2, _ := Prepare(key)
	if id1 != id2 || !bytes.Equal(salt1, salt2) {
		t.Fatal("Prepare not deterministic")
	}
	if len(salt1) != SaltLen {
		t.Fatalf("salt len %d", len(salt1))
	}
	if _, err := Base58Decode(id1); err != nil {
		t.Fatalf("id not base58: %v", err)
	}
	other, _, _ := Prepare(NewKey(false))
	if other == id1 {
		t.Fatal("different keys gave the same id")
	}
	if _, _, err := Prepare(make([]byte, 20)); err == nil {
		t.Fatal("bad key length accepted")
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	key := NewKey(false)
	pin := NewPIN(6)
	id, salt, err := Prepare(key)
	if err != nil {
		t.Fatal(err)
	}
	encKey, authKey, err := Derive(key, pin, salt)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("hello clipboard éà \U0001f512")
	blob, err := Seal(encKey, id, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(encKey, id, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch")
	}
	// Wrong PIN must fail to decrypt.
	badEnc, _, _ := Derive(key, "AAAAAA", salt)
	if _, err := Open(badEnc, id, blob); err == nil {
		t.Fatal("decrypt with wrong PIN succeeded")
	}
	// AAD binding: a different id must fail.
	if _, err := Open(encKey, "2NEpo7TZRRrLZSi2U", blob); err == nil {
		t.Fatal("decrypt with wrong id succeeded")
	}
	// Verifier is the hash of authKey.
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
	encKey, _, err := Derive(NewKey(true), "0123AB", bytes.Repeat([]byte{7}, SaltLen))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(encKey, "2NEpo7TZRRrLZSi2U", make([]byte, MaxEnvelope+1)); err == nil {
		t.Fatal("oversized envelope sealed")
	}
}

type vector struct {
	KeyCode   string `json:"key_code"`
	PIN       string `json:"pin"`
	IDB58     string `json:"id_b58"`
	SaltHex   string `json:"salt_hex"`
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
		pin     string
		header  Header
		payload []byte
	}{
		{0x01, KeyLenFull, "0123AB", Header{T: "text"}, []byte("hello world")},
		{0xaa, KeyLenShort, "ZZZZZZ", Header{T: "text"}, []byte("multi\nline\néàü \U0001f511 payload")},
		{0x00, KeyLenFull, "o1i-l 2ab", Header{T: "text"}, []byte("PIN normalization case")},
		{0x42, KeyLenShort, "F1LEPN", Header{T: "file", N: "résumé 🔐.pdf", M: "application/pdf"},
			[]byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x00, 0x01, 0xfe, 0xff, 0x80, 0x7f}},
	}
	var vecs []vector
	for _, f := range fixed {
		key := bytes.Repeat([]byte{f.keyByte}, f.keyLen)
		id, salt, err := Prepare(key)
		if err != nil {
			t.Fatal(err)
		}
		encKey, authKey, err := Derive(key, f.pin, salt)
		if err != nil {
			t.Fatal(err)
		}
		env, err := EncodeEnvelope(f.header, f.payload)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := Seal(encKey, id, env)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(encKey, id, blob)
		if err != nil || !bytes.Equal(got, env) {
			t.Fatalf("self-open failed: %v", err)
		}
		h, payload, err := DecodeEnvelope(got)
		if err != nil || h != f.header || !bytes.Equal(payload, f.payload) {
			t.Fatalf("self-decode-envelope failed: %v", err)
		}
		hj, _ := json.Marshal(f.header)
		vecs = append(vecs, vector{
			KeyCode:   EncodeCode(key),
			PIN:       f.pin,
			IDB58:     id,
			SaltHex:   hex.EncodeToString(salt),
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
		if vecs[i].IDB58 != stored[i].IDB58 || vecs[i].SaltHex != stored[i].SaltHex ||
			vecs[i].EncKeyHex != stored[i].EncKeyHex || vecs[i].AuthHex != stored[i].AuthHex ||
			vecs[i].Verifier != stored[i].Verifier || vecs[i].KeyCode != stored[i].KeyCode {
			t.Fatalf("vector %d KDF/code output drifted from checked-in reference", i)
		}
	}
}
