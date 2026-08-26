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

func TestNormalizePIN(t *testing.T) {
	if got := NormalizePIN("o1i-l 2ab"); got != "01112AB" {
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

func TestSealOpenRoundtrip(t *testing.T) {
	p := NewParams()
	pin := NewPIN(6)
	encKey, authKey, err := Derive(p.Key, pin, p.Salt)
	if err != nil {
		t.Fatal(err)
	}
	id := Base58Encode(p.ID)
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
	badEnc, _, _ := Derive(p.Key, "AAAAAA", p.Salt)
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
		{0xff, 0xff, 0xff, 0xff},           // absurd header length
		append([]byte{0, 0, 0, 2}, []byte("{}")...), // valid JSON, missing type
	} {
		if _, _, err := DecodeEnvelope(bad); err == nil {
			t.Fatalf("bad envelope %x accepted", bad)
		}
	}
}

func TestSealRejectsOversizedEnvelope(t *testing.T) {
	p := NewParams()
	encKey, _, err := Derive(p.Key, "0123AB", p.Salt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(encKey, Base58Encode(p.ID), make([]byte, MaxEnvelope+1)); err == nil {
		t.Fatal("oversized envelope sealed")
	}
}

type vector struct {
	KB58      string `json:"k_b58"`
	PIN       string `json:"pin"`
	SaltB58   string `json:"salt_b58"`
	IDB58     string `json:"id_b58"`
	Header    string `json:"header_json"`
	Payload   string `json:"payload_b64"`
	Envelope  string `json:"envelope_b64"`
	EncKeyHex string `json:"enc_key_hex"`
	AuthHex   string `json:"auth_key_hex"`
	Verifier  string `json:"verifier_hex"`
	CT        string `json:"ct_b64"`
}

// TestVectors pins Go output as the reference and (with -update) writes
// testdata/vectors.json, which tests/parity.mjs replays against the browser
// implementation (web/scrypt.js + WebCrypto).
func TestVectors(t *testing.T) {
	fixed := []struct {
		key, salt, id byte
		pin           string
		header        Header
		payload       []byte
	}{
		{0x01, 0x02, 0x03, "0123AB", Header{T: "text"}, []byte("hello world")},
		{0xaa, 0xbb, 0xcc, "ZZZZZZ", Header{T: "text"}, []byte("multi\nline\néàü \U0001f511 payload")},
		{0x00, 0xff, 0x10, "o1i-l 2ab", Header{T: "text"}, []byte("PIN normalization case")},
		{0x42, 0x24, 0x99, "F1LEPN", Header{T: "file", N: "résumé 🔐.pdf", M: "application/pdf"},
			[]byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x00, 0x01, 0xfe, 0xff, 0x80, 0x7f}},
	}
	var vecs []vector
	for _, f := range fixed {
		key := bytes.Repeat([]byte{f.key}, KeyLen)
		salt := bytes.Repeat([]byte{f.salt}, SaltLen)
		idRaw := bytes.Repeat([]byte{f.id}, IDLen)
		id := Base58Encode(idRaw)
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
		// Sanity: our own Open + DecodeEnvelope agree.
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
			KB58:      Base58Encode(key),
			PIN:       f.pin,
			SaltB58:   Base58Encode(salt),
			IDB58:     id,
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
	// Ensure the checked-in derivations (KDF outputs) are stable. Ciphertext
	// differs run-to-run (random nonce) so only deterministic fields compare.
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
		if vecs[i].EncKeyHex != stored[i].EncKeyHex || vecs[i].AuthHex != stored[i].AuthHex || vecs[i].Verifier != stored[i].Verifier {
			t.Fatalf("vector %d KDF output drifted from checked-in reference", i)
		}
	}
}
