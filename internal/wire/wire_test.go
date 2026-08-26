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

type vector struct {
	KB58      string `json:"k_b58"`
	PIN       string `json:"pin"`
	SaltB58   string `json:"salt_b58"`
	IDB58     string `json:"id_b58"`
	Plaintext string `json:"plaintext_b64"`
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
		plain         string
	}{
		{0x01, 0x02, 0x03, "0123AB", "hello world"},
		{0xaa, 0xbb, 0xcc, "ZZZZZZ", "multi\nline\néàü \U0001f511 payload"},
		{0x00, 0xff, 0x10, "o1i-l 2ab", "PIN normalization case"},
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
		blob, err := Seal(encKey, id, []byte(f.plain))
		if err != nil {
			t.Fatal(err)
		}
		// Sanity: our own Open agrees.
		if got, err := Open(encKey, id, blob); err != nil || !bytes.Equal(got, []byte(f.plain)) {
			t.Fatalf("self-open failed: %v", err)
		}
		vecs = append(vecs, vector{
			KB58:      Base58Encode(key),
			PIN:       f.pin,
			SaltB58:   Base58Encode(salt),
			IDB58:     id,
			Plaintext: base64.StdEncoding.EncodeToString([]byte(f.plain)),
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
