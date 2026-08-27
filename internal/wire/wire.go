// Package wire implements the Sharebuff v4 crypto and encoding primitives
// shared by the CLI and the fallback server. See docs/SPEC.md and
// docs/SECURITY.md.
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	Version  = "v4"
	NonceLen = 12

	// LocatorLen is the public record identifier: 5 Crockford chars (25 bits),
	// random, unique per live secret. It is the only part of the code the
	// server ever sees.
	LocatorLen = 5

	KeyLenTiny  = 5  // --tiny:  40-bit key,  8-char code (type by hand)
	KeyLenShort = 16 // --short: 128-bit key, 26-char code
	KeyLenFull  = 32 // default: 256-bit key, 52-char code (post-quantum bar)

	ScryptN = 1 << 16
	ScryptR = 8
	ScryptP = 1
	rootLen = 64

	MaxPayload  = 20 << 20                    // user data inside the envelope
	MaxHeader   = 4096                        // serialized envelope header
	MaxEnvelope = 4 + MaxHeader + MaxPayload  // what Seal accepts
	MaxBlob     = MaxEnvelope + NonceLen + 16 // nonce + ciphertext + GCM tag
	MaxAttempts = 10

	// After the n-th counted wrong attempt, further claims are rejected
	// (HTTP 429, uncounted) until min(2^n, CooldownMaxSeconds) seconds pass.
	CooldownMaxSeconds = 300

	DefaultTTLSeconds = 3600
	MinTTLSeconds     = 60
	MaxTTLSeconds     = 604800

	aadPrefix  = "sharebuff/" + Version + "."
	saltPrefix = "sharebuff/" + Version + "/"
)

// Alphabet is Crockford base32: no I, L, O, U. Locators, keys and PINs all
// use it so every typed token gets the same typo tolerance.
const Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// PINAlphabet is kept as an alias for readability at call sites.
const PINAlphabet = Alphabet

var crockford = base32.NewEncoding(Alphabet).WithPadding(base32.NoPadding)

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return b
}

// ValidKeyLen reports whether n is one of the supported key sizes.
func ValidKeyLen(n int) bool {
	return n == KeyLenTiny || n == KeyLenShort || n == KeyLenFull
}

// NewKey generates a secret key of the given size (KeyLenTiny/Short/Full).
func NewKey(n int) []byte {
	if !ValidKeyLen(n) {
		panic("wire: unsupported key length")
	}
	return randBytes(n)
}

// RandomToken returns n characters from Alphabet with unbiased sampling.
func RandomToken(n int) string {
	out := make([]byte, n)
	for i := 0; i < n; {
		b := randBytes(1)[0]
		if int(b) < 256-256%len(Alphabet) { // reject to avoid modulo bias
			out[i] = Alphabet[int(b)%len(Alphabet)]
			i++
		}
	}
	return string(out)
}

// NewLocator returns a fresh random public locator.
func NewLocator() string { return RandomToken(LocatorLen) }

// NewPIN generates an n-character PIN.
func NewPIN(n int) string { return RandomToken(n) }

// NormalizeCode uppercases, strips spaces/hyphens, and maps O→0, I→1, L→1.
// Used for locators, keys and PINs so they survive being typed by hand.
func NormalizeCode(s string) string {
	s = strings.ToUpper(s)
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '-':
		case 'O':
			b.WriteRune('0')
		case 'I', 'L':
			b.WriteRune('1')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizePIN is NormalizeCode.
func NormalizePIN(pin string) string { return NormalizeCode(pin) }

// ValidLocator reports whether s is a canonical (normalized) locator.
func ValidLocator(s string) bool {
	if len(s) != LocatorLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(Alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

func group5(raw string) string {
	var groups []string
	for len(raw) > 5 {
		groups = append(groups, raw[:5])
		raw = raw[5:]
	}
	return strings.Join(append(groups, raw), "-")
}

// EncodeCode renders LOCATOR-KEY… as dash-grouped Crockford base32. The first
// group is the public locator; everything after it is the secret key.
func EncodeCode(locator string, key []byte) string {
	return group5(locator + crockford.EncodeToString(key))
}

// DecodeCode parses a typed code (any case, dashes/spaces optional, O/I/L
// tolerated) into its locator and key. Rejects non-canonical spellings.
func DecodeCode(code string) (locator string, key []byte, err error) {
	n := NormalizeCode(code)
	if len(n) < LocatorLen {
		return "", nil, errors.New("wire: code too short")
	}
	locator, rest := n[:LocatorLen], n[LocatorLen:]
	if !ValidLocator(locator) {
		return "", nil, errors.New("wire: invalid locator character")
	}
	if len(rest) != 8 && len(rest) != 26 && len(rest) != 52 {
		return "", nil, errors.New("wire: key part must be 8, 26 or 52 characters")
	}
	key, err = crockford.DecodeString(rest)
	if err != nil {
		return "", nil, errors.New("wire: invalid code character")
	}
	if !ValidKeyLen(len(key)) || crockford.EncodeToString(key) != rest {
		return "", nil, errors.New("wire: non-canonical code")
	}
	return locator, key, nil
}

// Derive runs the KDF and returns (encKey, authKey). The locator is the
// scrypt salt: unique per secret, public, and not derived from the key — so
// nothing the server stores is a function of K alone, and an offline attacker
// must search K and PIN jointly (see docs/SECURITY.md).
func Derive(key []byte, pin, locator string) (encKey, authKey []byte, err error) {
	if !ValidKeyLen(len(key)) || !ValidLocator(locator) {
		return nil, nil, errors.New("wire: bad key length or locator")
	}
	password := append(append([]byte{}, key...), []byte(NormalizePIN(pin))...)
	root, err := scrypt.Key(password, []byte(saltPrefix+locator), ScryptN, ScryptR, ScryptP, rootLen)
	if err != nil {
		return nil, nil, err
	}
	return root[0:32], root[32:64], nil
}

// VerifierHex returns SHA-256(authKey) as lowercase hex.
func VerifierHex(authKey []byte) string {
	sum := sha256.Sum256(authKey)
	return hex.EncodeToString(sum[:])
}

func gcmFor(encKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts an envelope, returning nonce||ciphertext||tag, bound to the
// locator through the AAD.
func Seal(encKey []byte, locator string, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxEnvelope {
		return nil, errors.New("wire: envelope exceeds the maximum size")
	}
	aead, err := gcmFor(encKey)
	if err != nil {
		return nil, err
	}
	nonce := randBytes(NonceLen)
	return aead.Seal(nonce, nonce, plaintext, []byte(aadPrefix+locator)), nil
}

// Open decrypts a Seal blob.
func Open(encKey []byte, locator string, blob []byte) ([]byte, error) {
	if len(blob) < NonceLen+16 {
		return nil, errors.New("wire: blob too short")
	}
	aead, err := gcmFor(encKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, blob[:NonceLen], blob[NonceLen:], []byte(aadPrefix+locator))
}

// Header describes the envelope payload. It is encrypted alongside the
// payload, so the server never sees a filename or MIME type.
type Header struct {
	T string `json:"t"`           // "text" | "file"
	N string `json:"n,omitempty"` // filename (file mode)
	M string `json:"m,omitempty"` // MIME type (file mode)
}

// EncodeEnvelope renders u32be(len(header)) || header JSON || payload.
func EncodeEnvelope(h Header, payload []byte) ([]byte, error) {
	if h.T != "text" && h.T != "file" {
		return nil, errors.New("wire: header type must be text or file")
	}
	if len(payload) > MaxPayload {
		return nil, errors.New("wire: payload exceeds 20 MiB")
	}
	hj, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if len(hj) > MaxHeader {
		return nil, errors.New("wire: envelope header too large")
	}
	buf := make([]byte, 4+len(hj)+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(hj)))
	copy(buf[4:], hj)
	copy(buf[4+len(hj):], payload)
	return buf, nil
}

// DecodeEnvelope parses an EncodeEnvelope blob.
func DecodeEnvelope(b []byte) (Header, []byte, error) {
	var h Header
	if len(b) < 4 {
		return h, nil, errors.New("wire: envelope truncated")
	}
	hlen := int(binary.BigEndian.Uint32(b[0:4]))
	if hlen > MaxHeader || 4+hlen > len(b) {
		return h, nil, errors.New("wire: envelope header out of bounds")
	}
	if err := json.Unmarshal(b[4:4+hlen], &h); err != nil {
		return h, nil, err
	}
	if h.T != "text" && h.T != "file" {
		return h, nil, errors.New("wire: unknown envelope type")
	}
	return h, b[4+hlen:], nil
}
