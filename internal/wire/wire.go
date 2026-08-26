// Package wire implements the Sharebuff v3 crypto and encoding primitives
// shared by the CLI and the fallback server. See docs/SPEC.md.
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
	"math/big"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	Version  = "v3"
	IDLen    = 16
	SaltLen  = 16
	NonceLen = 12

	KeyLenShort = 16 // --short: 128-bit key, 26-char code
	KeyLenFull  = 32 // default: 256-bit key, 52-char code

	ScryptN = 1 << 16
	ScryptR = 8
	ScryptP = 1
	preLen  = 32
	rootLen = 64

	MaxPayload  = 20 << 20                    // user data inside the envelope
	MaxHeader   = 4096                        // serialized envelope header
	MaxEnvelope = 4 + MaxHeader + MaxPayload  // what Seal accepts
	MaxBlob     = MaxEnvelope + NonceLen + 16 // nonce + ciphertext + GCM tag
	MaxAttempts = 10

	// After the n-th counted wrong attempt, further claims are rejected
	// (HTTP 429, uncounted) until min(2^n, CooldownMaxSeconds) seconds pass.
	CooldownMaxSeconds = 300

	DefaultTTLSeconds = 604800
	MinTTLSeconds     = 60
	MaxTTLSeconds     = 604800

	aadPrefix = "sharebuff/" + Version + "."
	preSalt   = "sharebuff/" + Version + "/pre"
)

// PINAlphabet is Crockford base32: no I, L, O, U. Codes use the same alphabet.
const PINAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var crockford = base32.NewEncoding(PINAlphabet).WithPadding(base32.NoPadding)

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var b58Index = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(b58Alphabet); i++ {
		t[b58Alphabet[i]] = int8(i)
	}
	return t
}()

// Base58Encode encodes b using the Bitcoin alphabet.
func Base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	n := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// Base58Decode decodes s, rejecting characters outside the alphabet.
func Base58Decode(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	n := new(big.Int)
	radix := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		v := b58Index[s[i]]
		if v < 0 {
			return nil, errors.New("wire: invalid base58 character")
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(v)))
	}
	return append(make([]byte, zeros), n.Bytes()...), nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return b
}

// NewKey generates the secret key K: 32 bytes by default, 16 with short.
func NewKey(short bool) []byte {
	if short {
		return randBytes(KeyLenShort)
	}
	return randBytes(KeyLenFull)
}

// NewPIN generates an n-character PIN from PINAlphabet with unbiased sampling.
func NewPIN(n int) string {
	out := make([]byte, n)
	for i := 0; i < n; {
		b := randBytes(1)[0]
		if int(b) < 256-256%len(PINAlphabet) { // reject to avoid modulo bias
			out[i] = PINAlphabet[int(b)%len(PINAlphabet)]
			i++
		}
	}
	return string(out)
}

// NormalizeCode uppercases, strips spaces/hyphens, and maps O→0, I→1, L→1.
// Used for both PINs and URL codes so they survive being typed by hand.
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

// NormalizePIN is NormalizeCode (kept for readability at call sites).
func NormalizePIN(pin string) string { return NormalizeCode(pin) }

// EncodeCode renders K as dash-grouped Crockford base32 (5 chars per group).
func EncodeCode(key []byte) string {
	raw := crockford.EncodeToString(key)
	var groups []string
	for len(raw) > 5 {
		groups = append(groups, raw[:5])
		raw = raw[5:]
	}
	groups = append(groups, raw)
	return strings.Join(groups, "-")
}

// DecodeCode parses a typed code (any case, dashes/spaces optional,
// O/I/L tolerated) back into a 16- or 32-byte key.
func DecodeCode(code string) ([]byte, error) {
	n := NormalizeCode(code)
	if len(n) != 26 && len(n) != 52 {
		return nil, errors.New("wire: code must be 26 or 52 characters")
	}
	key, err := crockford.DecodeString(n)
	if err != nil {
		return nil, errors.New("wire: invalid code character")
	}
	if len(key) != KeyLenShort && len(key) != KeyLenFull {
		return nil, errors.New("wire: bad key length")
	}
	// Reject non-canonical encodings (non-zero padding bits) so a code has
	// exactly one spelling.
	if crockford.EncodeToString(key) != n {
		return nil, errors.New("wire: non-canonical code")
	}
	return key, nil
}

func validKey(key []byte) bool {
	return len(key) == KeyLenShort || len(key) == KeyLenFull
}

// Prepare is KDF stage A: from K alone, derive the server-side id and the
// per-secret salt for stage B. It runs scrypt so that a database dump (which
// contains id) offers only an expensive oracle for guessing K.
func Prepare(key []byte) (idB58 string, salt []byte, err error) {
	if !validKey(key) {
		return "", nil, errors.New("wire: key must be 16 or 32 bytes")
	}
	pre, err := scrypt.Key(key, []byte(preSalt), ScryptN, ScryptR, ScryptP, preLen)
	if err != nil {
		return "", nil, err
	}
	return Base58Encode(pre[0:IDLen]), pre[IDLen : IDLen+SaltLen], nil
}

// Derive is KDF stage B and returns (encKey, authKey).
func Derive(key []byte, pin string, salt []byte) (encKey, authKey []byte, err error) {
	if !validKey(key) || len(salt) != SaltLen {
		return nil, nil, errors.New("wire: bad key/salt length")
	}
	password := append(append([]byte{}, key...), []byte(NormalizePIN(pin))...)
	root, err := scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, rootLen)
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

// Seal encrypts an envelope, returning nonce||ciphertext||tag.
func Seal(encKey []byte, idB58 string, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxEnvelope {
		return nil, errors.New("wire: envelope exceeds the maximum size")
	}
	aead, err := gcmFor(encKey)
	if err != nil {
		return nil, err
	}
	nonce := randBytes(NonceLen)
	return aead.Seal(nonce, nonce, plaintext, []byte(aadPrefix+idB58)), nil
}

// Open decrypts a Seal blob.
func Open(encKey []byte, idB58 string, blob []byte) ([]byte, error) {
	if len(blob) < NonceLen+16 {
		return nil, errors.New("wire: blob too short")
	}
	aead, err := gcmFor(encKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, blob[:NonceLen], blob[NonceLen:], []byte(aadPrefix+idB58))
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
