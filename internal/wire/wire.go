// Package wire implements the Sharebuff v1 crypto and encoding primitives
// shared by the CLI and the fallback server. See docs/SPEC.md.
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	Version  = "v1"
	IDLen    = 16
	KeyLen   = 32
	SaltLen  = 16
	NonceLen = 12

	ScryptN = 1 << 16
	ScryptR = 8
	ScryptP = 1
	rootLen = 64

	MaxPlaintext = 64 * 1024
	MaxAttempts  = 5

	DefaultTTLSeconds = 604800
	MinTTLSeconds     = 60
	MaxTTLSeconds     = 604800

	aadPrefix = "sharebuff/" + Version + "."
)

// PINAlphabet is Crockford base32: no I, L, O, U.
const PINAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

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

// Params holds the sender-generated per-secret values.
type Params struct {
	ID   []byte // IDLen bytes
	Key  []byte // KeyLen bytes, travels only in the URL fragment
	Salt []byte // SaltLen bytes
}

// NewParams generates fresh id/key/salt from crypto/rand.
func NewParams() Params {
	return Params{ID: randBytes(IDLen), Key: randBytes(KeyLen), Salt: randBytes(SaltLen)}
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

// NormalizePIN uppercases, strips spaces/hyphens, and maps O→0, I→1, L→1.
func NormalizePIN(pin string) string {
	pin = strings.ToUpper(pin)
	var b strings.Builder
	for _, r := range pin {
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

// Derive runs the spec KDF and returns (encKey, authKey).
func Derive(key []byte, pin string, salt []byte) (encKey, authKey []byte, err error) {
	if len(key) != KeyLen || len(salt) != SaltLen {
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

// Seal encrypts plaintext, returning nonce||ciphertext||tag.
func Seal(encKey []byte, idB58 string, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintext {
		return nil, errors.New("wire: plaintext exceeds 64 KiB")
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

// Fragment renders the URL fragment for the retrieve page.
func Fragment(p Params) string {
	return Version + "." + Base58Encode(p.ID) + "." + Base58Encode(p.Key) + "." + Base58Encode(p.Salt)
}
