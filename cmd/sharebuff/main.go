// sharebuff posts an end-to-end-encrypted, one-shot secret (text or a file)
// and prints the retrieve URL + PIN. See docs/SPEC.md and docs/SECURITY.md.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sourcefrenchy/sharebuff/internal/wire"
)

type createReq struct {
	ID         string `json:"id"`
	CT         string `json:"ct"`
	Verifier   string `json:"verifier"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

type createResp struct {
	ExpiresAt int64    `json:"expires_at"`
	Error     string   `json:"error"`
	Reasons   []string `json:"reasons"`
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "sharebuff: "+format+"\n", a...)
	os.Exit(1)
}

// readClipboard reads the system clipboard as text on macOS, Linux
// (Wayland or X11), and Windows.
func readClipboard() ([]byte, error) {
	var candidates [][]string
	switch runtime.GOOS {
	case "darwin":
		candidates = [][]string{{"pbpaste"}}
	case "linux":
		candidates = [][]string{
			{"wl-paste", "--no-newline"},
			{"xclip", "-selection", "clipboard", "-o"},
			{"xsel", "-ob"},
		}
	case "windows":
		candidates = [][]string{{"powershell", "-NoProfile", "-Command", "Get-Clipboard", "-Raw"}}
	default:
		return nil, fmt.Errorf("clipboard capture not supported on %s; pipe the data instead", runtime.GOOS)
	}
	var lastErr error
	for _, c := range candidates {
		if _, err := exec.LookPath(c[0]); err != nil {
			lastErr = err
			continue
		}
		out, err := exec.Command(c[0], c[1:]...).Output()
		if err == nil {
			return out, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no working clipboard tool (tried pbpaste/wl-paste/xclip/xsel/powershell): %v", lastErr)
}

// readInput resolves the payload and its envelope header from, in order of
// precedence: --file, --clip (system clipboard), piped stdin. A bare
// interactive invocation prints usage instead of silently posting anything.
func readInput(filePath string, forceClip bool) (wire.Header, []byte) {
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			fatalf("reading %s: %v", filePath, err)
		}
		name := filepath.Base(filePath)
		mt := mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))
		if mt == "" {
			mt = "application/octet-stream"
		}
		return wire.Header{T: "file", N: name, M: mt}, data
	}
	if forceClip {
		data, err := readClipboard()
		if err != nil {
			fatalf("%v", err)
		}
		return wire.Header{T: "text"}, data
	}
	stat, err := os.Stdin.Stat()
	if piped := err == nil && stat.Mode()&os.ModeCharDevice == 0; piped {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, wire.MaxPayload+1))
		if err != nil {
			fatalf("reading stdin: %v", err)
		}
		return wire.Header{T: "text"}, data
	}
	// Interactive, no input selected: teach, don't post.
	flag.Usage()
	os.Exit(0)
	return wire.Header{}, nil // unreachable
}

// defaultServer is the deployed Cloudflare Worker; override with
// SHAREBUFF_URL or --server (e.g. for a self-hosted sharebuff-server).
const defaultServer = "https://s.sharebuff-worker.workers.dev"

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `sharebuff — one-shot end-to-end-encrypted drop (text & files)

Post a secret and get back a code (in a URL) plus a one-time PIN. The first
valid retrieve destroys it on the server (so do 10 wrong PINs, or 7 days).
Everything is encrypted on this machine: the server never sees the data,
the filename, the key, or the PIN.

Usage:
  <cmd> | sharebuff             post piped text     (e.g. pbpaste | sharebuff)
  sharebuff --clip              post your clipboard (pbpaste / wl-paste / xclip / Get-Clipboard)
  sharebuff --file report.pdf   post a file, up to 20 MiB
  sharebuff --full --clip       57-char code with a 256-bit key (formal post-quantum bar)

Code size: --tiny (13 chars, 40-bit key; the default), --short (31, 128-bit),
--full (57, 256-bit, the formal post-quantum bar), or --auto (short for files
and text over 4 KiB). Set SHAREBUFF_TIER=tiny|short|full|auto to fix a default.

PIN: 3 dictionary words by default, each from a different language in random
order (e.g. basil-tundra-koala, ~38 bits); --pin-words 4 (~50) or 6, or
--pin-len N for N random characters. Expiry: 1 hour by default (--ttl).

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(flag.CommandLine.Output(), `
The recipient opens the URL (or opens the site and types the code) and enters
the PIN — no CLI needed on their side. Share the code and the PIN over two
different channels.
`)
}

func main() {
	envOr := os.Getenv("SHAREBUFF_URL")
	if envOr == "" {
		envOr = defaultServer
	}
	server := flag.String("server", envOr, "server base URL (or SHAREBUFF_URL env)")
	ttl := flag.Duration("ttl", time.Hour, "time-to-live (1m..168h)")
	pinWords := flag.Int("pin-words", 3, "PIN as N dictionary words, each from a different language (3 ≈ 38 bits, 4 ≈ 50)")
	pinLen := flag.Int("pin-len", 0, "instead of words: PIN as N random characters (min 6, 5 bits each)")
	clip := flag.Bool("clip", false, "read from the system clipboard even when stdin is piped")
	file := flag.String("file", "", "send this file instead of text (filename/MIME are encrypted too)")
	tiny := flag.Bool("tiny", false, "40-bit key: 13-char code, easy to type by hand; PIN-hardened (the default)")
	short := flag.Bool("short", false, "128-bit key: 31-char code")
	full := flag.Bool("full", false, "256-bit key: 57-char code, the formal post-quantum bar (docs/SECURITY.md)")
	auto := flag.Bool("auto", false, "pick the key size from the payload: tiny for small text, short for files or text over 4 KiB")
	noPreview := flag.Bool("no-preview", false, "do not echo a 40-char preview of the text to the terminal")
	flag.Usage = usage
	flag.Parse()

	if *server == "" {
		fatalf("no server configured; set SHAREBUFF_URL or pass --server https://…")
	}
	base := strings.TrimRight(*server, "/")
	ttlSec := int64(ttl.Seconds())
	if ttlSec < wire.MinTTLSeconds || ttlSec > wire.MaxTTLSeconds {
		fatalf("--ttl must be between 1m and 168h")
	}
	if *pinLen != 0 && *pinLen < 6 {
		fatalf("--pin-len must be at least 6")
	}
	if *pinWords < 2 {
		fatalf("--pin-words must be at least 2")
	}
	header, plain := readInput(*file, *clip)
	keyLen, escalated, err := chooseTier(*tiny, *short, *full, *auto, os.Getenv("SHAREBUFF_TIER"), header.T == "file", len(plain))
	if err != nil {
		fatalf("%v", err)
	}
	if len(plain) == 0 {
		fatalf("nothing to share (empty input)")
	}
	if len(plain) > wire.MaxPayload {
		fatalf("input exceeds the %d MiB limit", wire.MaxPayload>>20)
	}
	env, err := wire.EncodeEnvelope(header, plain)
	if err != nil {
		fatalf("packing envelope: %v", err)
	}

	key := wire.NewKey(keyLen)
	pin := newWordPIN(*pinWords)
	if *pinLen > 0 {
		pin = wire.NewPIN(*pinLen)
	}
	client := &http.Client{Timeout: 5 * time.Minute} // large uploads on slow links

	// The locator is public and random; on the (rare) collision the server
	// answers 409 and we simply pick another one and re-derive.
	var locator string
	var cr createResp
	for attempt := 0; ; attempt++ {
		locator = wire.NewLocator()
		encKey, authKey, err := wire.Derive(key, pin, locator)
		if err != nil {
			fatalf("deriving keys: %v", err)
		}
		blob, err := wire.Seal(encKey, locator, env)
		if err != nil {
			fatalf("encrypting: %v", err)
		}
		body, _ := json.Marshal(createReq{
			ID:         locator,
			CT:         base64.StdEncoding.EncodeToString(blob),
			Verifier:   wire.VerifierHex(authKey),
			TTLSeconds: ttlSec,
		})
		resp, err := client.Post(base+"/api/secrets", "application/json", bytes.NewReader(body))
		if err != nil {
			fatalf("posting secret: %v", err)
		}
		cr = createResp{}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&cr)
		resp.Body.Close()
		if resp.StatusCode == http.StatusCreated {
			break
		}
		if resp.StatusCode == http.StatusConflict && attempt < 5 {
			continue
		}
		if resp.StatusCode == http.StatusForbidden && len(cr.Reasons) > 0 {
			fatalf("%s — %s. This looks like a managed or corporate network, where sharing is not permitted (docs/SECURITY.md).", cr.Error, strings.Join(cr.Reasons, "; "))
		}
		fatalf("server returned %s %s", resp.Status, cr.Error)
	}

	code := wire.EncodeCode(locator, key)
	fmt.Printf("URL: %s/#%s\n", base, code)
	fmt.Printf("PIN: %s\n", pin)
	what := fmt.Sprintf("text (%s): %s", humanSize(len(plain)), preview(plain))
	if *noPreview {
		what = fmt.Sprintf("text (%s)", humanSize(len(plain)))
	}
	if header.T == "file" {
		what = fmt.Sprintf("file %q (%s, %s)", header.N, humanSize(len(plain)), header.M)
	}
	fmt.Fprintf(os.Stderr, "\nPosted %s\nEncrypted locally; the server cannot read it (not even the filename).\n", what)
	if escalated {
		fmt.Fprintf(os.Stderr, "Using a 128-bit key (31-char code) for this payload: %s. Pass --tiny to force the 13-char code.\n", escalated_reason(header.T == "file"))
	}
	fmt.Fprintf(os.Stderr, "Typing instead of pasting? Open %s and enter the code %s\n", base, code)
	fmt.Fprintf(os.Stderr, "Expires %s, on the first valid retrieve, or after %d wrong PINs.\n",
		time.Unix(cr.ExpiresAt, 0).Local().Format(time.RFC1123), wire.MaxAttempts)
	fmt.Fprintf(os.Stderr, "Share the code/URL and the PIN over two different channels.\n")
}

// AutoEscalateBytes is the text size above which the automatic tier choice
// prefers the 128-bit key: a leaked PIN plus a stolen ciphertext must not be
// enough to crack a large or file payload (THREAT-REVIEW T3).
const AutoEscalateBytes = 4096

func escalated_reason(isFile bool) string {
	if isFile {
		return "files always get it"
	}
	return fmt.Sprintf("text over %d bytes", AutoEscalateBytes)
}

// chooseTier resolves the key size: an explicit flag wins, then the
// SHAREBUFF_TIER environment default (tiny|short|full|auto); the built-in
// default is tiny. With --auto (or SHAREBUFF_TIER=auto) files and text larger
// than AutoEscalateBytes get the short (128-bit) key. The second result
// reports whether that escalation kicked in.
func chooseTier(tiny, short, full, auto bool, env string, isFile bool, size int) (int, bool, error) {
	n, err := chooseTierExplicit(tiny, short, full, env)
	if err != nil {
		return 0, false, err
	}
	if n > 0 {
		return n, false, nil
	}
	if (auto || n == -1) && (isFile || size > AutoEscalateBytes) {
		return wire.KeyLenShort, true, nil
	}
	return wire.KeyLenTiny, false, nil
}

// chooseTierExplicit returns 0 when neither a flag nor the environment picks
// a tier (i.e. the automatic rule applies).
func chooseTierExplicit(tiny, short, full bool, env string) (int, error) {
	n := 0
	for _, f := range []bool{tiny, short, full} {
		if f {
			n++
		}
	}
	if n > 1 {
		return 0, fmt.Errorf("--tiny, --short and --full are mutually exclusive")
	}
	switch {
	case tiny:
		return wire.KeyLenTiny, nil
	case short:
		return wire.KeyLenShort, nil
	case full:
		return wire.KeyLenFull, nil
	}
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "":
		return 0, nil
	case "auto":
		return -1, nil
	case "tiny":
		return wire.KeyLenTiny, nil
	case "full":
		return wire.KeyLenFull, nil
	case "short":
		return wire.KeyLenShort, nil
	}
	return 0, fmt.Errorf("SHAREBUFF_TIER must be tiny, short, full or auto (got %q)", env)
}

// humanSize renders a byte count as B / KiB / MiB.
func humanSize(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
}

// preview returns a short, single-line glimpse of text (first 40 runes,
// control characters collapsed to spaces, "…" when truncated) so the user
// can confirm what was posted without the whole payload hitting the terminal.
func preview(b []byte) string {
	const max = 40
	runes := []rune(strings.ToValidUTF8(string(b), "�"))
	truncated := len(runes) > max
	if truncated {
		runes = runes[:max]
	}
	for i, r := range runes {
		if r < 0x20 || r == 0x7f {
			runes[i] = ' '
		}
	}
	s := strings.TrimSpace(string(runes))
	if truncated {
		s += "…"
	}
	return fmt.Sprintf("%q", s)
}
