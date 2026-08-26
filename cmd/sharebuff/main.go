// sharebuff posts an end-to-end-encrypted, one-shot secret from stdin or the
// macOS clipboard and prints the retrieve URL + PIN. See docs/SPEC.md.
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
	ExpiresAt int64  `json:"expires_at"`
	Error     string `json:"error"`
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
const defaultServer = "https://sharebuff.sharebuff-worker.workers.dev"

func main() {
	envOr := os.Getenv("SHAREBUFF_URL")
	if envOr == "" {
		envOr = defaultServer
	}
	server := flag.String("server", envOr, "server base URL (or SHAREBUFF_URL env)")
	ttl := flag.Duration("ttl", 168*time.Hour, "time-to-live (1m..168h)")
	pinLen := flag.Int("pin-len", 6, "PIN length (min 6)")
	clip := flag.Bool("clip", false, "read from the system clipboard even when stdin is piped")
	file := flag.String("file", "", "send this file instead of text (filename/MIME are encrypted too)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `sharebuff — one-shot end-to-end-encrypted drop (text & files)

Post a secret and get back a URL plus a one-time PIN. The first valid
retrieve destroys it on the server (so do 10 wrong PINs, or 7 days).
Everything is encrypted on this machine: the server never sees the data,
the filename, or the PIN.

Usage:
  <cmd> | sharebuff             post piped text     (e.g. pbpaste | sharebuff)
  sharebuff --clip              post your clipboard (pbpaste / wl-paste / xclip / Get-Clipboard)
  sharebuff --file report.pdf   post a file, up to 20 MiB

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), `
The recipient just opens the URL in a browser and types the PIN — no CLI
needed on their side. Share the URL and the PIN over two different channels.
`)
	}
	flag.Parse()

	if *server == "" {
		fatalf("no server configured; set SHAREBUFF_URL or pass --server https://…")
	}
	base := strings.TrimRight(*server, "/")
	ttlSec := int64(ttl.Seconds())
	if ttlSec < wire.MinTTLSeconds || ttlSec > wire.MaxTTLSeconds {
		fatalf("--ttl must be between 1m and 168h")
	}
	if *pinLen < 6 {
		fatalf("--pin-len must be at least 6")
	}

	header, plain := readInput(*file, *clip)
	if len(plain) == 0 {
		fatalf("nothing to share (empty input)")
	}
	if len(plain) > wire.MaxPayload {
		fatalf("input exceeds the %d MiB limit", wire.MaxPayload>>20)
	}

	p := wire.NewParams()
	pin := wire.NewPIN(*pinLen)
	encKey, authKey, err := wire.Derive(p.Key, pin, p.Salt)
	if err != nil {
		fatalf("deriving keys: %v", err)
	}
	env, err := wire.EncodeEnvelope(header, plain)
	if err != nil {
		fatalf("packing envelope: %v", err)
	}
	id := wire.Base58Encode(p.ID)
	blob, err := wire.Seal(encKey, id, env)
	if err != nil {
		fatalf("encrypting: %v", err)
	}

	body, _ := json.Marshal(createReq{
		ID:         id,
		CT:         base64.StdEncoding.EncodeToString(blob),
		Verifier:   wire.VerifierHex(authKey),
		TTLSeconds: ttlSec,
	})
	client := &http.Client{Timeout: 5 * time.Minute} // large uploads on slow links
	resp, err := client.Post(base+"/api/secrets", "application/json", bytes.NewReader(body))
	if err != nil {
		fatalf("posting secret: %v", err)
	}
	defer resp.Body.Close()
	var cr createResp
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&cr)
	if resp.StatusCode != http.StatusCreated {
		fatalf("server returned %s %s", resp.Status, cr.Error)
	}

	fmt.Printf("URL: %s/#%s\n", base, wire.Fragment(p))
	fmt.Printf("PIN: %s\n", pin)
	what := fmt.Sprintf("%d bytes of text", len(plain))
	if header.T == "file" {
		what = fmt.Sprintf("file %q (%d bytes, %s)", header.N, len(plain), header.M)
	}
	fmt.Fprintf(os.Stderr, "\nOne-shot secret posted: %s, encrypted locally; the server cannot read it (not even the filename).\n", what)
	fmt.Fprintf(os.Stderr, "Expires %s, on the first valid retrieve, or after %d wrong PINs.\n",
		time.Unix(cr.ExpiresAt, 0).Local().Format(time.RFC1123), wire.MaxAttempts)
	fmt.Fprintf(os.Stderr, "Share the URL and the PIN over two different channels.\n")
}
