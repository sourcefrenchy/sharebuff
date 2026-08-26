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
	"net/http"
	"os"
	"os/exec"
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

func readInput(forceClip bool) []byte {
	stat, err := os.Stdin.Stat()
	piped := err == nil && stat.Mode()&os.ModeCharDevice == 0
	if piped && !forceClip {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, wire.MaxPlaintext+1))
		if err != nil {
			fatalf("reading stdin: %v", err)
		}
		return data
	}
	if runtime.GOOS != "darwin" {
		fatalf("no piped stdin and clipboard capture is only wired for macOS; pipe the data instead: <cmd> | sharebuff")
	}
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		fatalf("pbpaste: %v", err)
	}
	return out
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
	clip := flag.Bool("clip", false, "read from the macOS clipboard even when stdin is piped")
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

	plain := readInput(*clip)
	if len(plain) == 0 {
		fatalf("nothing to share (empty input)")
	}
	if len(plain) > wire.MaxPlaintext {
		fatalf("input exceeds the %d KiB limit", wire.MaxPlaintext/1024)
	}

	p := wire.NewParams()
	pin := wire.NewPIN(*pinLen)
	encKey, authKey, err := wire.Derive(p.Key, pin, p.Salt)
	if err != nil {
		fatalf("deriving keys: %v", err)
	}
	id := wire.Base58Encode(p.ID)
	blob, err := wire.Seal(encKey, id, plain)
	if err != nil {
		fatalf("encrypting: %v", err)
	}

	body, _ := json.Marshal(createReq{
		ID:         id,
		CT:         base64.StdEncoding.EncodeToString(blob),
		Verifier:   wire.VerifierHex(authKey),
		TTLSeconds: ttlSec,
	})
	client := &http.Client{Timeout: 30 * time.Second}
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
	fmt.Fprintf(os.Stderr, "\nOne-shot secret posted (%d bytes encrypted locally; the server cannot read it).\n", len(plain))
	fmt.Fprintf(os.Stderr, "Expires %s, on the first valid retrieve, or after %d wrong PINs.\n",
		time.Unix(cr.ExpiresAt, 0).Local().Format(time.RFC1123), wire.MaxAttempts)
	fmt.Fprintf(os.Stderr, "Share the URL and the PIN over two different channels.\n")
}
