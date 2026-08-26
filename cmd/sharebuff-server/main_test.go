package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sourcefrenchy/sharebuff/internal/wire"
)

type secret struct {
	id, pin  string
	authHex  string
	verifier string
	ct       string
}

func makeSecret(t *testing.T) secret {
	t.Helper()
	p := wire.NewParams()
	pin := wire.NewPIN(6)
	encKey, authKey, err := wire.Derive(p.Key, pin, p.Salt)
	if err != nil {
		t.Fatal(err)
	}
	id := wire.Base58Encode(p.ID)
	blob, err := wire.Seal(encKey, id, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	return secret{
		id:       id,
		pin:      pin,
		authHex:  fmt.Sprintf("%x", authKey),
		verifier: wire.VerifierHex(authKey),
		ct:       base64.StdEncoding.EncodeToString(blob),
	}
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := &store{m: make(map[string]*record), maxTTL: 168 * time.Hour}
	ts := httptest.NewServer(newMux(s))
	t.Cleanup(ts.Close)
	return ts
}

func post(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func create(t *testing.T, ts *httptest.Server, sec secret) {
	t.Helper()
	code, _ := post(t, ts.URL+"/api/secrets", map[string]any{
		"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600,
	})
	if code != 201 {
		t.Fatalf("create: got %d", code)
	}
}

func TestClaimLifecycle(t *testing.T) {
	ts := newTestServer(t)
	sec := makeSecret(t)
	create(t, ts, sec)

	// Duplicate id rejected.
	if code, _ := post(t, ts.URL+"/api/secrets", map[string]any{
		"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600,
	}); code != 409 {
		t.Fatalf("duplicate create: got %d", code)
	}

	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"
	badAuth := "00" + sec.authHex[2:]

	// Wrong proofs do NOT burn; attempts_left counts down.
	for i := 1; i <= 2; i++ {
		code, body := post(t, ts.URL+"/api/secrets/"+sec.id+"/claim", map[string]string{"auth": badAuth})
		if code != 403 || int(body["attempts_left"].(float64)) != wire.MaxAttempts-i {
			t.Fatalf("bad claim %d: code=%d body=%v", i, code, body)
		}
	}

	// Valid claim returns the ciphertext and destroys the record.
	code, body := post(t, claimURL, map[string]string{"auth": sec.authHex})
	if code != 200 || body["ct"].(string) != sec.ct {
		t.Fatalf("valid claim: code=%d", code)
	}

	// Second claim (even valid) hits the tombstone.
	if code, body := post(t, claimURL, map[string]string{"auth": sec.authHex}); code != 410 || body["reason"] != "claimed" {
		t.Fatalf("post-claim: code=%d body=%v", code, body)
	}
	// Unknown id is 404.
	if code, _ := post(t, ts.URL+"/api/secrets/2NEpo7TZRRrLZSi2U/claim", map[string]string{"auth": sec.authHex}); code != 404 {
		t.Fatalf("unknown id: code=%d", code)
	}
}

func TestBurnAfterMaxAttempts(t *testing.T) {
	ts := newTestServer(t)
	sec := makeSecret(t)
	create(t, ts, sec)
	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"
	badAuth := "00" + sec.authHex[2:]

	for i := 1; i < wire.MaxAttempts; i++ {
		if code, _ := post(t, claimURL, map[string]string{"auth": badAuth}); code != 403 {
			t.Fatalf("attempt %d: code=%d", i, code)
		}
	}
	if code, body := post(t, claimURL, map[string]string{"auth": badAuth}); code != 410 || body["reason"] != "burned" {
		t.Fatalf("burning attempt: code=%d body=%v", code, body)
	}
	// The real PIN is now useless: the ciphertext is gone.
	if code, body := post(t, claimURL, map[string]string{"auth": sec.authHex}); code != 410 || body["reason"] != "burned" {
		t.Fatalf("post-burn valid claim: code=%d body=%v", code, body)
	}
}

// TestConcurrentClaims verifies exactly one winner under parallel valid claims.
func TestConcurrentClaims(t *testing.T) {
	ts := newTestServer(t)
	sec := makeSecret(t)
	create(t, ts, sec)
	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"

	const n = 16
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _ = post(t, claimURL, map[string]string{"auth": sec.authHex})
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, c := range codes {
		switch c {
		case 200:
			wins++
		case 410:
		default:
			t.Fatalf("unexpected code %d", c)
		}
	}
	if wins != 1 {
		t.Fatalf("expected exactly 1 successful claim, got %d", wins)
	}
}

func TestValidation(t *testing.T) {
	ts := newTestServer(t)
	sec := makeSecret(t)
	// Oversized ciphertext.
	big := base64.StdEncoding.EncodeToString(make([]byte, wire.MaxPlaintext+wire.NonceLen+17))
	if code, _ := post(t, ts.URL+"/api/secrets", map[string]any{
		"id": sec.id, "ct": big, "verifier": sec.verifier, "ttl_seconds": 3600,
	}); code != 413 {
		t.Fatalf("oversize: code=%d", code)
	}
	// Bad ttl / id / verifier.
	for _, req := range []map[string]any{
		{"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 5},
		{"id": "bad!id", "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600},
		{"id": sec.id, "ct": sec.ct, "verifier": "xyz", "ttl_seconds": 3600},
	} {
		if code, _ := post(t, ts.URL+"/api/secrets", req); code != 400 {
			t.Fatalf("expected 400 for %v, got %d", req, code)
		}
	}
}

func TestStaticPageHeaders(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /: %d", resp.StatusCode)
	}
	for _, h := range []string{"Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "Strict-Transport-Security"} {
		if resp.Header.Get(h) == "" {
			t.Fatalf("missing header %s", h)
		}
	}
}
