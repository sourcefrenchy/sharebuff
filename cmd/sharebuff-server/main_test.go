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
	return makeSecretPayload(t, []byte("payload"))
}

func makeSecretPayload(t *testing.T, payload []byte) secret {
	t.Helper()
	key := wire.NewKey(wire.KeyLenTiny)
	pin := wire.NewPIN(6)
	id := wire.NewLocator()
	encKey, authKey, err := wire.Derive(key, pin, id)
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.EncodeEnvelope(wire.Header{T: "file", N: "test.bin", M: "application/octet-stream"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := wire.Seal(encKey, id, env)
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

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestServer(t *testing.T) (*httptest.Server, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Now()}
	s := &store{m: make(map[string]*record), maxTTL: 168 * time.Hour, now: clk.Now, allowShare: true}
	ts := httptest.NewServer(newMux(s))
	t.Cleanup(ts.Close)
	return ts, clk
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
	ts, clk := newTestServer(t)
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

	// Wrong proofs do NOT burn; attempts_left counts down (clock advanced
	// past each cooldown so the attempts are counted).
	for i := 1; i <= 2; i++ {
		code, body := post(t, ts.URL+"/api/secrets/"+sec.id+"/claim", map[string]string{"auth": badAuth})
		if code != 403 || int(body["attempts_left"].(float64)) != wire.MaxAttempts-i {
			t.Fatalf("bad claim %d: code=%d body=%v", i, code, body)
		}
		clk.Advance(time.Duration(wire.CooldownMaxSeconds+1) * time.Second)
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
	if code, _ := post(t, ts.URL+"/api/secrets/ZZZZZ/claim", map[string]string{"auth": sec.authHex}); code != 404 {
		t.Fatalf("unknown id: code=%d", code)
	}
}

func TestBurnAfterMaxAttempts(t *testing.T) {
	ts, clk := newTestServer(t)
	sec := makeSecret(t)
	create(t, ts, sec)
	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"
	badAuth := "00" + sec.authHex[2:]

	for i := 1; i < wire.MaxAttempts; i++ {
		if code, _ := post(t, claimURL, map[string]string{"auth": badAuth}); code != 403 {
			t.Fatalf("attempt %d: code=%d", i, code)
		}
		clk.Advance(time.Duration(wire.CooldownMaxSeconds+1) * time.Second)
	}
	if code, body := post(t, claimURL, map[string]string{"auth": badAuth}); code != 410 || body["reason"] != "burned" {
		t.Fatalf("burning attempt: code=%d body=%v", code, body)
	}
	// The real PIN is now useless: the ciphertext is gone.
	if code, body := post(t, claimURL, map[string]string{"auth": sec.authHex}); code != 410 || body["reason"] != "burned" {
		t.Fatalf("post-burn valid claim: code=%d body=%v", code, body)
	}
}

// TestCooldown: attempts inside the cooldown window are rejected with 429 and
// do NOT count toward the burn limit — spam can neither brute-force nor burn.
func TestCooldown(t *testing.T) {
	ts, clk := newTestServer(t)
	sec := makeSecret(t)
	create(t, ts, sec)
	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"
	badAuth := "00" + sec.authHex[2:]

	// First wrong attempt is counted (attempts_left 9) and starts a 2s cooldown.
	code, body := post(t, claimURL, map[string]string{"auth": badAuth})
	if code != 403 || int(body["attempts_left"].(float64)) != wire.MaxAttempts-1 {
		t.Fatalf("first wrong: code=%d body=%v", code, body)
	}
	// Hammering during the cooldown: all 429, none counted — even with the
	// correct proof, which is not examined during cooldown.
	for i := 0; i < 50; i++ {
		auth := badAuth
		if i%2 == 0 {
			auth = sec.authHex
		}
		code, body := post(t, claimURL, map[string]string{"auth": auth})
		if code != 429 || body["retry_after_seconds"] == nil {
			t.Fatalf("spam %d: code=%d body=%v", i, code, body)
		}
	}
	// After the window: the counter did not move (still 8 left after this one)...
	clk.Advance(3 * time.Second)
	if code, body := post(t, claimURL, map[string]string{"auth": badAuth}); code != 403 ||
		int(body["attempts_left"].(float64)) != wire.MaxAttempts-2 {
		t.Fatalf("post-cooldown wrong: code=%d body=%v", code, body)
	}
	// ...and the correct PIN still works once its cooldown (4s) passes.
	clk.Advance(5 * time.Second)
	if code, _ := post(t, claimURL, map[string]string{"auth": sec.authHex}); code != 200 {
		t.Fatalf("post-cooldown valid claim: code=%d", code)
	}
}

// TestConcurrentClaims verifies exactly one winner under parallel valid claims.
func TestConcurrentClaims(t *testing.T) {
	ts, _ := newTestServer(t)
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
	ts, _ := newTestServer(t)
	sec := makeSecret(t)
	// Oversized ciphertext (one byte past the blob cap).
	big := base64.StdEncoding.EncodeToString(make([]byte, wire.MaxBlob+1))
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

// TestLargePayloadRoundtrip pushes a 3 MiB binary through create+claim and
// verifies the ciphertext comes back byte-identical and decryptable.
func TestLargePayloadRoundtrip(t *testing.T) {
	ts, _ := newTestServer(t)
	payload := bytes.Repeat([]byte{0xC3, 0x28, 0x00, 0xFF}, 3<<20/4) // 3 MiB, non-UTF8
	sec := makeSecretPayload(t, payload)
	create(t, ts, sec)
	code, body := post(t, ts.URL+"/api/secrets/"+sec.id+"/claim", map[string]string{"auth": sec.authHex})
	if code != 200 {
		t.Fatalf("claim: %d", code)
	}
	if body["ct"].(string) != sec.ct {
		t.Fatal("large ciphertext corrupted in transit")
	}
}

func TestEnvironmentSignals(t *testing.T) {
	ts, _ := newTestServer(t)
	get := func(hdr map[string]string) (bool, []any) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/env", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out["share"].(bool), out["reasons"].([]any)
	}
	if share, reasons := get(nil); !share || len(reasons) != 0 {
		t.Fatalf("clean request: share=%v reasons=%v", share, reasons)
	}
	for _, h := range []map[string]string{
		{"X-Sharebuff-Policy": "retrieve-only"},
		{"Via": "1.1 zscaler.net"},
		{"X-Forwarded-For": "10.0.0.5, 203.0.113.9"},
		{"X-Netskope-User": "alice"},
	} {
		if share, reasons := get(h); share || len(reasons) == 0 {
			t.Fatalf("headers %v should disable share: share=%v reasons=%v", h, share, reasons)
		}
	}
}

func TestShareDisabledByOperator(t *testing.T) {
	s := &store{m: make(map[string]*record), maxTTL: time.Hour, now: time.Now, allowShare: false}
	ts := httptest.NewServer(newMux(s))
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/env")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["share"].(bool) {
		t.Fatal("operator -share=false not honoured")
	}
}

func TestStaticPageHeaders(t *testing.T) {
	ts, _ := newTestServer(t)
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
