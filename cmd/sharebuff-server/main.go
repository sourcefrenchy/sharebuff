// sharebuff-server is the self-hosted fallback: the same HTTP API as the
// Cloudflare Worker (docs/SPEC.md), backed by an in-memory store, serving the
// same embedded static retrieve page. Run it behind any TLS proxy.
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/sourcefrenchy/sharebuff/internal/wire"
	"github.com/sourcefrenchy/sharebuff/web"
)

var (
	idRe  = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{16,32}$`)
	hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type record struct {
	ct            []byte
	verifier      [32]byte
	attempts      int
	expiresAt     time.Time
	nextAllowedAt time.Time
	gone          string // "", "claimed", "burned"
}

type store struct {
	mu     sync.Mutex
	m      map[string]*record
	maxTTL time.Duration
	now    func() time.Time
}

// cooldown returns the wait imposed after the n-th counted wrong attempt.
func cooldown(attempts int) time.Duration {
	if attempts >= 30 || 1<<attempts > wire.CooldownMaxSeconds {
		return wire.CooldownMaxSeconds * time.Second
	}
	return time.Duration(1<<attempts) * time.Second
}

func (s *store) janitor() {
	for range time.Tick(time.Minute) {
		now := s.now()
		s.mu.Lock()
		for id, r := range s.m {
			if now.After(r.expiresAt) {
				delete(s.m, id)
			}
		}
		s.mu.Unlock()
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *store) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         string `json:"id"`
		CT         string `json:"ct"`
		Verifier   string `json:"verifier"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 128*1024))
	if err != nil || json.Unmarshal(body, &req) != nil {
		errJSON(w, http.StatusBadRequest, "malformed body")
		return
	}
	if !idRe.MatchString(req.ID) || !hexRe.MatchString(req.Verifier) {
		errJSON(w, http.StatusBadRequest, "malformed id or verifier")
		return
	}
	if req.TTLSeconds == 0 {
		req.TTLSeconds = wire.DefaultTTLSeconds
	}
	if req.TTLSeconds < wire.MinTTLSeconds || req.TTLSeconds > int64(s.maxTTL.Seconds()) {
		errJSON(w, http.StatusBadRequest, "ttl out of range")
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.CT)
	if err != nil || len(ct) < wire.NonceLen+16 {
		errJSON(w, http.StatusBadRequest, "malformed ciphertext")
		return
	}
	if len(ct) > wire.MaxPlaintext+wire.NonceLen+16 {
		errJSON(w, http.StatusRequestEntityTooLarge, "ciphertext too large")
		return
	}
	verifier, _ := hex.DecodeString(req.Verifier)
	rec := &record{ct: ct, expiresAt: s.now().Add(time.Duration(req.TTLSeconds) * time.Second)}
	copy(rec.verifier[:], verifier)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[req.ID]; exists {
		errJSON(w, http.StatusConflict, "id already exists")
		return
	}
	s.m[req.ID] = rec
	writeJSON(w, http.StatusCreated, map[string]int64{"expires_at": rec.expiresAt.Unix()})
}

func (s *store) claim(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Auth string `json:"auth"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil || json.Unmarshal(body, &req) != nil || !idRe.MatchString(id) || !hexRe.MatchString(req.Auth) {
		errJSON(w, http.StatusBadRequest, "malformed request")
		return
	}
	authBytes, _ := hex.DecodeString(req.Auth)
	sum := sha256.Sum256(authBytes)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	rec, ok := s.m[id]
	if !ok || now.After(rec.expiresAt) {
		delete(s.m, id)
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	if rec.gone != "" {
		writeJSON(w, http.StatusGone, map[string]string{"reason": rec.gone})
		return
	}
	// Cooldown gate: rejected before the proof is examined, and NOT counted —
	// hammering can neither brute-force the PIN nor burn the secret.
	if now.Before(rec.nextAllowedAt) {
		retry := int64(rec.nextAllowedAt.Sub(now).Seconds()) + 1
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retry))
		writeJSON(w, http.StatusTooManyRequests, map[string]int64{"retry_after_seconds": retry})
		return
	}
	if subtle.ConstantTimeCompare(sum[:], rec.verifier[:]) != 1 {
		rec.attempts++
		rec.nextAllowedAt = now.Add(cooldown(rec.attempts))
		if rec.attempts >= wire.MaxAttempts {
			// Burn: keep only a tombstone until the original expiry.
			s.m[id] = &record{gone: "burned", expiresAt: rec.expiresAt}
			writeJSON(w, http.StatusGone, map[string]string{"reason": "burned"})
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]int{"attempts_left": wire.MaxAttempts - rec.attempts})
		return
	}
	// Valid claim: destroy before responding; exactly one caller can get here.
	ct := rec.ct
	s.m[id] = &record{gone: "claimed", expiresAt: rec.expiresAt}
	writeJSON(w, http.StatusOK, map[string]string{"ct": base64.StdEncoding.EncodeToString(ct)})
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(web.FS, ".")
	if err != nil {
		log.Fatal(err)
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	})
}

func newMux(s *store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/secrets", s.create)
	mux.HandleFunc("POST /api/secrets/{id}/claim", s.claim)
	mux.Handle("GET /", staticHandler())
	return mux
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8091", "listen address")
	maxTTL := flag.Duration("max-ttl", 168*time.Hour, "maximum secret TTL")
	flag.Parse()

	s := &store{m: make(map[string]*record), maxTTL: *maxTTL, now: time.Now}
	go s.janitor()
	mux := newMux(s)

	log.Printf("sharebuff-server listening on %s (max TTL %s)", *addr, *maxTTL)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
