package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// TestOpenJSVectors decrypts secrets that were encrypted by the browser
// implementation (web/crypto.js, via tests/gen-js-vectors.mjs). Together with
// tests/parity.mjs (Go-encrypted → JS-decrypted) this closes the loop in both
// directions.
func TestOpenJSVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/js_vectors.json")
	if err != nil {
		t.Skip("testdata/js_vectors.json missing; run: make jsvectors")
	}
	var vecs []struct {
		Code    string `json:"code"`
		PIN     string `json:"pin"`
		Header  string `json:"header_json"`
		Payload string `json:"payload_b64"`
		CT      string `json:"ct_b64"`
	}
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatal(err)
	}
	if len(vecs) == 0 {
		t.Fatal("no vectors")
	}
	for i, v := range vecs {
		locator, key, err := DecodeCode(v.Code)
		if err != nil {
			t.Fatalf("vector %d: decode code: %v", i, err)
		}
		encKey, _, err := Derive(key, v.PIN, locator)
		if err != nil {
			t.Fatal(err)
		}
		blob, _ := base64.StdEncoding.DecodeString(v.CT)
		env, err := Open(encKey, locator, blob)
		if err != nil {
			t.Fatalf("vector %d: Go could not open browser-encrypted blob: %v", i, err)
		}
		h, payload, err := DecodeEnvelope(env)
		if err != nil {
			t.Fatalf("vector %d: envelope: %v", i, err)
		}
		var wantH Header
		_ = json.Unmarshal([]byte(v.Header), &wantH)
		wantP, _ := base64.StdEncoding.DecodeString(v.Payload)
		if h != wantH || !bytes.Equal(payload, wantP) {
			t.Fatalf("vector %d: header/payload mismatch: %+v", i, h)
		}
	}
}
