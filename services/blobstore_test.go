package services

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBlobStoreDisabledWithoutToken(t *testing.T) {
	os.Unsetenv("BLOB_READ_WRITE_TOKEN")
	store := NewBlobStore()
	if store.Enabled() {
		t.Fatal("store should be disabled without BLOB_READ_WRITE_TOKEN")
	}
	if _, _, err := store.ClientToken("uploads/x.zip"); err == nil {
		t.Fatal("ClientToken should fail when the store is disabled")
	}
	if _, err := store.DownloadTo("https://x.blob.vercel-storage.com/a.zip", "/tmp/a.zip"); err == nil {
		t.Fatal("DownloadTo should fail when the store is disabled")
	}
}

func TestBlobStoreClientTokenFormat(t *testing.T) {
	token := "vercel_blob_rw_abcdef123456_secret"
	t.Setenv("BLOB_READ_WRITE_TOKEN", token)
	store := NewBlobStore()
	if !store.Enabled() {
		t.Fatal("store should be enabled with a read-write token")
	}
	if store.StoreID() != "abcdef123456" {
		t.Fatalf("unexpected store id: %s", store.StoreID())
	}

	pathname := "uploads/12345_my-project.zip"
	clientToken, expires, err := store.ClientToken(pathname)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(clientToken, "vercel_blob_client_abcdef123456_") {
		t.Fatalf("unexpected client token prefix: %s", clientToken)
	}
	if !expires.After(time.Now()) {
		t.Fatal("token should expire in the future")
	}

	// The token is vercel_blob_client_{storeId}_{base64(signature.payload)}
	// where the signature is the hex HMAC-SHA256 of the base64 payload, keyed
	// by the read-write token — the exact format the official SDK produces.
	inner := strings.TrimPrefix(clientToken, "vercel_blob_client_abcdef123456_")
	decoded, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		t.Fatalf("inner token is not base64: %v", err)
	}
	parts := strings.SplitN(string(decoded), ".", 2)
	if len(parts) != 2 {
		t.Fatalf("inner token has no signature separator: %s", string(decoded))
	}
	sig, payload := parts[0], parts[1]

	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(payload))
	if !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		t.Fatal("signature does not match HMAC-SHA256 of the payload")
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("payload is not base64: %v", err)
	}
	var p struct {
		Pathname        string `json:"pathname"`
		AddRandomSuffix bool   `json:"addRandomSuffix"`
		ValidUntil      int64  `json:"validUntil"`
	}
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if p.Pathname != pathname {
		t.Fatalf("payload pathname = %q, want %q", p.Pathname, pathname)
	}
	if p.AddRandomSuffix {
		t.Fatal("payload should disable the random suffix")
	}
	if p.ValidUntil <= time.Now().UnixMilli() {
		t.Fatal("payload validUntil should be in the future")
	}
}

func TestBlobStoreParseStoreID(t *testing.T) {
	// The store id is the 4th underscore-separated segment, exactly like the
	// official SDK (token.split("_")[3]).
	if got := parseStoreID("vercel_blob_rw_abc123_deadbeef"); got != "abc123" {
		t.Fatalf("expected store id abc123, got %q", got)
	}
	if got := parseStoreID("vercel_blob_rw_myStoreId"); got != "myStoreId" {
		t.Fatalf("expected store id myStoreId, got %q", got)
	}
	if got := parseStoreID("garbage-token"); got != "" {
		t.Fatalf("expected empty store id for garbage token, got %q", got)
	}
	if got := parseStoreID("vercel_blob_rw_"); got != "" {
		t.Fatalf("expected empty store id for a truncated token, got %q", got)
	}
}

func TestBlobStoreUploadURL(t *testing.T) {
	t.Setenv("BLOB_READ_WRITE_TOKEN", "vercel_blob_rw_store123_secret")
	store := NewBlobStore()
	uploadURL, blobURL := store.UploadURL("uploads/a.zip")
	if !strings.HasPrefix(uploadURL, "https://vercel.com/api/blob/?pathname=uploads%2Fa.zip") {
		t.Fatalf("unexpected upload url: %s", uploadURL)
	}
	if blobURL != "https://store123.private.blob.vercel-storage.com/uploads/a.zip" {
		t.Fatalf("unexpected blob url: %s", blobURL)
	}
}

// rewriteTransport sends every request to the test server regardless of the
// URL's host, so the tests can exercise the real Vercel-Blob-shaped URLs
// (which must pass DownloadTo's host validation) against a local server.
type rewriteTransport struct {
	target string // e.g. "127.0.0.1:PORT"
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.target
	return http.DefaultTransport.RoundTrip(req)
}

// TestBlobStoreDownloadTo verifies the download wire protocol: the blob URL is
// fetched directly (the SDK's get() method) with the read-write token in the
// Authorization header and the body streamed to disk.
func TestBlobStoreDownloadTo(t *testing.T) {
	payload := []byte("PK\x03\x04 fake zip payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer vercel_blob_rw_store123_secret" {
			t.Errorf("missing/incorrect bearer auth: %q", got)
		}
		w.Write(payload)
	}))
	defer srv.Close()

	t.Setenv("BLOB_READ_WRITE_TOKEN", "vercel_blob_rw_store123_secret")
	store := NewBlobStore()
	store.client = &http.Client{Transport: rewriteTransport{target: strings.TrimPrefix(srv.URL, "http://")}}
	dest := filepath.Join(t.TempDir(), "dl.zip")
	n, err := store.DownloadTo("https://store123.private.blob.vercel-storage.com/uploads/a.zip", dest)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("downloaded %d bytes, want %d", n, len(payload))
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("downloaded content does not match the served payload")
	}
}

// TestBlobStoreDownloadToRejectsForeignHost verifies the security guard: a
// client-supplied blobUrl pointing outside Vercel Blob is rejected BEFORE any
// request is made, so the read-write token can never be exfiltrated to an
// attacker-controlled server.
func TestBlobStoreDownloadToRejectsForeignHost(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Write([]byte("you should never see me"))
	}))
	defer srv.Close()

	t.Setenv("BLOB_READ_WRITE_TOKEN", "vercel_blob_rw_store123_secret")
	store := NewBlobStore()
	if _, err := store.DownloadTo(srv.URL+"/collect", filepath.Join(t.TempDir(), "x.zip")); err == nil {
		t.Fatal("expected the foreign-host URL to be rejected")
	}
	if hit {
		t.Fatal("no request should be made to a non-Blob host")
	}
}

// TestBlobStoreDownloadToNotFound verifies a missing blob surfaces a clear
// error instead of a partial/corrupt file.
func TestBlobStoreDownloadToNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	t.Setenv("BLOB_READ_WRITE_TOKEN", "vercel_blob_rw_store123_secret")
	store := NewBlobStore()
	store.client = &http.Client{Transport: rewriteTransport{target: strings.TrimPrefix(srv.URL, "http://")}}
	if _, err := store.DownloadTo("https://store123.private.blob.vercel-storage.com/gone.zip", filepath.Join(t.TempDir(), "x.zip")); err == nil {
		t.Fatal("expected an error for a missing blob")
	}
}

// TestBlobStoreDelete verifies the delete wire protocol: POST to {api}/delete
// with the JSON body {"urls":[...]} and the read-write token.
func TestBlobStoreDelete(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("delete should POST, got %s", r.Method)
		}
		if r.URL.Path != "/delete" {
			t.Errorf("delete should hit /delete, got %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer vercel_blob_rw_store123_secret" {
			t.Errorf("missing/incorrect bearer auth: %q", got)
		}
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("BLOB_READ_WRITE_TOKEN", "vercel_blob_rw_store123_secret")
	store := NewBlobStore()
	store.apiBase = srv.URL
	if err := store.Delete("https://store123.private.blob.vercel-storage.com/uploads/a.zip"); err != nil {
		t.Fatal(err)
	}

	var body struct {
		URLs []string `json:"urls"`
	}
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("delete body is not JSON: %v", err)
	}
	if len(body.URLs) != 1 || body.URLs[0] != "https://store123.private.blob.vercel-storage.com/uploads/a.zip" {
		t.Fatalf("unexpected delete body urls: %+v", body.URLs)
	}
}
