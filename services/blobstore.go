package services

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxBlobBytes mirrors the direct multipart upload ceiling (handlers' 5 GB
// safety net): both the client-token constraint and the server-side download
// cap use it, so the Blob path can never accept or fetch more than the direct
// path would.
const maxBlobBytes int64 = 5 << 30

// BlobStore is a thin, SDK-free client for Vercel Blob's *client upload*
// protocol. The browser PUTs the uploaded file directly to Vercel Blob (which
// is NOT a Vercel Function, so the platform's 4.5 MB request-body limit does
// not apply), then the Go backend downloads the stored blob and runs the
// analysis pipeline on it.
//
// The protocol mirrors exactly what the official @vercel/blob SDK does:
//
//  1. The server mints a short-lived *client token* from the read-write token:
//     `vercel_blob_client_{storeId}_{base64(hmacHex.payloadBase64)}` where the
//     payload is the JSON `{pathname, addRandomSuffix, validUntil, ...}` and
//     the HMAC key is the read-write token itself.
//  2. The browser PUTs the raw file bytes to `{api}/?pathname=...` with
//     `Authorization: Bearer {clientToken}` plus the x-api-* / x-vercel-blob-*
//     headers (the file never transits a function, so size is unlimited).
//  3. The backend downloads the blob DIRECTLY from its blob URL with the
//     read-write token in the Authorization header (the SDK's get() wire
//     protocol) and streams it to disk. Cleanup posts to the /delete API.
//
// When no BLOB_READ_WRITE_TOKEN is configured the store reports itself as
// disabled and the app falls back to the classic direct multipart upload
// (which is fine below the platform limit and on non-Vercel hosts).
type BlobStore struct {
	// token is the long-lived read-write token from the Vercel dashboard
	// (BLOB_READ_WRITE_TOKEN). Its shape is vercel_blob_rw_{storeId}_{secret}.
	token string
	// storeID is parsed out of the read-write token.
	storeID string
	// access is the blob store access mode used for uploads ("private" by
	// default — only the backend can download the file; override with
	// BLOB_ACCESS="public" for public stores).
	access string
	// apiBase is the Blob API root (https://vercel.com/api/blob by default;
	// VERCEL_BLOB_API_URL overrides, matching the SDK).
	apiBase string
	// apiVersion is the x-api-version header (the SDK currently pins v12;
	// BLOB_API_VERSION can override when Vercel bumps it).
	apiVersion string
	// tokenTTL bounds how long a minted client token stays valid (the SDK
	// defaults to 30s, which is too tight for a 40 MB upload on a slow link).
	tokenTTL time.Duration
	// client is the shared HTTP client (bounded by timeouts so a slow Blob
	// API never stalls a serverless request window).
	client *http.Client
}

// NewBlobStore builds the store from the environment. It reports disabled
// (Enabled() == false) when no BLOB_READ_WRITE_TOKEN is configured.
func NewBlobStore() *BlobStore {
	token := os.Getenv("BLOB_READ_WRITE_TOKEN")
	storeID := ""
	if token != "" {
		storeID = parseStoreID(token)
	}
	return &BlobStore{
		token:      token,
		storeID:    storeID,
		access:     getenv("BLOB_ACCESS", "private"),
		apiBase:    getenv("VERCEL_BLOB_API_URL", "https://vercel.com/api/blob"),
		apiVersion: getenv("BLOB_API_VERSION", "12"),
		tokenTTL:   15 * time.Minute,
		client: &http.Client{
			// Blob API round-trips must fit inside the serverless request
			// window; uploads/downloads of the actual object can take longer.
			Timeout: 5 * time.Minute,
		},
	}
}

// Enabled reports whether a read-write token is configured, i.e. whether the
// direct-to-Blob upload path is available.
func (b *BlobStore) Enabled() bool {
	return b.token != "" && b.storeID != ""
}

// StoreID returns the parsed store identifier ("" when disabled).
func (b *BlobStore) StoreID() string { return b.storeID }

// Access returns the upload access mode ("private" or "public").
func (b *BlobStore) Access() string { return b.access }

// APIVersion returns the x-api-version header the upload must carry.
func (b *BlobStore) APIVersion() string { return b.apiVersion }

// ClientToken mints a client upload token for the given pathname. The token is
// HMAC-signed with the read-write token and carries the constraints (pathname,
// no random suffix, validity window) that Vercel Blob enforces at upload time.
func (b *BlobStore) ClientToken(pathname string) (string, time.Time, error) {
	if !b.Enabled() {
		return "", time.Time{}, fmt.Errorf("blob store is not configured (BLOB_READ_WRITE_TOKEN missing)")
	}
	expires := time.Now().Add(b.tokenTTL)
	payloadJSON, err := json.Marshal(map[string]interface{}{
		"pathname":           pathname,
		"addRandomSuffix":    false,
		"maximumSizeInBytes": maxBlobBytes,
		"validUntil":         expires.UnixMilli(),
	})
	if err != nil {
		return "", time.Time{}, err
	}
	payload := base64.StdEncoding.EncodeToString(payloadJSON)

	mac := hmac.New(sha256.New, []byte(b.token))
	mac.Write([]byte(payload))
	signature := hex.EncodeToString(mac.Sum(nil))

	clientToken := "vercel_blob_client_" + b.storeID + "_" +
		base64.StdEncoding.EncodeToString([]byte(signature+"."+payload))
	return clientToken, expires, nil
}

// UploadURL returns the URL the browser PUTs the file to, plus the final blob
// URL that will exist after the upload (deterministic because the token
// disables the random suffix).
func (b *BlobStore) UploadURL(pathname string) (uploadURL, blobURL string) {
	uploadURL = b.apiBase + "/?pathname=" + url.QueryEscape(pathname)
	blobURL = fmt.Sprintf("https://%s.%s.blob.vercel-storage.com/%s", b.storeID, b.access, pathname)
	return uploadURL, blobURL
}

// DownloadTo streams the object behind blobURL into destPath and returns the
// number of bytes written. It follows the official SDK's get() wire protocol
// (verified against the live Blob API): for a private store the blob URL is
// fetched DIRECTLY with the read-write token in the Authorization header — no
// head/downloadUrl round-trip. (The v12 head response no longer carries a
// downloadUrl field, so the old resolve-then-download flow would fail.)
//
// SECURITY: the caller passes a client-supplied URL, so before any request is
// made the host is validated to be a Vercel Blob host. This mirrors the
// official SDK's get() guard and guarantees the read-write token can never be
// sent to a non-Vercel server (an arbitrary https:// blobUrl must not turn
// this endpoint into a token exfiltration vector).
func (b *BlobStore) DownloadTo(blobURL, destPath string) (int64, error) {
	if !b.Enabled() {
		return 0, fmt.Errorf("blob store is not configured (BLOB_READ_WRITE_TOKEN missing)")
	}
	parsed, err := url.Parse(blobURL)
	if err != nil || parsed.Hostname() == "" {
		return 0, fmt.Errorf("invalid blob url: %q", blobURL)
	}
	if parsed.Scheme != "https" || !strings.HasSuffix(parsed.Hostname(), ".blob.vercel-storage.com") {
		return 0, fmt.Errorf("invalid blob url: %q does not point to Vercel Blob", blobURL)
	}
	req, err := http.NewRequest(http.MethodGet, blobURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+b.token)

	resp, err := b.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, fmt.Errorf("blob not found (already deleted?)")
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("blob download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return 0, err
	}
	// Cap the copy so an oversized object can't fill the serverless temp disk
	// (the same CopyN-style guard the ZIP extractor uses). The file is closed
	// and removed explicitly — on Windows an open file cannot be deleted.
	written, err := io.Copy(out, io.LimitReader(resp.Body, maxBlobBytes+1))
	closeErr := out.Close()
	if err != nil {
		os.Remove(destPath)
		return 0, err
	}
	if closeErr != nil {
		os.Remove(destPath)
		return 0, closeErr
	}
	if written > maxBlobBytes {
		os.Remove(destPath)
		return 0, fmt.Errorf("blob download exceeds the %d MB size limit", maxBlobBytes/(1024*1024))
	}
	return written, nil
}

// Delete best-effort removes the object behind blobURL so the store never
// accumulates user projects. It posts to the Blob API's /delete operation with
// the JSON body {"urls":[...]} and the read-write token — the same request
// the official SDK's del() makes (verified against the live Blob API). Errors
// are returned but callers usually ignore them (cleanup is best-effort).
func (b *BlobStore) Delete(blobURL string) error {
	if !b.Enabled() {
		return nil
	}
	body, err := json.Marshal(map[string][]string{"urls": {blobURL}})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, b.apiBase+"/delete", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 200 = deleted. A 404 (already gone) is fine too.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("blob delete failed with status %d", resp.StatusCode)
	}
	return nil
}

// parseStoreID extracts the store id from a read-write token of the form
// vercel_blob_rw_{storeId}_{secret}. It mirrors the official SDK exactly:
// the store id is the 4th underscore-separated segment (parts[3]) — the SDK
// does NOT normalize (store_ prefix) read-write tokens, only delegation-token
// payloads.
func parseStoreID(token string) string {
	parts := strings.Split(token, "_")
	if len(parts) < 4 || parts[0] != "vercel" || parts[1] != "blob" || parts[2] != "rw" {
		return ""
	}
	return parts[3]
}

// getenv reads an env var with a fallback default.
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
