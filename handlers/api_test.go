package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestOrderQueueCapacity verifies the order/queue system: the first N uploads
// (orders) each reserve a slot, the next one is rejected, and once a running
// scan finishes (slot released) the next order can take its place. N comes
// from the channel's actual capacity (MAX_CONCURRENT_ANALYSES, default 100).
func TestOrderQueueCapacity(t *testing.T) {
	// Drain any slots left over from other tests so this test is hermetic.
	for len(orderSlots) > 0 {
		releaseOrderSlot()
	}

	capacity := cap(orderSlots)
	if capacity < 1 {
		t.Fatalf("expected a positive order-slot capacity, got %d", capacity)
	}

	// Fill all slots.
	for i := 0; i < capacity; i++ {
		if !reserveOrderSlot() {
			t.Fatalf("order %d should have reserved a slot", i+1)
		}
	}

	// The next order must be rejected while all slots are busy.
	if reserveOrderSlot() {
		t.Fatal("the order beyond capacity should have been rejected while all slots are busy")
	}

	// When one scan finishes, its slot frees up and the next order proceeds.
	releaseOrderSlot()
	if !reserveOrderSlot() {
		t.Fatal("a slot should have opened after one scan finished")
	}

	// Clean up: release everything this test reserved so other tests (and the
	// real server, if this runs in-process) start from a clean state.
	for len(orderSlots) > 0 {
		releaseOrderSlot()
	}
}

// TestUploadTokenDisabled verifies the large-file upload endpoint answers
// {"enabled":false} when no Blob store is configured, so the frontend falls
// back to the classic direct upload.
func TestUploadTokenDisabled(t *testing.T) {
	os.Unsetenv("BLOB_READ_WRITE_TOKEN")
	os.Unsetenv("BLOB_ACCESS")

	req := httptest.NewRequest(http.MethodPost, "/api/upload/token", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()

	u := &UploadHandler{}
	u.UploadToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if enabled, _ := resp["enabled"].(bool); enabled {
		t.Fatal("expected enabled=false when no blob token is configured")
	}
}

// TestAnalysisDeadline verifies the watchdog derives from the ANALYSIS_TIMEOUT
// env var and defaults to 10 minutes.
func TestAnalysisDeadline(t *testing.T) {
	os.Unsetenv("ANALYSIS_TIMEOUT")
	if d := analysisDeadline(); d != 600*time.Second {
		t.Fatalf("expected the default 600s deadline, got %s", d)
	}

	t.Setenv("ANALYSIS_TIMEOUT", "280")
	if d := analysisDeadline(); d != 280*time.Second {
		t.Fatalf("expected a 280s deadline, got %s", d)
	}

	t.Setenv("ANALYSIS_TIMEOUT", "bogus")
	if d := analysisDeadline(); d != 600*time.Second {
		t.Fatalf("expected the default deadline for an invalid value, got %s", d)
	}
}

// TestUploadTokenEnabled verifies the large-file upload endpoint mints a
// client token with the SDK wire format when a Blob store is configured.
func TestUploadTokenEnabled(t *testing.T) {
	t.Setenv("BLOB_READ_WRITE_TOKEN", "vercel_blob_rw_store123_secret")
	t.Setenv("BLOB_ACCESS", "private")

	req := httptest.NewRequest(http.MethodPost, "/api/upload/token", strings.NewReader(`{"filename":"my-project.zip"}`))
	rr := httptest.NewRecorder()

	u := &UploadHandler{}
	u.UploadToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if enabled, _ := resp["enabled"].(bool); !enabled {
		t.Fatal("expected enabled=true when a blob token is configured")
	}
	tok, _ := resp["token"].(string)
	if !strings.HasPrefix(tok, "vercel_blob_client_store123_") {
		t.Fatalf("unexpected client token: %q", tok)
	}
	if blobURL, _ := resp["blob_url"].(string); !strings.HasPrefix(blobURL, "https://store123.private.blob.vercel-storage.com/uploads/") {
		t.Fatalf("unexpected blob url: %q", blobURL)
	}
	if uploadURL, _ := resp["upload_url"].(string); !strings.Contains(uploadURL, "pathname=uploads%2F") {
		t.Fatalf("unexpected upload url: %q", uploadURL)
	}
}

// TestCompleteUploadDisabled verifies the completion endpoint rejects requests
// with a localized error when no Blob store is configured.
func TestCompleteUploadDisabled(t *testing.T) {
	os.Unsetenv("BLOB_READ_WRITE_TOKEN")

	req := httptest.NewRequest(http.MethodPost, "/api/upload/complete", strings.NewReader(`{"blobUrl":"https://store.private.blob.vercel-storage.com/uploads/x.zip"}`))
	rr := httptest.NewRecorder()

	u := &UploadHandler{}
	u.CompleteUpload(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if msg, _ := resp["error"].(string); msg == "" {
		t.Fatal("expected a localized error message")
	}
}
