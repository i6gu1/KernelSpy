package services

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"black-hat/models"
)

// Analysis lifecycle identifiers used by the state file on disk.
const (
	StateRunning   = "running"
	StateCompleted = "completed"
)

// staleStateAfter bounds how long a "running" marker is trusted. A container
// instance that dies mid-analysis leaves a "running" state behind; once the
// marker is older than this the analysis is treated as gone so clients stop
// polling instead of spinning forever.
const staleStateAfter = 45 * time.Minute

// resultState is the JSON payload of analyses/{id}/state.json.
type resultState struct {
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at"`
}

// ResultStore keeps analysis results (and their lifecycle state) in the
// per-instance memory cache for speed, with the authoritative copy written to
// Vercel Blob whenever the blob store is enabled. That makes results render
// correctly even when the status poll or the /results page lands on a
// *different* container instance than the one that ran the analysis — Vercel
// containers auto-scale to several instances and requests are not sticky, which
// is exactly the source of the intermittent "No analysis available" bug.
//
// When Blob is not configured the store degrades to the plain in-memory map,
// which is correct for the single-process hosts (local dev, Render, VPS).
type ResultStore struct {
	mu    sync.RWMutex
	cache map[int]*models.AnalysisResult
	// stateCache speeds up same-process reads (the instance that runs the
	// analysis answers status polls without a Blob round-trip).
	stateCache map[int]resultState
	blob       *BlobStore
}

var (
	resultStore     *ResultStore
	resultStoreOnce sync.Once
)

// ResultStoreInstance returns the shared result store.
func ResultStoreInstance() *ResultStore {
	resultStoreOnce.Do(func() {
		resultStore = &ResultStore{
			cache:      make(map[int]*models.AnalysisResult),
			stateCache: make(map[int]resultState),
			blob:       NewBlobStore(),
		}
	})
	return resultStore
}

// pathFor returns the blob pathname for a result/state object.
func (s *ResultStore) pathFor(id int, name string) string {
	return fmt.Sprintf("analyses/%d/%s", id, name)
}

// stateJSON is the JSON blob written for a given status.
func stateJSON(status string) []byte {
	payload, _ := json.Marshal(resultState{Status: status, UpdatedAt: time.Now().UTC().Format(time.RFC3339)})
	return payload
}

// MarkRunning records that the analysis is in flight, both locally and (when
// enabled) in shared Blob storage so other instances see the same state.
func (s *ResultStore) MarkRunning(id int) {
	s.mu.Lock()
	s.stateCache[id] = resultState{Status: StateRunning, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	s.mu.Unlock()
	if s.blob.Enabled() {
		_ = s.blob.Put(s.pathFor(id, "state.json"), stateJSON(StateRunning))
	}
}

// MarkCompleted records that the analysis finished. The result itself is
// persisted separately by PutResult.
func (s *ResultStore) MarkCompleted(id int) {
	s.mu.Lock()
	s.stateCache[id] = resultState{Status: StateCompleted, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	s.mu.Unlock()
	if s.blob.Enabled() {
		_ = s.blob.Put(s.pathFor(id, "state.json"), stateJSON(StateCompleted))
	}
}

// Forget removes any local cache entries for an id (best-effort cleanup).
func (s *ResultStore) Forget(id int) {
	s.mu.Lock()
	delete(s.cache, id)
	delete(s.stateCache, id)
	s.mu.Unlock()
}

// FetchState returns the current lifecycle state ("", StateRunning or
// StateCompleted). Blob is consulted when the id is unknown locally and the
// store is enabled; stale "running" markers (orphaned by a dead instance) are
// treated as no state. A completed state with a readable result returns
// StateCompleted so the caller (e.g. the status endpoint) can decide how to
// answer without fetching the (possibly large) result payload again.
func (s *ResultStore) FetchState(id int) string {
	s.mu.RLock()
	st, ok := s.stateCache[id]
	s.mu.RUnlock()
	if ok {
		return s.stateFrom(st)
	}
	if s.blob.Enabled() {
		_, blobURL := s.blob.UploadURL(s.pathFor(id, "state.json"))
		data, err := s.blob.DownloadBytes(blobURL)
		if err != nil {
			return ""
		}
		var st resultState
		if json.Unmarshal(data, &st) != nil {
			return ""
		}
		ts, terr := time.Parse(time.RFC3339, st.UpdatedAt)
		if terr == nil {
			st.UpdatedAt = ts.UTC().Format(time.RFC3339)
		}
		s.mu.Lock()
		s.stateCache[id] = st
		s.mu.Unlock()
		return s.stateFrom(st)
	}
	return ""
}

// stateFrom applies the staleness rule to a cached state entry.
func (s *ResultStore) stateFrom(st resultState) string {
	if st.Status == StateRunning {
		if ts, err := time.Parse(time.RFC3339, st.UpdatedAt); err == nil {
			if time.Since(ts) > staleStateAfter {
				// The instance that owned the scan is gone; do not report a
				// forever-running analysis.
				return ""
			}
		}
		return StateRunning
	}
	if st.Status == StateCompleted {
		return StateCompleted
	}
	return ""
}

// PutResult stores a finished report: the in-memory cache always wins locally,
// and the JSON payload is mirrored to Blob so every instance (and any later
// refresh after an instance recycled) can render it.
func (s *ResultStore) PutResult(id int, result *models.AnalysisResult) {
	s.mu.Lock()
	s.cache[id] = result
	s.stateCache[id] = resultState{Status: StateCompleted, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	s.mu.Unlock()

	if !s.blob.Enabled() {
		return
	}
	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	_ = s.blob.Put(s.pathFor(id, "result.json"), data)
	_ = s.blob.Put(s.pathFor(id, "state.json"), stateJSON(StateCompleted))
}

// FetchResult loads an analysis result: memory first, then Blob. When a value
// comes from Blob it is cached back so a warm instance answers instantly the
// next time.
func (s *ResultStore) FetchResult(id int) (*models.AnalysisResult, bool) {
	s.mu.RLock()
	res, ok := s.cache[id]
	s.mu.RUnlock()
	if ok {
		return res, true
	}

	if s.blob.Enabled() {
		_, blobURL := s.blob.UploadURL(s.pathFor(id, "result.json"))
		data, err := s.blob.DownloadBytes(blobURL)
		if err == nil {
			var res models.AnalysisResult
			if json.Unmarshal(data, &res) == nil {
				copy := res
				s.mu.Lock()
				s.cache[id] = &copy
				s.mu.Unlock()
				return &copy, true
			}
		}
	}
	return nil, false
}
