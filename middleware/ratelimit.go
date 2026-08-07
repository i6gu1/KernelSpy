package middleware

import (
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ScanRateLimiter tracks how many scans each IP has performed and enforces a
// limit of one scan per IP per rolling 24h window. In-memory is sufficient for
// the single-container Vercel deployment; swap for Redis if scaling out.
type ScanRateLimiter struct {
	mu    sync.Mutex
	scans map[string]time.Time // ip -> last scan time
}

const scanWindow = 24 * time.Hour

func NewScanRateLimiter() *ScanRateLimiter {
	return &ScanRateLimiter{scans: make(map[string]time.Time)}
}

// remainingLocked returns how long the IP must wait before its next scan, or
// 0 if it is allowed to scan now. Callers must hold rl.mu.
func (rl *ScanRateLimiter) remainingLocked(ip string) time.Duration {
	last, ok := rl.scans[ip]
	if !ok {
		return 0
	}
	elapsed := time.Since(last)
	if elapsed >= scanWindow {
		return 0
	}
	return scanWindow - elapsed
}

// Limit returns a fiber handler. When the client (identified by IP) has
// already scanned within the window, it responds 429 with a clear message.
// This is a fast-path check only — the authoritative check + record happens
// atomically in TryRecord(), called once the analysis has actually started,
// so invalid uploads never consume the user's single daily scan.
func (rl *ScanRateLimiter) Limit(c *fiber.Ctx) error {
	ip := c.IP()

	rl.mu.Lock()
	remaining := rl.remainingLocked(ip)
	rl.mu.Unlock()

	if remaining > 0 {
		return rl.respondTooMany(c, remaining)
	}

	return c.Next()
}

// TryRecord atomically checks the quota and, if free, records a scan for the
// IP. It returns true when the scan was recorded, or false plus the number of
// seconds the client must wait when the quota is already consumed. Calling
// this (rather than Limit alone) closes the check-then-act race between two
// concurrent uploads from the same IP.
func (rl *ScanRateLimiter) TryRecord(ip string) (ok bool, retryAfterSeconds int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if remaining := rl.remainingLocked(ip); remaining > 0 {
		retry := int(remaining.Seconds())
		if retry < 1 {
			retry = 1
		}
		return false, retry
	}

	rl.scans[ip] = time.Now()

	// Opportunistic cleanup to keep the map bounded.
	if len(rl.scans) > 5000 {
		now := time.Now()
		for k, v := range rl.scans {
			if now.Sub(v) > scanWindow {
				delete(rl.scans, k)
			}
		}
	}

	return true, 0
}

func (rl *ScanRateLimiter) respondTooMany(c *fiber.Ctx, remaining time.Duration) error {
	retryAfter := int(remaining.Seconds())
	if retryAfter < 1 {
		retryAfter = 1
	}
	c.Set("Retry-After", strconv.Itoa(retryAfter))
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
		"error":               "Rate limit exceeded: you can scan only one project per day. Please try again tomorrow.",
		"retry_after_seconds": retryAfter,
	})
}
