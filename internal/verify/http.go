package verify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Transient failures are the normal case for a CI job that fires a burst of
// adjudication requests: providers rate-limit (429), shed load (529/503) and
// occasionally drop a connection. Without retries a single blip silently costs
// a whole batch its verdicts — with on_error="keep" the scan still succeeds and
// the findings come back unverified, which reads like a clean run but is not.
const (
	httpAttempts    = 3                // initial attempt + 2 retries
	maxResponseSize = 1 << 20          // plenty for a batch verdict document
	maxRetryBackoff = 30 * time.Second // ceiling for a server-provided Retry-After
)

// httpBackoff is the base delay; attempt N waits base * 2^(N-1). A var so
// tests can zero it.
var httpBackoff = time.Second

// httpResponse is the part of a provider response the callers care about.
type httpResponse struct {
	status int
	body   []byte
}

// postJSON sends body to url and returns the response, retrying transient
// failures. It rebuilds the request on every attempt (a consumed body cannot be
// replayed) and gives up as soon as ctx is done, so a caller's timeout still
// bounds total wall-clock across retries.
//
// header is applied to each attempt; provider is used only in error messages.
func postJSON(ctx context.Context, client *http.Client, provider, url string, body []byte, header http.Header) (*httpResponse, error) {
	var (
		lastErr        error
		lastRetryAfter time.Duration // server-provided hint from the previous attempt
	)

	for attempt := 1; attempt <= httpAttempts; attempt++ {
		if attempt > 1 {
			wait := backoffFor(attempt, lastRetryAfter)
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%s: %w", provider, ctx.Err())
			case <-time.After(wait):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			// A malformed URL will not fix itself on the next attempt.
			return nil, fmt.Errorf("%s: build request: %w", provider, err)
		}
		req.Header = header.Clone()

		resp, err := client.Do(req)
		if err != nil {
			// A cancelled context is the caller giving up, not a blip.
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%s: %w", provider, ctx.Err())
			}
			lastErr, lastRetryAfter = fmt.Errorf("%s: request failed: %w", provider, err), 0
			continue
		}

		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		resp.Body.Close()
		if readErr != nil {
			lastErr, lastRetryAfter = fmt.Errorf("%s: read response: %w", provider, readErr), retryAfter
			continue
		}
		if retryableStatus(resp.StatusCode) {
			lastErr = fmt.Errorf("%s: HTTP %d: %s", provider, resp.StatusCode, trimBody(raw))
			lastRetryAfter = retryAfter
			continue
		}
		return &httpResponse{status: resp.StatusCode, body: raw}, nil
	}

	return nil, fmt.Errorf("%s after %d attempts: %w", provider, httpAttempts, lastErr)
}

// retryableStatus reports whether a status code is worth another attempt:
// rate limits, request timeouts, and server-side failures. Everything else
// (auth, malformed request, unknown model) fails the same way every time.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	}
	return code >= 500
}

// backoffFor returns the delay before the given attempt. A server-provided
// Retry-After wins when it is longer than our own backoff, clamped so a
// pathological header cannot stall a scan for minutes.
func backoffFor(attempt int, retryAfter time.Duration) time.Duration {
	wait := httpBackoff << (attempt - 2) // attempt 2 → base, 3 → 2×base
	if retryAfter > wait {
		wait = retryAfter
	}
	if wait > maxRetryBackoff {
		wait = maxRetryBackoff
	}
	return wait
}

// parseRetryAfter reads the header in both documented forms: delay in seconds,
// or an HTTP date. An unparseable value is treated as absent.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// trimBody bounds an error message so a provider's HTML error page does not
// end up in the user's terminal.
func trimBody(b []byte) string {
	const max = 500
	s := string(bytes.TrimSpace(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
