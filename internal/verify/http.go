package verify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Transient failures are the normal case for a CI job that fires a burst of
// adjudication requests: providers rate-limit (429), shed load (529/503) and
// occasionally drop a connection. Without retries a single blip silently costs
// a whole batch its verdicts — with on_error="keep" the scan still succeeds and
// the findings come back unverified, which reads like a clean run but is not.
const (
	httpAttempts    = 5                // initial attempt + 4 retries
	maxResponseSize = 1 << 20          // plenty for a batch verdict document
	maxRetryBackoff = 90 * time.Second // ceiling for a server-provided Retry-After
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
//
// perAttempt bounds a single HTTP round trip, NOT the whole sequence. Wrapping
// the sequence was wrong: honouring a 20s Retry-After inside a 45s budget left
// nothing for the retry itself, so a rate-limited scan died with "context
// deadline exceeded" instead of waiting out the window. An overall ceiling is
// still derived below so a scan cannot hang indefinitely.
func postJSON(ctx context.Context, client *http.Client, provider, url string, body []byte, header http.Header, perAttempt time.Duration) (*httpResponse, error) {
	if perAttempt > 0 {
		overall := perAttempt*time.Duration(httpAttempts) + maxRetryBackoff*time.Duration(httpAttempts-1)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, overall)
		defer cancel()
	}
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

		attemptCtx := ctx
		var attemptCancel context.CancelFunc
		if perAttempt > 0 {
			attemptCtx, attemptCancel = context.WithTimeout(ctx, perAttempt)
		}

		req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			if attemptCancel != nil {
				attemptCancel()
			}
			// A malformed URL will not fix itself on the next attempt.
			return nil, fmt.Errorf("%s: build request: %w", provider, err)
		}
		req.Header = header.Clone()

		resp, err := client.Do(req)
		if err != nil {
			if attemptCancel != nil {
				attemptCancel()
			}
			// The OUTER context being done is the caller giving up. A per-attempt
			// deadline is just a slow response, and is worth another try.
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%s: %w", provider, ctx.Err())
			}
			lastErr, lastRetryAfter = fmt.Errorf("%s: request failed: %w", provider, err), 0
			continue
		}

		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		resp.Body.Close()
		if attemptCancel != nil {
			attemptCancel()
		}
		if readErr != nil {
			lastErr, lastRetryAfter = fmt.Errorf("%s: read response: %w", provider, readErr), retryAfter
			continue
		}
		if retryableStatus(resp.StatusCode) {
			lastErr = fmt.Errorf("%s: HTTP %d: %s", provider, resp.StatusCode, trimBody(raw))
			if retryAfter == 0 {
				retryAfter = retryAfterFromBody(raw)
			}
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
	// RFC 7231 specifies whole seconds, but providers send fractions: Groq
	// replies "20.3775". strconv.Atoi rejected those, the hint was discarded,
	// and the scan retried on the 1s/2s default backoff against a window that
	// had 20 seconds left to run -- so every attempt was refused and the batch
	// failed. ParseFloat accepts both forms.
	if secs, err := strconv.ParseFloat(v, 64); err == nil && secs >= 0 {
		return time.Duration(secs * float64(time.Second))
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// retryAfterFromBody digs the wait out of a rate-limit payload when the header
// is missing. Providers that omit Retry-After often still state the delay in
// the error message ("Please try again in 20.3775s"), and honouring it is the
// difference between a scan that finishes and one that dies on a free tier.
var retryAfterBody = regexp.MustCompile(`try again in ([0-9]+(?:\.[0-9]+)?)\s*(ms|s\b)`)

func retryAfterFromBody(b []byte) time.Duration {
	m := retryAfterBody.FindSubmatch(b)
	if m == nil {
		return 0
	}
	n, err := strconv.ParseFloat(string(m[1]), 64)
	if err != nil || n < 0 {
		return 0
	}
	unit := time.Second
	if string(m[2]) == "ms" {
		unit = time.Millisecond
	}
	return time.Duration(n * float64(unit))
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
