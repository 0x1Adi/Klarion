package verify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// TestVerifySplitsAnUnparseableBatch: when the provider cannot produce usable
// output for a whole batch, halving it must recover rather than losing every
// verdict. Groq returns 400 json_validate_failed with an empty
// failed_generation for this, which is a sampling failure, not a bad request.
func TestVerifySplitsAnUnparseableBatch(t *testing.T) {
	const bigBatch = 4
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		atomic.AddInt32(&calls, 1)
		// Fail any batch bigger than two candidates, as a size-sensitive
		// generation failure would.
		if m := regexp.MustCompile(`following (\d+) candidate`).FindSubmatch(body); m != nil {
			if n, _ := strconv.Atoi(string(m[1])); n > 2 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"code":"json_validate_failed","failed_generation":""}}`))
				return
			}
		}
		n, _ := strconv.Atoi(string(regexp.MustCompile(`following (\d+) candidate`).FindSubmatch(body)[1]))
		results := make([]string, 0, n)
		for i := 0; i < n; i++ {
			results = append(results, fmt.Sprintf(
				`{"index":%d,"status":"secret","confidence":0.9,"reason":"r"}`, i))
		}
		content := `{"results":[` + strings.Join(results, ",") + `]}`
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":` + strconv.Quote(content) + `}}]}`))
	}))
	defer srv.Close()

	old := httpBackoff
	httpBackoff = time.Millisecond
	defer func() { httpBackoff = old }()

	v := &openaiVerifier{model: "stub", baseURL: srv.URL, timeout: 5 * time.Second, client: srv.Client()}
	batch := make([]Request, bigBatch)
	for i := range batch {
		batch[i] = Request{Index: i, Secret: "s", FilePath: "f"}
	}

	got, err := v.Verify(context.Background(), batch)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got) != bigBatch {
		t.Fatalf("got %d verdicts, want %d", len(got), bigBatch)
	}
	for i, vd := range got {
		if vd.Status != finding.VerdictSecret {
			t.Errorf("verdict %d = %v, want secret", i, vd.Status)
		}
	}
}

// TestVerifyFallsBackToReasoningChannel: a reasoning model at low effort
// sometimes leaves message.content empty and puts the answer in
// message.reasoning. Reading only content lost the whole batch as
// "no verdicts in model output".
func TestVerifyFallsBackToReasoningChannel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner := `{"results":[{"index":0,"status":"false_positive","confidence":0.9,"reason":"r"}]}`
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"","reasoning":` +
			strconv.Quote(inner) + `}}]}`))
	}))
	defer srv.Close()

	v := &openaiVerifier{model: "stub", baseURL: srv.URL, timeout: 5 * time.Second, client: srv.Client()}
	got, err := v.Verify(context.Background(), []Request{{Index: 0, Secret: "s", FilePath: "f"}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(got) != 1 || got[0].Status != finding.VerdictFalsePositive {
		t.Fatalf("got %+v, want one false_positive verdict", got)
	}
}
