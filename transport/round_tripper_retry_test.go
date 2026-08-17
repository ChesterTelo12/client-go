package transport

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type retryMockTokenSource struct {
	tokens []string
	index  int
	lk     sync.Mutex
}

func (m *retryMockTokenSource) Token() (*oauth2.Token, error) {
	m.lk.Lock()
	defer m.lk.Unlock()
	if m.index >= len(m.tokens) {
		return nil, fmt.Errorf("no more tokens")
	}
	t := &oauth2.Token{
		AccessToken: m.tokens[m.index],
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	m.index++
	return t, nil
}

type retryRoundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.fn(req)
}

func TestTokenSourceWrapRetry(t *testing.T) {
	tokens := []string{"token-v1", "token-v2"}
	mts := &retryMockTokenSource{tokens: tokens}
	cts := NewCachedTokenSource(mts)

	var requests []*http.Request
	var lk sync.Mutex
	base := &retryRoundTripper{
		fn: func(req *http.Request) (*http.Response, error) {
			lk.Lock()
			requests = append(requests, req)
			lk.Unlock()

			if len(requests) == 1 {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
			}, nil
		},
	}

	rt := &tokenSourceWrap{
		base: base,
		ts:   cts,
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t(err)
	}

	// First attempt
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// The first request sent to base should have token-v1
	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	if auth := requests[0].Header.Get("Authorization"); auth != "Bearer token-v1" {
		t.Errorf("expected Bearer token-v1, got %q", auth)
	}

	// Simulate retry by cloning the request that was sent (which has the Authorization header)
	req2 := requests[0].Clone(req.Context())

	// Second attempt (retry)
	resp2, err := rt.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}

	// The second request sent to base should have token-v2
	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}
	if auth := requests[1].Header.Get("Authorization"); auth != "Bearer token-v2" {
		t.Errorf("expected Bearer token-v2, got %q", auth)
	}
}
