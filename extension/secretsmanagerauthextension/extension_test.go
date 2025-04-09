// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package secretsmanagerauthextension

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// newTestServer creates a test HTTP server that checks for expected headers
func newTestServer(t *testing.T, expectedHeaders map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that headers were added to the request
		for key, value := range expectedHeaders {
			assert.Equal(t, value, r.Header.Get(key))
		}
		w.WriteHeader(http.StatusOK)
	}))
}

// mockTransport is a mock http.RoundTripper for tests
type mockTransport struct {
	response *http.Response
	err      error
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

func TestAuthenticatorStart(t *testing.T) {
	// Create test secret
	secretValue := map[string]string{
		"X-API-Key":     "test-api-key",
		"Authorization": "Bearer test-token",
	}
	secretJSON, err := json.Marshal(secretValue)
	require.NoError(t, err)
	secretString := string(secretJSON)

	// Create authenticator with test config
	cfg := &Config{
		SecretName:      "test-secret",
		RefreshInterval: 200 * time.Millisecond,
	}
	logger := zaptest.NewLogger(t)
	auth, err := newAuthenticator(cfg, logger)
	require.NoError(t, err)

	// Create a test implementation for refreshHeaders that uses our mock data
	auth.refreshHeaders = func(_ context.Context) error {
		auth.headersMutex.Lock()
		defer auth.headersMutex.Unlock()
		return json.Unmarshal([]byte(secretString), &auth.headers)
	}

	// Test start
	err = auth.Start(t.Context(), componenttest.NewNopHost())
	require.NoError(t, err)

	// Verify headers were loaded
	time.Sleep(100 * time.Millisecond) // Allow time for initial fetch
	auth.headersMutex.RLock()
	assert.Equal(t, "test-api-key", auth.headers["X-API-Key"])
	assert.Equal(t, "Bearer test-token", auth.headers["Authorization"])
	auth.headersMutex.RUnlock()

	// Clean up
	err = auth.Shutdown(t.Context())
	require.NoError(t, err)
}

func TestRoundTripper(t *testing.T) {
	// Create authenticator with test headers
	testHeaders := map[string]string{
		"X-API-Key":     "test-api-key",
		"Authorization": "Bearer test-token",
		"X-Custom":      "custom-value",
	}

	auth := &secretsManagerAuthenticator{
		cfg:     &Config{},
		logger:  zap.NewNop(),
		headers: testHeaders,
		done:    make(chan struct{}),
	}

	// Create test server that verifies headers
	server := newTestServer(t, testHeaders)
	defer server.Close()

	// Create custom round tripper
	rt, err := auth.RoundTripper(http.DefaultTransport)
	require.NoError(t, err)

	// Make request
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestFallbackHeaders(t *testing.T) {
	// Create authenticator with fallback headers
	fallbackHeaders := map[string]string{
		"Fallback-Header": "fallback-value",
	}

	cfg := &Config{
		SecretName:      "non-existent-secret",
		FallbackHeaders: fallbackHeaders,
		RefreshInterval: 200 * time.Millisecond,
	}
	logger := zaptest.NewLogger(t)
	auth, err := newAuthenticator(cfg, logger)
	require.NoError(t, err)

	// Override refreshHeaders to simulate a failure
	auth.refreshHeaders = func(_ context.Context) error {
		return &types.ResourceNotFoundException{
			Message: aws.String("Secret not found"),
		}
	}

	// Test start
	err = auth.Start(t.Context(), componenttest.NewNopHost())
	require.NoError(t, err)

	// Verify fallback headers were used
	time.Sleep(100 * time.Millisecond) // Allow time for initial fetch
	auth.headersMutex.RLock()
	assert.Equal(t, "fallback-value", auth.headers["Fallback-Header"])
	auth.headersMutex.RUnlock()

	// Create test server that verifies fallback headers
	server := newTestServer(t, fallbackHeaders)
	defer server.Close()

	// Create custom round tripper
	rt, err := auth.RoundTripper(http.DefaultTransport)
	require.NoError(t, err)

	// Make request
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Clean up
	err = auth.Shutdown(t.Context())
	require.NoError(t, err)
}

// TestMain sets up the test environment and handles goleak detection
func TestMain(m *testing.M) {
	// Run tests
	goleak.VerifyTestMain(m,
		// These goroutines are created by the HTTP Client and are difficult to clean up
		// in tests. This pattern is similar to what other extension tests do in the project.
		goleak.IgnoreTopFunction("net/http.(*http2ClientConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
	)
}
