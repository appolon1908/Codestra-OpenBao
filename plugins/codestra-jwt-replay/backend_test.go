// Copyright (c) 2026 Codestra
// SPDX-License-Identifier: MPL-2.0

package replayauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
)

func storage(t *testing.T) logical.Storage {
	t.Helper()
	physical, err := inmem.NewInmem(map[string]string{}, log.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	return logical.NewLogicalStorage(physical)
}

func unsignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func claims(jti string, expires int64) tokenClaims {
	return tokenClaims{
		Issuer: "https://auth.codestra.co/realms/codestra", ClientID: "middleware-api",
		Environment: "staging", JTI: jti, ExpiresAt: expires,
	}
}

func TestParseClaims(t *testing.T) {
	token := unsignedToken(t, map[string]any{
		"iss": "https://auth.codestra.co/realms/codestra", "azp": "middleware-api",
		"codestra_environment": "staging", "jti": "one-time-id", "exp": 1300,
	})
	value, err := parseTokenClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	if value.JTI != "one-time-id" || value.ExpiresAt != 1300 {
		t.Fatalf("unexpected claims: %#v", value)
	}
}

func TestStandardAgentLoginIsForcedThroughCEL(t *testing.T) {
	for _, test := range []struct {
		input    string
		expected string
		login    bool
	}{
		{"login", "cel/login", true},
		{"cel/login", "cel/login", true},
		{"oidc/callback", "oidc/callback", false},
	} {
		actual, replayProtected := canonicalLoginPath(test.input)
		if actual != test.expected || replayProtected != test.login {
			t.Fatalf(
				"canonicalLoginPath(%q) = %q,%v; want %q,%v",
				test.input, actual, replayProtected, test.expected, test.login,
			)
		}
	}
}

func TestSequentialReplayIsDenied(t *testing.T) {
	store := storage(t)
	if err := claimJTI(t.Context(), store, claims("same-jti", 1300), 1000); err != nil {
		t.Fatal(err)
	}
	if err := claimJTI(t.Context(), store, claims("same-jti", 1300), 1001); !errors.Is(err, errReplay) {
		t.Fatalf("expected replay denial, got %v", err)
	}
}

func TestConcurrentReplayHasExactlyOneWinner(t *testing.T) {
	store := storage(t)
	var success atomic.Int64
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if claimJTI(context.Background(), store, claims("concurrent-jti", 1300), 1000) == nil {
				success.Add(1)
			}
		}()
	}
	wait.Wait()
	if success.Load() != 1 {
		t.Fatalf("expected one successful claim, got %d", success.Load())
	}
}

func TestExpiredEntriesAreCleanedWithoutDeletingNewReuse(t *testing.T) {
	store := storage(t)
	if err := claimJTI(t.Context(), store, claims("reused-after-expiry", 1010), 1000); err != nil {
		t.Fatal(err)
	}
	if err := claimJTI(t.Context(), store, claims("reused-after-expiry", 2000), 1100); err != nil {
		t.Fatal(err)
	}
	if err := cleanupExpired(t.Context(), store, 1200, cleanupLimit); err != nil {
		t.Fatal(err)
	}
	if err := claimJTI(t.Context(), store, claims("reused-after-expiry", 2000), 1201); !errors.Is(err, errReplay) {
		t.Fatalf("cleanup deleted a live replacement: %v", err)
	}
}
