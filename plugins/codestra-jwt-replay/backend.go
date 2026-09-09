// Copyright (c) 2026 Codestra
// SPDX-License-Identifier: MPL-2.0

// Package replayauth wraps the exact upstream OpenBao JWT backend with a
// Raft-transactional, hash-only one-time JTI claim.
package replayauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	jwtauth "github.com/openbao/openbao/builtin/credential/jwt"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
)

const (
	pluginVersion = "v1.1.0"
	usedPrefix    = "codestra-jti/used/"
	expiryPrefix  = "codestra-jti/expiry/"
	retentionSkew = int64(30)
	cleanupLimit  = 256
)

var errReplay = errors.New("JWT replay rejected")

type backend struct {
	logical.Backend
}

type tokenClaims struct {
	Issuer      string
	ClientID    string
	Environment string
	JTI         string
	ExpiresAt   int64
}

type usedEntry struct {
	ExpiresAt int64 `json:"expires_at"`
}

// Factory preserves the exact upstream JWT implementation and adds only the
// stateful replay claim after upstream signature/issuer/audience/CEL success.
func Factory(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
	upstream, err := jwtauth.Factory(ctx, config)
	if err != nil {
		return nil, err
	}
	return &backend{Backend: upstream}, nil
}

func (b *backend) PluginVersion() logical.PluginVersion {
	return logical.PluginVersion{Version: pluginVersion}
}

func canonicalLoginPath(path string) (string, bool) {
	switch path {
	case "login", "cel/login":
		return "cel/login", true
	default:
		return path, false
	}
}

func (b *backend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	if req.Operation == logical.RollbackOperation {
		if err := cleanupExpired(ctx, req.Storage, time.Now().Unix(), cleanupLimit); err != nil {
			return nil, errors.New("JTI replay cache cleanup failed")
		}
		return b.Backend.HandleRequest(ctx, req)
	}

	path, replayProtectedLogin := canonicalLoginPath(req.Path)
	effectiveRequest := req
	if path != req.Path {
		copy := *req
		copy.Path = path
		effectiveRequest = &copy
	}
	response, err := b.Backend.HandleRequest(ctx, effectiveRequest)
	if err != nil || response == nil || response.IsError() || response.Auth == nil ||
		req.Operation != logical.UpdateOperation || !replayProtectedLogin {
		return response, err
	}

	raw, ok := req.Data["jwt"].(string)
	if !ok || raw == "" {
		return logical.ErrorResponse("JWT replay protection rejected token"), nil
	}
	claims, parseErr := parseTokenClaims(raw)
	if parseErr != nil {
		return logical.ErrorResponse("JWT replay protection rejected token"), nil
	}
	now := time.Now().Unix()
	if cleanupErr := cleanupExpired(ctx, req.Storage, now, cleanupLimit); cleanupErr != nil {
		return logical.ErrorResponse("JWT replay cache unavailable"), nil
	}
	if claimErr := claimJTI(ctx, req.Storage, claims, now); claimErr != nil {
		if errors.Is(claimErr, errReplay) || errors.Is(claimErr, physical.ErrTransactionCommitFailure) {
			return logical.ErrorResponse("JWT replay rejected"), nil
		}
		return logical.ErrorResponse("JWT replay cache unavailable"), nil
	}

	return response, nil
}

func parseTokenClaims(token string) (tokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tokenClaims{}, errors.New("JWT must contain three segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return tokenClaims{}, errors.New("JWT payload is not base64url")
	}
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		return tokenClaims{}, errors.New("JWT payload is not JSON")
	}
	stringClaim := func(name string) (string, error) {
		item, ok := value[name].(string)
		if !ok || item == "" {
			return "", fmt.Errorf("JWT claim %s is missing", name)
		}
		return item, nil
	}
	issuer, err := stringClaim("iss")
	if err != nil {
		return tokenClaims{}, err
	}
	clientID, err := stringClaim("azp")
	if err != nil {
		return tokenClaims{}, err
	}
	environment, err := stringClaim("codestra_environment")
	if err != nil {
		return tokenClaims{}, err
	}
	jti, err := stringClaim("jti")
	if err != nil {
		return tokenClaims{}, err
	}
	expValue, ok := value["exp"].(float64)
	if !ok || expValue <= 0 || expValue != math.Trunc(expValue) || expValue > math.MaxInt64 {
		return tokenClaims{}, errors.New("JWT exp is invalid")
	}
	return tokenClaims{
		Issuer: issuer, ClientID: clientID, Environment: environment,
		JTI: jti, ExpiresAt: int64(expValue),
	}, nil
}

func claimKey(claims tokenClaims) string {
	value := strings.Join([]string{claims.Issuer, claims.ClientID, claims.Environment, claims.JTI}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func claimJTI(ctx context.Context, storage logical.Storage, claims tokenClaims, now int64) error {
	if claims.ExpiresAt <= now {
		return errReplay
	}
	request := &logical.Request{Storage: storage}
	rollback, err := logical.StartTxStorage(ctx, request)
	if err != nil {
		return err
	}
	defer rollback()

	digest := claimKey(claims)
	key := usedPrefix + digest
	existing, err := request.Storage.Get(ctx, key)
	if err != nil {
		return err
	}
	if existing != nil {
		var entry usedEntry
		if err := existing.DecodeJSON(&entry); err != nil {
			return errors.New("JTI replay cache entry is invalid")
		}
		if entry.ExpiresAt >= now {
			return errReplay
		}
	}

	retainedUntil := claims.ExpiresAt + retentionSkew
	entry, err := logical.StorageEntryJSON(key, usedEntry{ExpiresAt: retainedUntil})
	if err != nil {
		return err
	}
	if err := request.Storage.Put(ctx, entry); err != nil {
		return err
	}
	bucket := (retainedUntil + 59) / 60
	index, err := logical.StorageEntryJSON(
		fmt.Sprintf("%s%010d/%s", expiryPrefix, bucket, digest),
		usedEntry{ExpiresAt: retainedUntil},
	)
	if err != nil {
		return err
	}
	if err := request.Storage.Put(ctx, index); err != nil {
		return err
	}
	return logical.EndTxStorage(ctx, request)
}

func cleanupExpired(ctx context.Context, storage logical.Storage, now int64, limit int) error {
	buckets, err := storage.List(ctx, expiryPrefix)
	if err != nil {
		return err
	}
	processed := 0
	for _, bucket := range buckets {
		if processed >= limit || !strings.HasSuffix(bucket, "/") {
			break
		}
		var minute int64
		if _, err := fmt.Sscanf(strings.TrimSuffix(bucket, "/"), "%d", &minute); err != nil {
			return errors.New("JTI replay expiry index is invalid")
		}
		if minute*60 > now {
			continue
		}
		digests, err := storage.List(ctx, expiryPrefix+bucket)
		if err != nil {
			return err
		}
		for _, digest := range digests {
			if processed >= limit {
				return nil
			}
			if strings.Contains(digest, "/") {
				return errors.New("JTI replay expiry digest is invalid")
			}
			request := &logical.Request{Storage: storage}
			rollback, err := logical.StartTxStorage(ctx, request)
			if err != nil {
				return err
			}
			primaryKey := usedPrefix + digest
			primary, readErr := request.Storage.Get(ctx, primaryKey)
			if readErr == nil && primary != nil {
				var item usedEntry
				readErr = primary.DecodeJSON(&item)
				if readErr == nil && item.ExpiresAt <= now {
					readErr = request.Storage.Delete(ctx, primaryKey)
				}
			}
			if readErr == nil {
				readErr = request.Storage.Delete(ctx, expiryPrefix+bucket+digest)
			}
			if readErr == nil {
				readErr = logical.EndTxStorage(ctx, request)
			}
			rollback()
			if readErr != nil && !errors.Is(readErr, physical.ErrTransactionAlreadyCommitted) {
				return readErr
			}
			processed++
		}
	}
	return nil
}
