// Copyright (c) 2026 Codestra
// SPDX-License-Identifier: MPL-2.0

// Command testtoken creates short-lived isolated integration JWTs. It is not
// built into or shipped with the production plugin.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func identifier() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return hex.EncodeToString(value)
}

func token(signer jose.Signer, now time.Time, overrides map[string]any) string {
	claims := map[string]any{
		"iss": "https://auth.codestra.co/realms/codestra",
		"sub": "integration-workload",
		"aud": []string{"openbao"},
		"azp": "middleware-api",
		"iat": now.Add(-5 * time.Second).Unix(),
		"exp": now.Add(120 * time.Second).Unix(),
		"jti": identifier(),
		"codestra_environment": "staging",
	}
	for key, value := range overrides {
		if value == nil {
			delete(claims, key)
		} else {
			claims[key] = value
		}
	}
	value, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return value
}

func main() {
	output := flag.String("output", "", "protected temporary output directory")
	flag.Parse()
	if *output == "" {
		panic("output is required")
	}
	if err := os.MkdirAll(*output, 0o700); err != nil {
		panic(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(*output, "public.pem"), public, 0o600); err != nil {
		panic(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		panic(err)
	}
	now := time.Now().UTC()
	tokens := map[string]string{
		"valid": token(signer, now, nil),
		"agentCompatible": token(signer, now, nil),
		"concurrent": token(signer, now, nil),
		"wrongIssuer": token(signer, now, map[string]any{"iss": "https://issuer.invalid/realm"}),
		"wrongAudience": token(signer, now, map[string]any{"aud": []string{"wrong"}}),
		"wrongEnvironment": token(signer, now, map[string]any{"codestra_environment": "production"}),
		"wrongClient": token(signer, now, map[string]any{"azp": "other-client"}),
		"expired": token(signer, now, map[string]any{"iat": now.Add(-400 * time.Second).Unix(), "exp": now.Add(-100 * time.Second).Unix()}),
		"overlong": token(signer, now, map[string]any{"exp": now.Add(600 * time.Second).Unix()}),
		"futureIssuedAt": token(signer, now, map[string]any{"iat": now.Add(120 * time.Second).Unix(), "exp": now.Add(240 * time.Second).Unix()}),
		"missingSubject": token(signer, now, map[string]any{"sub": nil}),
		"missingJTI": token(signer, now, map[string]any{"jti": nil}),
	}
	encoded, err := json.Marshal(tokens)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(*output, "tokens.json"), encoded, 0o600); err != nil {
		panic(err)
	}
}
