// Copyright (c) 2026 Codestra
// SPDX-License-Identifier: MPL-2.0
package josev3security

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	capjwt "github.com/hashicorp/cap/jwt"
)

var capNow = time.Unix(2000000000, 0).UTC()

func capValidator(t *testing.T) (*capjwt.Validator, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capjwt.NewStaticKeySet([]crypto.PublicKey{&key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	validator, err := capjwt.NewValidator(keys)
	if err != nil {
		t.Fatal(err)
	}
	return validator, key
}
func capToken(t *testing.T, key *ecdsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func canonicalCAPClaims() map[string]interface{} {
	return map[string]interface{}{"iss": "https://issuer.example.invalid", "sub": "builder", "aud": []string{"codestra"},
		"jti": "test-nonce", "iat": capNow.Unix(), "nbf": capNow.Unix() - 1, "exp": capNow.Unix() + 3600}
}
func capExpected() capjwt.Expected {
	return capjwt.Expected{Issuer: "https://issuer.example.invalid", Subject: "builder", Audiences: []string{"codestra"},
		ID: "test-nonce", SigningAlgorithms: []capjwt.Alg{capjwt.ES256}, Now: func() time.Time { return capNow },
		ClockSkewLeeway: -1, NotBeforeLeeway: -1, ExpirationLeeway: -1}
}
func requireCAPAliasRejection(t *testing.T, validator *capjwt.Validator, token string) {
	t.Helper()
	for _, method := range []struct {
		name     string
		validate func(context.Context, string, capjwt.Expected) (map[string]interface{}, error)
	}{
		{"required-time", validator.Validate}, {"optional-time", validator.ValidateAllowMissingIatNbfExp},
	} {
		t.Run(method.name, func(t *testing.T) {
			if returned, err := method.validate(context.Background(), token, capExpected()); err == nil {
				t.Fatalf("signed claim alias accepted: %v", returned)
			} else if !strings.Contains(err.Error(), "ambiguous claim") {
				t.Fatalf("token rejected for unexpected reason: %v", err)
			}
		})
	}
}
func TestCAPRejectsSignedHomoglyphRegisteredClaimConfusion(t *testing.T) {
	validator, key := capValidator(t)
	for _, tc := range []struct {
		name, canonical, alias, untrusted, trusted string
		remove                                     bool
	}{
		{"subject-collision", "sub", "\u017fub", "admin", "builder", false},
		{"issuer-collision", "iss", "i\u017fs", "https://untrusted.example.invalid", "https://issuer.example.invalid", false},
		{"lone-subject-homoglyph", "sub", "\u017fub", "", "builder", true},
		{"lone-issuer-homoglyph", "iss", "i\u017fs", "", "https://issuer.example.invalid", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := canonicalCAPClaims()
			if tc.remove {
				delete(claims, tc.canonical)
			} else {
				claims[tc.canonical] = tc.untrusted
			}
			claims[tc.alias] = tc.trusted
			requireCAPAliasRejection(t, validator, capToken(t, key, claims))
		})
	}
}
func TestCAPRejectsCaseVariantsOfEveryRegisteredClaim(t *testing.T) {
	validator, key := capValidator(t)
	for _, name := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} {
		t.Run(name, func(t *testing.T) {
			claims := canonicalCAPClaims()
			// Both variants carry the same value: rejection must enforce canonical claim
			// names rather than happen accidentally through an expected-value mismatch.
			claims[strings.ToUpper(name)] = claims[name]
			requireCAPAliasRejection(t, validator, capToken(t, key, claims))
		})
	}
}
func TestCAPCanonicalAndCustomClaimsPreserveAuthenticationChecks(t *testing.T) {
	validator, key := capValidator(t)
	claims := canonicalCAPClaims()
	claims["n\u00e1me"] = "Jos\u00e9"
	claims["u\u017fer_tag"] = "custom"
	returned, err := validator.Validate(context.Background(), capToken(t, key, claims), capExpected())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"iss", "sub", "jti", "n\u00e1me", "u\u017fer_tag"} {
		if returned[name] != claims[name] {
			t.Fatalf("canonical/custom claim changed: %s", name)
		}
	}
	for _, tc := range []string{"issuer", "subject", "audience", "expired", "signature"} {
		t.Run(tc, func(t *testing.T) {
			invalid := canonicalCAPClaims()
			signingKey := key
			switch tc {
			case "issuer":
				invalid["iss"] = "https://untrusted.example.invalid"
			case "subject":
				invalid["sub"] = "intruder"
			case "audience":
				invalid["aud"] = []string{"other"}
			case "expired":
				invalid["exp"] = capNow.Unix() - 3600
			case "signature":
				var err error
				signingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := validator.Validate(context.Background(), capToken(t, signingKey, invalid), capExpected()); err == nil {
				t.Fatalf("%s validation weakened", tc)
			}
		})
	}
}

func TestCAPOptionalTemporalClaimsRetainSeparateValidationContract(t *testing.T) {
	validator, key := capValidator(t)
	claims := canonicalCAPClaims()
	for _, name := range []string{"iat", "nbf", "exp"} {
		delete(claims, name)
	}
	token := capToken(t, key, claims)
	if _, err := validator.Validate(context.Background(), token, capExpected()); err == nil {
		t.Fatal("required-time validation accepted all time claims missing")
	}
	returned, err := validator.ValidateAllowMissingIatNbfExp(context.Background(), token, capExpected())
	if err != nil || returned["sub"] != "builder" {
		t.Fatalf("optional-time contract changed: %v %v", returned, err)
	}
}
