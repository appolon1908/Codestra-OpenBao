// Copyright (c) 2026 Codestra
// SPDX-License-Identifier: MPL-2.0
package josev3security

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	capjwt "github.com/hashicorp/cap/jwt"
)

func enc(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func encoded(v interface{}) string { b, _ := json.Marshal(v); return enc(b) }
func public(bits uint) map[string]interface{} {
	n := new(big.Int).Lsh(big.NewInt(1), bits-1)
	n.SetBit(n, 0, 1)
	return map[string]interface{}{"kty": "RSA", "n": enc(n.Bytes()), "e": "AQAB"}
}
func requireGuard(t *testing.T, err error, guard string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), guard) {
		t.Fatalf("expected guard %q, got %v", guard, err)
	}
}
func TestRSABounds(t *testing.T) {
	for _, bits := range []uint{2048, 4096, 4097} {
		raw, _ := json.Marshal(public(bits))
		var key jose.JSONWebKey
		err := json.Unmarshal(raw, &key)
		if bits > 4096 {
			requireGuard(t, err, "modulus too large")
		} else if err != nil {
			t.Fatal(err)
		}
	}
	for _, bits := range []uint{32, 4097} {
		key := public(bits)
		key["d"], key["p"], key["q"] = "AQ", enc(new(big.Int).Lsh(big.NewInt(1), 4096).Bytes()), "Aw"
		raw, _ := json.Marshal(key)
		var parsed jose.JSONWebKey
		err := json.Unmarshal(raw, &parsed)
		if bits > 4096 {
			requireGuard(t, err, "modulus too large")
		} else {
			requireGuard(t, err, "p * q != n")
		}
	}
	// A bounded but inconsistent product must use the same cheap guard.
	key := public(2048)
	key["d"], key["p"], key["q"] = "AQ", "Aw", "BQ"
	raw, _ := json.Marshal(key)
	var parsed jose.JSONWebKey
	requireGuard(t, json.Unmarshal(raw, &parsed), "p * q != n")
}
func TestPrivateHeadersRejectedInEveryJWSForm(t *testing.T) {
	for _, field := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		for _, unprotected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/unprotected=%v", field, unprotected), func(t *testing.T) {
				key := public(2048)
				key[field] = "AQ"
				protected := map[string]interface{}{"alg": "RS256"}
				header := map[string]interface{}{}
				if unprotected {
					header["jwk"] = key
				} else {
					protected["jwk"] = key
				}
				sig := map[string]interface{}{"protected": encoded(protected), "signature": "AQ", "header": header}
				flat := map[string]interface{}{"payload": "e30", "protected": sig["protected"], "signature": "AQ", "header": header}
				general := map[string]interface{}{"payload": "e30", "signatures": []interface{}{sig}}
				messages := []string{}
				for _, msg := range []interface{}{flat, general} {
					b, _ := json.Marshal(msg)
					messages = append(messages, string(b))
				}
				if !unprotected {
					messages = append(messages, encoded(protected)+".e30.AQ")
				}
				for _, msg := range messages {
					_, err := jose.ParseSigned(msg)
					requireGuard(t, err, "JWK contains private parameters")
				}
			})
		}
	}
}
func TestGeneralHeaderAndPublicJWKPreserved(t *testing.T) {
	msg := map[string]interface{}{"payload": "e30", "signatures": []interface{}{map[string]interface{}{
		"protected": encoded(map[string]interface{}{"alg": "RS256"}),
		"header":    map[string]interface{}{"kid": "expected", "jwk": public(2048)}, "signature": "AQ"}}}
	raw, _ := json.Marshal(msg)
	parsed, err := jose.ParseSigned(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	sig := parsed.Signatures[0]
	if sig.Header.KeyID != "expected" || sig.Unprotected.KeyID != "expected" || sig.Header.JSONWebKey == nil {
		t.Fatal("general serialization lost public/unprotected header")
	}
}
func TestCapRejectsBeforeKeySearch(t *testing.T) {
	called := false
	validator, err := capjwt.NewValidatorWithKeySetSearcher(func(context.Context, string) (capjwt.KeySet, error) {
		called = true
		return nil, fmt.Errorf("unexpected search")
	})
	if err != nil {
		t.Fatal(err)
	}
	key := public(2048)
	key["p"] = "AQ"
	token := encoded(map[string]interface{}{"alg": "RS256", "kid": "attacker", "jwk": key}) + ".e30.AQ"
	_, err = validator.Validate(context.Background(), token, capjwt.Expected{SigningAlgorithms: []capjwt.Alg{"RS256"}})
	requireGuard(t, err, "JWK contains private parameters")
	if called {
		t.Fatal("private header reached key search")
	}
}
func TestValidPrivateKeyAndCapJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jose.JSONWebKey{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	var decoded jose.JSONWebKey
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: decoded.Key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(map[string]interface{}{"iss": "fixture", "aud": "fixture", "sub": "fixture", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nbf": time.Now().Add(-time.Minute).Unix()})
	signed, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
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
	_, err = validator.Validate(context.Background(), token, capjwt.Expected{Issuer: "fixture", Audiences: []string{"fixture"}, SigningAlgorithms: []capjwt.Alg{"RS256"}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestJWEPrivateEPKRejectsOtherwiseValidMessage(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := jose.NewMultiEncrypter(jose.A128GCM, []jose.Recipient{
		{Algorithm: jose.ECDH_ES_A128KW, Key: &key.PublicKey},
		{Algorithm: jose.ECDH_ES_A128KW, Key: &second.PublicKey}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encrypter.Encrypt([]byte("expected plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, plain, err := encrypted.DecryptMulti(key)
	if err != nil || string(plain) != "expected plaintext" {
		t.Fatalf("valid JWE rejected: %v", err)
	}
	var message map[string]interface{}
	if err = json.Unmarshal([]byte(encrypted.FullSerialize()), &message); err != nil {
		t.Fatal(err)
	}
	// Recipient headers are unprotected: adding this stray private field does
	// not change AAD. Unpatched v3 decrypts this otherwise valid JWE.
	for _, recipient := range message["recipients"].([]interface{}) {
		header := recipient.(map[string]interface{})["header"].(map[string]interface{})
		header["epk"].(map[string]interface{})["p"] = "AQ"
	}
	raw, _ := json.Marshal(message)
	parsed, err := jose.ParseEncrypted(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []*ecdsa.PrivateKey{key, second} {
		if _, _, _, err = parsed.DecryptMulti(private); err == nil {
			t.Fatal("private EPK accepted")
		}
	}
}
