// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kubernetes

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/hashicorp/errwrap"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/command/agentproxyshared/auth"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
)

func TestKubernetesAuth_basic(t *testing.T) {
	testCases := map[string]struct {
		tokenPath string
		data      *mockJWTFile
		e         error
	}{
		"normal": {
			data: newMockJWTFile(jwtData),
		},
		"projected": {
			tokenPath: "/some/other/path",
			data:      newMockJWTFile(jwtProjectedData),
		},
		"not_found": {
			e: errors.New("open /var/run/secrets/kubernetes.io/serviceaccount/token: no such file or directory"),
		},
		"projected_not_found": {
			tokenPath: "/some/other/path",
			e:         errors.New("open /some/other/path: no such file or directory"),
		},
	}

	for k, tc := range testCases {
		t.Run(k, func(t *testing.T) {
			authCfg := auth.AuthConfig{
				Logger:    logging.NewVaultLogger(hclog.Trace),
				MountPath: "kubernetes",
				Config: map[string]interface{}{
					"role": "plugin-test",
				},
			}

			if tc.tokenPath != "" {
				authCfg.Config["token_path"] = tc.tokenPath
			}

			a, err := NewKubernetesAuthMethod(&authCfg)
			if err != nil {
				t.Fatal(err)
			}

			// Type assert to set the kubernetesMethod jwtData, to mock out reading
			// files from the pod.
			k := a.(*kubernetesMethod)
			if tc.data != nil {
				k.jwtData = tc.data
			}

			_, _, data, err := k.Authenticate(t.Context(), nil)
			if err != nil && tc.e == nil {
				t.Fatal(err)
			}

			if err != nil && !errwrap.Contains(err, tc.e.Error()) {
				t.Fatalf("expected \"no such file\" error, got: (%s)", err)
			}

			if err == nil && tc.e != nil {
				t.Fatal("expected error, but got none")
			}

			if tc.e == nil {
				authJWTraw, ok := data["jwt"]
				if !ok {
					t.Fatal("expected to find jwt data")
				}

				authJWT := authJWTraw.(string)
				token := jwtData
				if tc.tokenPath != "" {
					token = jwtProjectedData
				}
				if authJWT != token {
					t.Fatalf("error with auth tokens, expected (%s) got (%s)", token, authJWT)
				}
			}
		})
	}
}

// jwt for default service account
var jwtData = "<CODESTRA_GITLEAKS_FIXTURE_INVALID>"

// jwt for projected service account
var jwtProjectedData = "<CODESTRA_GITLEAKS_FIXTURE_INVALID>"

// mockJWTFile provides a mock ReadCloser struct to inject into
// kubernetesMethod.jwtData
type mockJWTFile struct {
	b *bytes.Buffer
}

var _ io.ReadCloser = &mockJWTFile{}

func (j *mockJWTFile) Read(p []byte) (n int, err error) {
	return j.b.Read(p)
}

func (j *mockJWTFile) Close() error { return nil }

func newMockJWTFile(s string) *mockJWTFile {
	return &mockJWTFile{
		b: bytes.NewBufferString(s),
	}
}
