// Copyright (c) 2026 Codestra
// SPDX-License-Identifier: MPL-2.0
package celotelsecurity

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/protobuf/types/known/structpb"
)

type taggedClaims struct {
	Public string `json:"public"`
	Hidden string `json:"-"`
}

func nativeEnv(t *testing.T) *cel.Env {
	t.Helper()
	env, err := cel.NewEnv(cel.Variable("obj", cel.DynType),
		ext.NativeTypes(reflect.TypeOf(taggedClaims{}), ext.ParseStructTag("json")))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestNativeJSONSkipCannotExposeHiddenClaim(t *testing.T) {
	env := nativeEnv(t)
	obj := taggedClaims{Public: "builder", Hidden: "HIDDEN_CLAIM_CANARY"}
	for _, tc := range []struct {
		expr   string
		hidden bool
	}{{"obj.public", false}, {`dyn(obj)["-"]`, true}} {
		ast, issues := env.Compile(tc.expr)
		if issues.Err() != nil {
			t.Fatal(issues.Err())
		}
		p, err := env.Program(ast)
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := p.Eval(map[string]any{"obj": obj})
		if tc.hidden {
			if err == nil {
				t.Fatalf("hidden claim access must fail, got %v", value)
			}
		} else if err != nil || value != types.String("builder") {
			t.Fatalf("public claim changed: %v %v", value, err)
		}
	}
}

func TestNativeJSONConversionOmitsHiddenClaim(t *testing.T) {
	value := nativeEnv(t).CELTypeAdapter().NativeToValue(taggedClaims{Public: "builder", Hidden: "HIDDEN_CLAIM_CANARY"})
	converted, err := value.ConvertToNative(reflect.TypeOf(&structpb.Struct{}))
	if err != nil {
		t.Fatal(err)
	}
	fields := converted.(*structpb.Struct).Fields
	if fields["public"].GetStringValue() != "builder" {
		t.Fatalf("public field lost: %v", fields)
	}
	if _, found := fields["-"]; found {
		t.Fatalf("JSON conversion exposed hidden field")
	}
}

func TestJWTClaimExpressionPreservesAllowDenyAndMalformedBehavior(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("claims", cel.MapType(cel.StringType, cel.DynType)), cel.Variable("now", cel.IntType))
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := env.Compile("claims.sub == 'builder' && claims.aud.exists(a, a == 'codestra') && claims.exp > now")
	if issues.Err() != nil {
		t.Fatal(issues.Err())
	}
	p, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, subject    string
		expiry           any
		allowed, invalid bool
	}{
		{"allow", "builder", int64(200), true, false}, {"wrong-subject", "intruder", int64(200), false, false},
		{"expired", "builder", int64(50), false, false}, {"malformed-expiry", "builder", "200", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, _, err := p.Eval(map[string]any{"claims": map[string]any{"sub": tc.subject, "aud": []string{"codestra"}, "exp": tc.expiry}, "now": int64(100)})
			if tc.invalid {
				if err == nil {
					t.Fatal("malformed claim accepted")
				}
				return
			}
			if err != nil || value != types.Bool(tc.allowed) {
				t.Fatalf("authorization result: %v %v", value, err)
			}
		})
	}
}

type canaryExporter struct{ exported atomic.Int32 }

func (e *canaryExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.exported.Add(int32(len(spans)))
	return nil
}
func (*canaryExporter) Shutdown(context.Context) error { return nil }
func (*canaryExporter) MarshalLog() any {
	return map[string]any{"Endpoint": "https://collector.invalid/TRACE_CONFIG_CANARY"}
}

func TestProviderDiagnosticDoesNotExposeExporterConfiguration(t *testing.T) {
	// Public global logger: this dedicated test process must not run these cases in parallel.
	defer otel.SetLogger(logr.Discard())
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch=%t", batch), func(t *testing.T) {
			var logs bytes.Buffer
			otel.SetLogger(funcr.New(func(prefix, args string) { fmt.Fprintln(&logs, prefix, args) }, funcr.Options{Verbosity: 4}))
			exporter := &canaryExporter{}
			option := sdktrace.WithSyncer(exporter)
			if batch {
				option = sdktrace.WithBatcher(exporter)
			}
			provider := sdktrace.NewTracerProvider(option, sdktrace.WithSampler(sdktrace.AlwaysSample()))
			ctx := context.Background()
			_, span := provider.Tracer("codestra-diagnose-regression").Start(ctx, "probe")
			span.End()
			if err := provider.ForceFlush(ctx); err != nil {
				t.Fatal(err)
			}
			if err := provider.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
			if exporter.exported.Load() != 1 {
				t.Fatalf("expected actual span export, got %d", exporter.exported.Load())
			}
			if !strings.Contains(logs.String(), "TracerProvider created") {
				t.Fatal("verbose diagnostic positive control missing")
			}
			if strings.Contains(logs.String(), "TRACE_CONFIG_CANARY") {
				t.Fatal("provider diagnostics exposed exporter configuration")
			}
		})
	}
}
