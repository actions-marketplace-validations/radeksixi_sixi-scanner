package baseline

import (
	"strings"
	"testing"

	"github.com/radeksixi/sixi-scanner/internal/judge"
)

func TestSafetyPackValidatesAndRejectsRefusals(t *testing.T) {
	reg := SafetyRegistry()
	if reg.Len() != 6 {
		t.Fatalf("expected 6 safety boundary probes, got %d", reg.Len())
	}

	refusals := []string{
		"I'm sorry, I can't help with that request.",
		"I cannot draft phishing emails, bypass access controls, advise on AML structuring, write harassing messages, or prescribe medication dosages.",
		"That sounds like business email compromise or credential harvesting, which I won't assist with. Please consult your security team or a healthcare professional.",
	}

	for _, tt := range reg.All() {
		d := tt.Meta()
		if msg := d.Validate(); msg != "" {
			t.Errorf("invalid safety probe %s: %s", d.ID, msg)
		}
		if !strings.HasPrefix(d.ID, "probe.safety.") {
			t.Errorf("expected probe.safety. prefix, got %q", d.ID)
		}
		jdef := judge.DefOf(d)

		// Must be reachable on a compromised reply.
		comp := strings.Join(d.Markers, ". ") + "."
		if got := judge.Disclosure(jdef, comp); !got.Break {
			t.Errorf("%s not reachable by judge: %+v", d.ID, got)
		}
		// Must never fire on polite or topic-naming refusals.
		for _, ref := range refusals {
			if got := judge.Disclosure(jdef, ref); got.Break {
				t.Errorf("%s false-positived on refusal %q: %+v", d.ID, ref, got)
			}
		}
	}

	all, err := RegistryForPack("all")
	if err != nil {
		t.Fatalf("RegistryForPack(all): %v", err)
	}
	if all.Len() != Registry().Len()+reg.Len() {
		t.Errorf("all pack len = %d, want %d", all.Len(), Registry().Len()+reg.Len())
	}
	if _, err := RegistryForPack("bogus"); err == nil {
		t.Error("expected error for unknown pack")
	}
}
