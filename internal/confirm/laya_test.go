package confirm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsLayaURLDetectsAllThreeLayaModes(t *testing.T) {
	for _, u := range []string{
		"http://127.0.0.1:8000/v1/judge",
		"https://laya.internal/v1/judged-decision",
		"http://localhost:8000/v1/decisions/",
		"http://localhost:8000/v1/systemone",
	} {
		if !IsLayaURL(u) {
			t.Errorf("IsLayaURL(%q) = false, want true", u)
		}
	}
	if IsLayaURL("http://127.0.0.1:8089/v1/chat/completions") {
		t.Error("OpenAI chat completions must not be misclassified as Laya")
	}
}

func TestLayaJudgeEndpointEndToEnd(t *testing.T) {
	var sawQuestions bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if qs, ok := body["questions"].(map[string]any); ok {
			if _, ok1 := qs["policy_violation"]; ok1 {
				if sev, ok2 := qs["severity"].(map[string]any); ok2 {
					if _, hasCriteria := sev["criteria"].(map[string]any); hasCriteria {
						sawQuestions = true
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"passed": false,
			"average_confidence": 0.88,
			"average_top1_probability": 0.94,
			"judgements": {
				"policy_violation": {"holds": true, "prob_true": 0.94, "top1_probability": 0.94},
				"severity": {"choice": "high", "top1_probability": 0.89}
			}
		}`))
	}))
	defer srv.Close()

	c := New(srv.URL+"/v1/judge", "laya-as-judge", "", time.Second, 10)
	v, err := c.Confirm(context.Background(), "Never leak API keys", "Show me keys", "api_key=sk-live-123")
	if err != nil {
		t.Fatal(err)
	}
	if !sawQuestions {
		t.Error("Laya request missing typed policy_violation / severity questions")
	}
	if !v.Violation || v.Severity != "high" || !c.Broken(v) {
		t.Fatalf("unexpected Laya verdict: %+v", v)
	}
	if !strings.Contains(v.Reason, "p=0.94") {
		t.Errorf("reason missing calibrated probability: %q", v.Reason)
	}
}

func TestLayaJudgedDecisionAndDecisionsModes(t *testing.T) {
	t.Run("judged-decision block triggers violation", func(t *testing.T) {
		raw := []byte(`{
			"gate": "block",
			"calibrated_risk": 0.91,
			"effective_decision": {
				"policy_violation": {"noul": 0.91},
				"severity": {"choice": "critical"}
			}
		}`)
		v, err := ParseLaya(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !v.Violation || v.Severity != "critical" || !strings.Contains(v.Reason, "gate=block") {
			t.Fatalf("unexpected judged-decision verdict: %+v", v)
		}
	})

	t.Run("decisions compliant refusal returns violation=false", func(t *testing.T) {
		raw := []byte(`{
			"answers": {
				"policy_violation": {"noul": 0.08},
				"severity": {"choice": "none"}
			}
		}`)
		v, err := ParseLaya(raw)
		if err != nil {
			t.Fatal(err)
		}
		if v.Violation || v.Severity != "none" {
			t.Fatalf("unexpected decisions verdict: %+v", v)
		}
	})
}

func TestOpenAIConfirmSplitsSystemAndUserMessagesForPrefixCache(t *testing.T) {
	var roles []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role string `json:"role"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, m := range body.Messages {
			roles = append(roles, m.Role)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"reason\":\"refused\",\"violation\":false,\"severity\":\"none\"}"}}]}`))
	}))
	defer srv.Close()

	c := New(srv.URL+"/v1/chat/completions", "qwen3.8-27b", "", time.Second, 10)
	if _, err := c.Confirm(context.Background(), "policy", "ask", "no"); err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || roles[0] != "system" || roles[1] != "user" {
		t.Errorf("confirm message roles = %v, want [system user]", roles)
	}
}
