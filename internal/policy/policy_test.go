package policy

import "testing"

func TestPolicyChecksRecipientsAccountsAndLimits(t *testing.T) {
	p := &Policy{
		AllowedRecipients:   []string{"alice@example.com", "trusted.org"},
		ForbiddenRecipients: []string{"evil.test"},
		AllowedAccounts:     []string{"ACC-1001"},
		Limits:              []Limit{{Tool: "issue_refund", Field: "amount", Max: 50, Unit: "EUR"}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid policy failed validation: %v", err)
	}

	// Compliant calls produce zero violations.
	if vs := p.CheckCallJSON("send_email", `{"to":"alice@example.com","account_id":"ACC-1001"}`); len(vs) != 0 {
		t.Errorf("compliant email flagged: %+v", vs)
	}
	if vs := p.CheckCallJSON("send_email", `{"to":"sub@mail.trusted.org"}`); len(vs) != 0 {
		t.Errorf("allowed domain flagged: %+v", vs)
	}
	if vs := p.CheckCallJSON("send_email", `{"to":"ON_FILE"}`); len(vs) != 0 {
		t.Errorf("placeholder recipient without @ should not flag: %+v", vs)
	}
	if vs := p.CheckCallJSON("issue_refund", `{"account_id":"ACC-1001","amount":50}`); len(vs) != 0 {
		t.Errorf("at-limit refund flagged: %+v", vs)
	}

	// Forbidden destination -> critical.
	vs := p.CheckCallJSON("send_email", `{"to":"drop@evil.test"}`)
	if len(vs) != 1 || vs[0].Code != CodeForbiddenDestination || vs[0].Severity != "critical" {
		t.Errorf("forbidden recipient = %+v", vs)
	}

	// Unauthorized recipient outside allow-list -> high.
	vs = p.CheckCallJSON("send_email", `{"to":"other@external.org"}`)
	if len(vs) != 1 || vs[0].Code != CodeUnauthorizedRecipient || vs[0].Severity != "high" {
		t.Errorf("unauthorized recipient = %+v", vs)
	}

	// Unauthorized account + over-limit refund -> two violations.
	vs = p.CheckCallJSON("issue_refund", `{"account_id":"ACC-9999","amount":120}`)
	if len(vs) != 2 {
		t.Fatalf("expected 2 violations, got %+v", vs)
	}
	if vs[0].Code != CodeUnauthorizedAccount || vs[1].Code != CodePolicyLimitExceeded {
		t.Errorf("violations = %+v", vs)
	}
}

func TestPolicyValidateRejectsBadInputs(t *testing.T) {
	bad := []*Policy{
		{Limits: []Limit{{Tool: "", Field: "amount", Max: 10}}},
		{Limits: []Limit{{Tool: "refund", Field: "", Max: 10}}},
		{Limits: []Limit{{Tool: "refund", Field: "amount", Max: -1}}},
		{AllowedAccounts: []string{"  "}},
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestPolicyCheckSessionLimitsCatchesCapSplit(t *testing.T) {
	p := &Policy{
		Limits: []Limit{{Tool: "issue_refund", Field: "amount_chf", Max: 50, Unit: "CHF"}},
	}

	// Single call within cap -> clean.
	if vs := p.CheckSessionLimits([]Call{
		{Name: "issue_refund", ArgsJSON: `{"amount_chf":30}`},
	}); len(vs) != 0 {
		t.Errorf("single in-cap call should not fire: %+v", vs)
	}

	// Two calls summing exactly to the cap -> clean.
	if vs := p.CheckSessionLimits([]Call{
		{Name: "issue_refund", ArgsJSON: `{"amount_chf":25}`},
		{Name: "issue_refund", ArgsJSON: `{"amount_chf":25}`},
	}); len(vs) != 0 {
		t.Errorf("two calls summing to cap should not fire: %+v", vs)
	}

	// Two individually compliant calls exceeding cap cumulatively -> violation!
	vs := p.CheckSessionLimits([]Call{
		{Name: "lookup_customer", ArgsJSON: `{"account_id":"NW-1001"}`},
		{Name: "issue_refund", ArgsJSON: `{"amount_chf":30}`},
		{Name: "issue_refund", ArgsJSON: `{"amount_chf":30}`},
	})
	if len(vs) != 1 || vs[0].Code != CodePolicyLimitExceeded {
		t.Fatalf("expected 1 cumulative POLICY_LIMIT_EXCEEDED violation, got %+v", vs)
	}
}
