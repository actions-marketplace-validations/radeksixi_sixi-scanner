package report

import "regexp"

// Ordered redaction patterns: more specific token shapes (JWTs, prefixed API
// keys, DB credentials) run before generic email/IP/number rules so a secret is
// never half-masked as a generic number or email.
var (
	redactJWTRE     = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b`)
	redactDBCredsRE = regexp.MustCompile(`(?i)\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|amqp|mssql)://)[^\s:/@]+:[^\s:/@]+@`)
	redactBearerRE  = regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{20,}`)
	redactAPIKeyRE  = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{16,}|(?:pk|rk)-[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{30,})\b`)
	redactEmailRE   = regexp.MustCompile(`[\w.+-]+@[\w-]+(?:\.[\w-]+)+`)
	redactIPv4RE    = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b`)
	redactLongNumRE = regexp.MustCompile(`\b\d{4}(?:[\s-]?\d{4}){2,3}\b|\b\d{12,}\b`)
)

// RedactText replaces secrets, credentials, email addresses, IPv4 addresses and
// long account/card numbers in s with typed placeholders.
func RedactText(s string) string {
	if s == "" {
		return s
	}
	s = redactJWTRE.ReplaceAllString(s, "[REDACTED_JWT]")
	s = redactDBCredsRE.ReplaceAllString(s, "${1}[REDACTED_SECRET]@")
	s = redactBearerRE.ReplaceAllString(s, "${1}[REDACTED_SECRET]")
	s = redactAPIKeyRE.ReplaceAllString(s, "[REDACTED_SECRET]")
	s = redactEmailRE.ReplaceAllString(s, "[REDACTED_EMAIL]")
	s = redactIPv4RE.ReplaceAllString(s, "[REDACTED_IP]")
	s = redactLongNumRE.ReplaceAllString(s, "[REDACTED_NUMBER]")
	return s
}

// Redact scrubs secrets and PII from every finding's evidence in place while
// leaving pre-computed fingerprints intact so diffing stays consistent.
func (s *Scan) Redact() {
	if s == nil {
		return
	}
	s.Options.Redacted = true
	for i := range s.Findings {
		ev := &s.Findings[i].Evidence
		ev.Prompt = RedactText(ev.Prompt)
		ev.Response = RedactText(ev.Response)
		ev.Reason = RedactText(ev.Reason)
		for j := range ev.Markers {
			ev.Markers[j] = RedactText(ev.Markers[j])
		}
		for j := range ev.Negated {
			ev.Negated[j] = RedactText(ev.Negated[j])
		}
	}
}
