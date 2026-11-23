package toolscan

import "regexp"

type rule struct {
	id         string
	title      string
	severity   string
	class      string
	labels     []string
	provenance []string
	re         *regexp.Regexp
	kinds      map[string]bool
}

func kinds(ks ...string) map[string]bool {
	m := make(map[string]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

var instructionKinds = kinds(KindServerInstructions)

var injectionRules = []rule{
	{
		id: "injection.ignore_previous", title: "Overrides prior instructions",
		severity: "critical", class: "injection",
		labels: []string{"ignore_previous"}, provenance: []string{"MCP04", "ASI03"},
		re: regexp.MustCompile(`(?i)\b((?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|earlier)\s+(?:instructions?|rules?|prompts?|directives?|guidelines?)|disregard\s+(?:the\s+)?above|forget\s+(?:all\s+)?earlier|ignore\s+all\s+prior|disregard\s+previous)`),
	},
	{
		id: "injection.conceal_from_user", title: "Directs the agent to hide actions from the user",
		severity: "high", class: "injection",
		labels: []string{"conceal_from_user"}, provenance: []string{"MCP04", "ASI03"},
		re: regexp.MustCompile(`(?i)\b(?:do\s+not|don't|never)\s+(?:mention|inform|tell|notify|alert|reveal|disclose|show|explain)\b.{0,48}\b(?:user|human|caller|operator|this\s+(?:step|call|action|process|tool|operation|check))\b`),
	},
	{
		id: "injection.mandatory_precheck", title: "Fabricates a mandatory pre-authorization or compliance ritual in tool metadata",
		severity: "medium", class: "injection",
		labels: []string{"mandatory_precheck"}, provenance: []string{"MCP04", "ASI03"},
		re: regexp.MustCompile(`(?i)\bmandatory\s+(?:pre-?auth\w*|security|compliance|verification|audit|safety|initialization|diagnostic)\s+(?:check|step|protocol|verification|procedure)\b`),
	},
	{
		id: "injection.imperative_override", title: "Replaces the agent's identity or role",
		severity: "critical", class: "injection",
		labels: []string{"imperative_override"}, provenance: []string{"MCP09", "ASI07"},
		re: regexp.MustCompile(`(?i)\b(you\s+are\s+(now|no\s+longer)|from\s+now\s+on(?:\s*,)?\s+(?:you\s+are|pretend\s+you\s+are)|(?:replace|discard)\s+your\s+(?:(?:current|system)\s+)?(?:role|identity|persona)|your\s+new\s+(?:role|identity|persona|instructions))`),
	},
	{
		id: "injection.important_tag", title: "Injected <IMPORTANT> block",
		severity: "critical", class: "injection",
		labels: []string{"important_tag"}, provenance: []string{"MCP04", "ASI03"},
		re: regexp.MustCompile(`(?i)</?IMPORTANT>`),
	},
	{
		id: "injection.instructions_tag", title: "Injected <instructions> block",
		severity: "critical", class: "injection",
		labels: []string{"instructions_tag"}, provenance: []string{"MCP04", "ASI03"},
		re: regexp.MustCompile(`(?i)</?instructions>`),
	},
	{
		id: "injection.system_tag", title: "Simulated <system> block",
		severity: "critical", class: "injection",
		labels: []string{"system_tag"}, provenance: []string{"MCP04", "ASI03"},
		re: regexp.MustCompile(`(?i)</?system>`),
	},
	{
		id: "injection.control_boundary", title: "Chat-template or system-prompt boundary marker",
		severity: "high", class: "injection",
		labels: []string{"control_boundary"}, provenance: []string{"MCP04", "ASI03"},
		re: regexp.MustCompile(`(?i)(\[/?INST\]|<\|(?:im_start|im_end|system|user|assistant)\|>|\bsystem\s+prompt\s*:)`),
	},
	{
		id: "steering.always_use", title: "Directs the agent to always use this tool",
		severity: "medium", class: "injection",
		labels: []string{"always_use"}, provenance: []string{"MCP04", "ASI03"},
		re: regexp.MustCompile(`(?i)\b(always\s+use\s+this\s+tool|you\s+must\s+use)`),
	},
	{
		id: "steering.never_use_other", title: "Directs the agent away from other tools",
		severity: "medium", class: "injection",
		labels: []string{"never_use_other"}, provenance: []string{"MCP04", "ASI03"},
		re: regexp.MustCompile(`(?i)\b(never\s+use|do\s+not\s+use)\b`),
	},
	{
		id: "steering.instead_of", title: "Redirects tool selection away from another tool",
		severity: "medium", class: "injection",
		labels: []string{"instead_of"}, provenance: []string{"MCP04", "ASI03"},
		re: regexp.MustCompile(`(?i)\b(instead\s+of\s+\w+|use\s+this\s+instead)`),
	},
	{
		id: "instruction.curl_wget", title: "Shell fetch of a remote URL in advertised context",
		severity: "critical", class: "injection",
		labels: []string{"curl_wget"}, provenance: []string{"MCP09", "ASI07"},
		re:    regexp.MustCompile(`(?i)\b(curl|wget)\s+.{0,5}https?://`),
		kinds: instructionKinds,
	},
}

var (
	steeringPattern    = regexp.MustCompile(`(?i)\b(instead\s+of|use\s+this\s+instead|always\s+use|never\s+use|do\s+not\s+use|prefer\s+this)`)
	prereqHookPattern  = regexp.MustCompile(`(?i)\b(before|prior\s+to|after|whenever|when)\s+(using|calling|invoking|executing|running)\b`)
	prereqObligPattern = regexp.MustCompile(`(?i)\b(must|mandatory|required|always|first\s+(call|invoke|run|execute|use)|silently|secretly|do\s+not\s+(tell|mention|inform)|critical|crucial|essential)\b`)
)

func rulesFor(kind string) []rule {
	out := make([]rule, 0, len(injectionRules))
	for _, r := range injectionRules {
		if r.kinds == nil || r.kinds[kind] {
			out = append(out, r)
		}
	}
	return out
}

var capabilityRules = []struct {
	label string
	re    *regexp.Regexp
}{
	{"shell_access", regexp.MustCompile(`(?is)(\bsh\s+-c\b|\bshell[ _-]?command\b|\b(run|execute|exec|spawn|invoke)\b.{0,48}\b(shell|bash|terminal|command|subprocess|powershell)\b|\b(shell|bash|terminal|command|subprocess|powershell)\b.{0,48}\b(run|execute|exec|spawn|invoke)\b)`)},
	{"code_execution", regexp.MustCompile(`(?is)(\beval\b|\b(run|execute|exec|spawn|invoke|compile|interpret)[_ -]?(code|python|javascript|lambda|script)\b|\b(run|execute|exec|interpret)\b\s+(a|an|the\s+)?(arbitrary|provided|supplied|user[- ]provided|source\s+)?(code|python|javascript|lambda|script)\b)`)},
	{"credential_access", regexp.MustCompile(`(?is)\b(secret|credential|api[_ -]?key|password|token|private[_ -]?key|vault)\b`)},
	{"database_access", regexp.MustCompile(`(?is)\b(sql|query|database|postgres|mysql|mongodb|redis|select\s+\*|drop\s+table)\b`)},
	{"file_write", regexp.MustCompile(`(?is)\b(write|save|create|append|delete|remove|overwrite)[_ -]?(file|to\s+disk|path)\b`)},
	{"network_outbound", regexp.MustCompile(`(?is)\b(fetch|request|webhook|http[_ -]?(get|post)|download|upload|send\s+to)\b`)},
	{"email_send", regexp.MustCompile(`(?is)\b(send[_ -]?(mail|email)|smtp|sendmail)\b`)},
}

var exfilURLPattern = regexp.MustCompile(`(?i)https?://[^\s"'` + "`" + `]+[?&](data|token|secret|password|key|credential)=`)
