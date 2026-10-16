// Package scope answers one question: is this IP or hostname, right now,
// inside the authorized engagement scope? It has no knowledge of
// networking, proxies, or CLI concerns — it is meant to be imported
// directly by third-party tools, not just consumed through Marque's
// own CLI.
package scope

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode controls how a consumer should react to a Decision where
// Allowed is false. Scope itself always computes the same underlying
// Allowed value regardless of Mode — Mode is metadata for the caller,
// not a change to the matching logic.
type Mode int

const (
	// ModeEnforce means a consumer should block denied targets.
	ModeEnforce Mode = iota
	// ModeWarn means a consumer should allow denied targets through
	// but log a loud violation warning. Used to observe what enforce
	// would block before trusting it.
	ModeWarn
	// ModeDryRun means a consumer should take no real action at all —
	// evaluate and report decisions without live traffic or exec.
	ModeDryRun
)

// String renders m as the same lowercase name used in a scope file's
// mode field ("enforce", "warn", "dry-run").
func (m Mode) String() string {
	switch m {
	case ModeEnforce:
		return "enforce"
	case ModeWarn:
		return "warn"
	case ModeDryRun:
		return "dry-run"
	default:
		return "unknown"
	}
}

// MarshalJSON renders Mode as its string name, so audit logs and
// --json CLI output read "enforce" rather than a bare integer.
func (m Mode) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.String())
}

// UnmarshalJSON accepts the same string names Mode renders via
// MarshalJSON, and rejects anything parseMode wouldn't accept from a
// scope file.
func (m *Mode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	mode, err := parseMode(s)
	if err != nil {
		return err
	}
	*m = mode
	return nil
}

func parseMode(raw string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "enforce":
		return ModeEnforce, nil
	case "warn":
		return ModeWarn, nil
	case "dry-run", "dryrun":
		return ModeDryRun, nil
	default:
		return 0, fmt.Errorf("mode %q is invalid: must be enforce, warn, or dry-run", raw)
	}
}

// Scope is a parsed, validated engagement scope: an authorized window
// in time plus the CIDRs and domains a target must fall inside (and
// outside any exclusion) to be in scope.
type Scope struct {
	// Name is the engagement name from the scope file, e.g. "acme-2026q4".
	Name string
	// Client is the client name from the scope file, e.g. "Acme Corp".
	// Optional — never required, never validated beyond trimming.
	Client string
	// Start is the beginning of the authorized engagement window.
	Start time.Time
	// End is the end of the authorized engagement window, or nil for
	// an open-ended engagement (e.g. a bug bounty program with no
	// fixed end date) — see Parse for how an omitted engagement.end
	// in the scope file maps to this.
	End *time.Time
	// Mode is the scope file's declared mode, carried through to every
	// Decision unchanged — see Mode's doc comment for what it means.
	Mode Mode
	// IncludeRules holds the include entries exactly as declared in
	// the scope file, in declaration order. Check/CheckHost don't use
	// these directly (they match against the parsed CIDR/domain rules
	// below) — these are for a consumer that wants to display what's
	// in scope, like `marque validate`.
	IncludeRules []string
	// ExcludeRules is the same, for the scope file's exclude entries.
	ExcludeRules []string

	includeCIDRs   []cidrRule
	excludeCIDRs   []cidrRule
	includeDomains []domainRule
	excludeDomains []domainRule
}

type file struct {
	Engagement struct {
		Name   string `yaml:"name"`
		Client string `yaml:"client"`
		Start  string `yaml:"start"`
		End    string `yaml:"end"`
	} `yaml:"engagement"`
	Scope struct {
		Include []string `yaml:"include"`
		Exclude []string `yaml:"exclude"`
	} `yaml:"scope"`
	Mode string `yaml:"mode"`
}

// Load reads and parses a scope file from disk. See Parse for the
// validation rules applied to its contents.
func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scope file: %w", err)
	}
	return Parse(data)
}

// Parse validates and builds a Scope from raw scope-file bytes.
//
// Parse fails closed: any ambiguity or malformed input is a returned
// error, never a Scope that silently permits more than intended. It
// never panics, including on arbitrary/garbage input — this is a
// fuzz-tested invariant (see fuzz_test.go), not just an aspiration.
func Parse(data []byte) (*Scope, error) {
	var f file
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing scope file: %w", err)
	}

	name := strings.TrimSpace(f.Engagement.Name)
	if name == "" {
		return nil, fmt.Errorf("engagement.name is required")
	}

	start, err := time.Parse(time.RFC3339, strings.TrimSpace(f.Engagement.Start))
	if err != nil {
		return nil, fmt.Errorf("engagement.start %q is not valid ISO 8601: %w", f.Engagement.Start, err)
	}

	// engagement.end is optional: an absent/empty key means an
	// open-ended engagement (no hard end date), e.g. a bug bounty
	// program with no fixed close. A present-but-malformed value is
	// still a hard parse error, same as always.
	var end *time.Time
	if trimmedEnd := strings.TrimSpace(f.Engagement.End); trimmedEnd != "" {
		parsedEnd, err := time.Parse(time.RFC3339, trimmedEnd)
		if err != nil {
			return nil, fmt.Errorf("engagement.end %q is not valid ISO 8601: %w", f.Engagement.End, err)
		}
		if !parsedEnd.After(start) {
			return nil, fmt.Errorf("engagement.end (%s) must be after engagement.start (%s)", f.Engagement.End, f.Engagement.Start)
		}
		end = &parsedEnd
	}

	mode, err := parseMode(f.Mode)
	if err != nil {
		return nil, err
	}

	s := &Scope{Name: name, Client: strings.TrimSpace(f.Engagement.Client), Start: start, End: end, Mode: mode}

	for _, raw := range f.Scope.Include {
		trimmed, err := s.addRule(raw, true)
		if err != nil {
			return nil, err
		}
		s.IncludeRules = append(s.IncludeRules, trimmed)
	}
	for _, raw := range f.Scope.Exclude {
		trimmed, err := s.addRule(raw, false)
		if err != nil {
			return nil, err
		}
		s.ExcludeRules = append(s.ExcludeRules, trimmed)
	}

	if len(s.includeCIDRs) == 0 && len(s.includeDomains) == 0 {
		return nil, fmt.Errorf("scope.include must contain at least one CIDR or domain")
	}

	return s, nil
}

// addRule classifies and stores a single scope entry, returning its
// trimmed form so the caller can record it in declaration order.
func (s *Scope) addRule(raw string, include bool) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("scope entry cannot be empty")
	}

	if looksLikeCIDROrIP(trimmed) {
		ipnet, err := parseCIDROrIP(trimmed)
		if err != nil {
			return "", err
		}
		rule := cidrRule{raw: trimmed, ipnet: ipnet}
		if include {
			s.includeCIDRs = append(s.includeCIDRs, rule)
		} else {
			s.excludeCIDRs = append(s.excludeCIDRs, rule)
		}
		return trimmed, nil
	}

	dr, err := parseDomainRule(trimmed)
	if err != nil {
		return "", err
	}
	if include {
		s.includeDomains = append(s.includeDomains, dr)
	} else {
		s.excludeDomains = append(s.excludeDomains, dr)
	}
	return trimmed, nil
}
