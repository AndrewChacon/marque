package scope

import (
	"net"
	"testing"
)

// FuzzParse confirms the scope-file parser never panics on arbitrary
// input and, per the fail-closed principle, never produces a Scope
// whose Check/CheckHost calls panic either — a parser that silently
// accepts something it shouldn't is exactly the garbage-input failure
// mode this project exists to avoid.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`
engagement:
  name: seed
  start: 2026-01-01T00:00:00Z
  end: 2026-01-02T00:00:00Z
scope:
  include: ["10.0.0.0/8", "*.acme.com"]
  exclude: ["10.0.5.0/24"]
mode: enforce
`))
	f.Add([]byte(`
engagement:
  name: seed-open-ended
  start: 2026-01-01T00:00:00Z
scope:
  include: ["10.0.0.0/8"]
mode: enforce
`))
	f.Add([]byte(""))
	f.Add([]byte("not: [valid"))
	f.Add([]byte("engagement: null"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Parse(data)
		if err != nil {
			return
		}
		// A Scope that parsed successfully must never panic when
		// exercised, regardless of how strange the input that built it was.
		_ = s.Check(net.ParseIP("127.0.0.1"))
		_ = s.Check(net.ParseIP("::1"))
		_ = s.CheckHost("example.com")
	})
}

func fuzzTestScope(f *testing.F) *Scope {
	f.Helper()
	doc := []byte(`
engagement:
  name: fuzz
  start: 2000-01-01T00:00:00Z
  end: 2100-01-01T00:00:00Z
scope:
  include: ["*.acme.com", "10.0.0.0/8", "2001:db8::/32"]
  exclude: ["db.internal.acme.com", "10.0.5.0/24"]
mode: enforce
`)
	s, err := Parse(doc)
	if err != nil {
		f.Fatalf("fixed fuzz fixture failed to parse: %v", err)
	}
	return s
}

// FuzzCheckHost confirms the matcher never panics on arbitrary
// hostname input, and that an Allowed decision always carries the
// rule that justified it (never an accidental allow with no reason).
func FuzzCheckHost(f *testing.F) {
	s := fuzzTestScope(f)
	f.Add("foo.acme.com")
	f.Add("db.internal.acme.com")
	f.Add("")
	f.Add("*evil*")
	f.Add("..")
	f.Add("a.......com")

	f.Fuzz(func(t *testing.T, host string) {
		d := s.CheckHost(host)
		if d.Allowed && d.MatchedRule == "" {
			t.Fatalf("CheckHost(%q) allowed with no matching rule recorded", host)
		}
	})
}

// FuzzCheck confirms the IP matcher never panics and never allows
// without a matching rule, across arbitrary address-shaped strings.
func FuzzCheck(f *testing.F) {
	s := fuzzTestScope(f)
	f.Add("10.0.0.1")
	f.Add("10.0.5.1")
	f.Add("2001:db8::1")
	f.Add("not-an-ip")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		ip := net.ParseIP(raw)
		if ip == nil {
			return
		}
		d := s.Check(ip)
		if d.Allowed && d.MatchedRule == "" {
			t.Fatalf("Check(%q) allowed with no matching rule recorded", raw)
		}
	})
}
