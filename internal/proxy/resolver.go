package proxy

import (
	"context"
	"net"
)

// Resolver resolves a hostname to its addresses. The one method
// matches *net.Resolver's real signature exactly, so net.DefaultResolver
// satisfies this interface with no wrapping — tests substitute a fake
// with canned answers instead of depending on real DNS, which is what
// makes the DNS-rebinding test deterministic.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}
