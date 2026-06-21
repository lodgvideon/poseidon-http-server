package middleware

import (
	"context"
	"net"
	"strings"

	"github.com/lodgvideon/poseidon-http-client/hpack"
	"github.com/lodgvideon/poseidon-http-server/server"
)

// ---------------------------------------------------------------------------
// RealIP — trusted-proxy client IP resolution
// ---------------------------------------------------------------------------
//
// RealIP resolves the real client IP from X-Forwarded-For / X-Real-IP, but
// ONLY when the immediate peer (the TCP connection's remote address) is itself
// a member of a configured set of trusted proxy CIDRs. This is secure by
// default: with no trusted proxies configured the middleware trusts NOTHING,
// so a client cannot spoof its address by sending forged forwarding headers —
// the peer address is used verbatim.
//
// The resolved IP is stored in the request context and retrieved with
// [ClientIP]. The immediate peer address is sourced from the context via
// [PeerAddr]; the server populates it per-connection (see [WithPeerAddr]),
// which also lets tests drive the middleware without a live connection.

// realIPCtxKey and peerAddrCtxKey are distinct from middleware.ctxKey so the
// integer values cannot collide with the RequestID key.
type realIPCtxKey struct{}

type peerAddrCtxKey struct{}

// Trusted-proxy forwarding headers, lower-cased to match HPACK field names.
const (
	hdrXForwardedFor = "x-forwarded-for"
	hdrXRealIP       = "x-real-ip"
)

// RealIPConfig configures the RealIP middleware.
type RealIPConfig struct {
	// TrustedProxies is the set of proxy addresses whose forwarding headers
	// are honored. Each entry is a CIDR ("10.0.0.0/8", "::1/128") or a bare
	// IP ("10.0.0.1", treated as a /32 or /128 host route). Malformed entries
	// are ignored. An empty/nil set trusts nothing (secure default).
	TrustedProxies []string
}

// RealIP returns a middleware that resolves the client IP from forwarding
// headers when the immediate peer is a trusted proxy, falling back to the peer
// address otherwise. The result is available to downstream handlers via
// [ClientIP].
func RealIP(cfg RealIPConfig) server.Middleware {
	trusted := parseCIDRs(cfg.TrustedProxies)

	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(ctx context.Context, req *server.Request, w server.ResponseWriter) error {
			peer := PeerAddr(ctx)
			clientIP := resolveClientIP(peer, req.Headers, trusted)
			if clientIP != "" {
				ctx = context.WithValue(ctx, realIPCtxKey{}, clientIP)
			}
			return next.ServeHTTP(ctx, req, w)
		})
	}
}

// ClientIP returns the client IP resolved by the RealIP middleware, or "" if
// RealIP did not run or could not resolve an address.
func ClientIP(ctx context.Context) string {
	if v, ok := ctx.Value(realIPCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// WithPeerAddr returns a copy of ctx carrying the immediate peer's network
// address (host:port form as from net.Conn.RemoteAddr().String()). The server
// sets this per request; RealIP reads it via [PeerAddr].
func WithPeerAddr(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, peerAddrCtxKey{}, addr)
}

// PeerAddr returns the immediate peer address previously set with
// [WithPeerAddr], or "" if none was set.
func PeerAddr(ctx context.Context) string {
	if v, ok := ctx.Value(peerAddrCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// resolveClientIP implements the trust decision. peer is the raw peer address
// (host:port or host); headers are the request headers; trusted is the parsed
// set of trusted proxy networks.
func resolveClientIP(peer string, headers []hpack.HeaderField, trusted []*net.IPNet) string {
	peerIP := hostOnly(peer)

	// Secure default / untrusted peer: never honor forwarding headers.
	if !ipInAny(peerIP, trusted) {
		return peerIP
	}

	// Peer is trusted — honor forwarding headers. X-Forwarded-For first
	// (it carries the full hop chain), then X-Real-IP as a fallback.
	if xff := forwardHeader(headers, hdrXForwardedFor); xff != "" {
		if ip := clientFromXFF(xff, trusted); ip != "" {
			return ip
		}
	}
	if xr := forwardHeader(headers, hdrXRealIP); xr != "" {
		if ip := normalizeIP(xr); ip != "" {
			return ip
		}
	}

	// Trusted peer but no usable forwarding header — use the peer itself.
	return peerIP
}

// clientFromXFF walks an X-Forwarded-For value right-to-left and returns the
// rightmost address that is NOT a trusted proxy (the real client). If every
// hop is trusted it returns the leftmost (claimed origin). Returns "" if the
// header contains no parseable address.
func clientFromXFF(xff string, trusted []*net.IPNet) string {
	parts := strings.Split(xff, ",")

	var leftmost string
	for i := len(parts) - 1; i >= 0; i-- {
		ip := normalizeIP(strings.TrimSpace(parts[i]))
		if ip == "" {
			continue
		}
		leftmost = ip // tracks the last (leftmost) valid IP seen
		if !ipInAny(ip, trusted) {
			return ip
		}
	}
	return leftmost
}

// parseCIDRs converts the configured trusted-proxy entries into networks,
// accepting both CIDR ("10.0.0.0/8") and bare-IP ("10.0.0.1") forms. Invalid
// entries are skipped.
func parseCIDRs(entries []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			// Bare IP → host route (/32 or /128).
			if ip := net.ParseIP(e); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				nets = append(nets, &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(bits, bits),
				})
			}
			continue
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// ipInAny reports whether ip (string form) is contained in any of nets.
func ipInAny(ip string, nets []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// hostOnly strips a trailing :port from a peer address, tolerating bare hosts,
// bracketed IPv6 ("[::1]:443"), and addresses with no port at all.
func hostOnly(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	// No port (or unbalanced brackets): strip surrounding brackets if present.
	addr = strings.TrimPrefix(addr, "[")
	addr = strings.TrimSuffix(addr, "]")
	return addr
}

// normalizeIP validates a candidate IP string and returns its canonical form,
// or "" if it is not a valid IP address.
func normalizeIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// forwardHeader returns the value of the first header whose (lower-cased) name
// matches want, or "" if absent.
func forwardHeader(headers []hpack.HeaderField, want string) string {
	for _, h := range headers {
		if string(h.Name) == want {
			return string(h.Value)
		}
	}
	return ""
}
