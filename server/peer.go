package server

import "context"

// peerAddrCtxKey carries the immediate peer's network address on the request
// context.
//
// It lives in this package rather than in middleware because the dependency
// runs middleware -> server: the server has to be able to SET the value that
// middleware.RealIP reads, and it cannot import middleware to reach the key.
// middleware.WithPeerAddr / middleware.PeerAddr delegate here, so both packages
// name the same key.
type peerAddrCtxKey struct{}

// WithPeerAddr returns a copy of ctx carrying the immediate peer's network
// address in host:port form, as from net.Conn.RemoteAddr().String().
//
// The server calls this once per accepted connection, before the HTTP/2
// handshake, so every stream context on that connection inherits the value and
// no per-request work is added. Read it back with [PeerAddr].
//
// "Immediate peer" means the other end of the TCP/TLS connection — a proxy
// rather than the origin client when one is in front of the server. Resolving
// the originating client from forwarding headers is middleware.RealIP's job,
// and it is only safe when this address is a trusted proxy.
func WithPeerAddr(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, peerAddrCtxKey{}, addr)
}

// PeerAddr returns the immediate peer address previously set with
// [WithPeerAddr], or "" if none was set.
func PeerAddr(ctx context.Context) string {
	v, _ := ctx.Value(peerAddrCtxKey{}).(string)
	return v
}
