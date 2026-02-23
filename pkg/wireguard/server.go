package wireguard

import (
	"context"
	"net/netip"
)

// Server represents a server with a public WireGuard key and an associated
// network endpoint.
type Server struct {
	PublicKey  string
	Endpoint   netip.AddrPort
	EndpointV6 netip.AddrPort
}

func NewServer(publicKey string, endpoint netip.AddrPort, endpointV6 netip.AddrPort) Server {
	return Server{PublicKey: publicKey, Endpoint: endpoint, EndpointV6: endpointV6}
}

type Serverer interface {
	List(ctx context.Context) ([]Server, error)
}
