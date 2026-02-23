package wireguard

import (
	"context"
	"net/netip"
)

type ConfigGenerator interface {
	List(
		ctx context.Context,
		interfaceAddresses []netip.Prefix,
		allowedIPs []netip.Prefix,
		persistentKeepalive uint16,
		dns []netip.Addr,
	) ([]Configuration, error)
}
