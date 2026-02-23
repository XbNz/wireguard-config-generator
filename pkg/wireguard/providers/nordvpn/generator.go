package nordvpn

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/samber/lo"

	"github.com/xbnz/wireguard-config-generator/pkg/wireguard"
)

// ConfigGenerator is responsible for generating WireGuard configurations using
// a private Key and server fetcher.
type ConfigGenerator struct {
	privateKeyFetcher privateKey
	serverFetcher     server
}

// NewConfigGenerator initializes and returns a ConfigGenerator with the
// provided private Key and server fetchers.
func NewConfigGenerator(
	privateKeyFetcher privateKey,
	serverFetcher server,
) *ConfigGenerator {
	return &ConfigGenerator{
		privateKeyFetcher: privateKeyFetcher,
		serverFetcher:     serverFetcher,
	}
}

// List generates WireGuard configurations based on provided interface
// addresses, allowed IPs, DNS, and server details.
func (c *ConfigGenerator) List(
	ctx context.Context,
	interfaceAddresses []netip.Prefix,
	allowedIPs []netip.Prefix,
	persistentKeepalive uint16,
	dns []netip.Addr,
) ([]wireguard.Configuration, error) {
	pk, err := c.privateKeyFetcher.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"fetching private Key from config generator: %w",
			err,
		)
	}

	servers, err := c.serverFetcher.List(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"fetching servers from config generator: %w",
			err,
		)
	}

	return lo.Map(servers, func(ns NordServer, _ int) wireguard.Configuration {
		peer := wireguard.NewPeerConfig(
			ns.PublicKey,
			ns.Endpoint,
			allowedIPs,
			persistentKeepalive,
		)

		return wireguard.NewConfiguration(
			string(pk),
			interfaceAddresses,
			dns,
			[]wireguard.PeerConfig{peer},
		)
	}), nil
}
