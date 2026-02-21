package nordvpn

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/samber/lo"
	"github.com/xbnz/wireguard-config-generator/internal/wireguard"
)

type ConfigGenerator struct {
	client            *http.Client
	privateKeyFetcher privateKey
	serverFetcher     server
}

func NewConfigGenerator(
	client *http.Client,
	privateKeyFetcher privateKey,
	serverFetcher server,
) *ConfigGenerator {
	return &ConfigGenerator{
		client:            client,
		privateKeyFetcher: privateKeyFetcher,
		serverFetcher:     serverFetcher,
	}
}

func (c *ConfigGenerator) List(
	ctx context.Context,
	interfaceAddresses []netip.Prefix,
	allowedIPs []netip.Prefix,
	persistentKeepalive uint16,
	dns []netip.Addr,
) ([]wireguard.Configuration, error) {
	pk, err := c.privateKeyFetcher.fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching private key from config generator: %w", err)
	}

	servers, err := c.serverFetcher.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching servers from config generator: %w", err)
	}

	return lo.Map(servers, func(ns nordServer, _ int) wireguard.Configuration {
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
