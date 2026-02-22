package nordvpn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func TestConfigGenerator_(t *testing.T) {
	t.Run("happy path table tests", func(t *testing.T) {
		const expectedPublicKey = "qIhtTW9K4iXWFo5Q4dOPdXg8/xubXr9yEGoN55D8xnA="

		mockPrivateKeyServer := httptest.NewServer(
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(`{"nordlynx_private_key":"test_key"}`))
			}),
		)
		defer mockPrivateKeyServer.Close()

		mockServerListServer := httptest.NewServer(
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
				rw.Write(
					[]byte(
						fmt.Sprintf(
							`[{"station":"62.3.36.228","technologies":[{"identifier":"wireguard_udp","metadata":[{"name":"public_key","value":"%s"}]}]}]`,
							expectedPublicKey,
						),
					),
				)
			}),
		)
		defer mockServerListServer.Close()

		configGeneratorImpl := NewConfigGenerator(
			new(NewPrivateKey(
				mockPrivateKeyServer.Client(),
				"test_token",
				mockPrivateKeyServer.URL,
			)),
			new(NewServer(
				mockServerListServer.Client(),
				mockServerListServer.URL,
				validator.New(validator.WithRequiredStructEnabled()),
			)),
		)

		tests := []struct {
			name                string
			interfaceAddresses  []netip.Prefix
			allowedIPs          []netip.Prefix
			persistentKeepalive uint16
			dns                 []netip.Addr
		}{
			{
				name: "single ips for all fields",
				interfaceAddresses: []netip.Prefix{
					netip.MustParsePrefix("10.5.0.2/32"),
				},
				allowedIPs: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
				},
				dns: []netip.Addr{
					netip.MustParseAddr("8.8.8.8"),
				},
			},
			{
				name: "multiple ips for all fields",
				interfaceAddresses: []netip.Prefix{
					netip.MustParsePrefix("10.5.0.0/24"),
					netip.MustParsePrefix("10.5.1.0/24"),
				},
				allowedIPs: []netip.Prefix{
					netip.MustParsePrefix("10.6.0.0/24"),
					netip.MustParsePrefix("10.6.1.0/24"),
				},
				dns: []netip.Addr{
					netip.MustParseAddr("8.8.8.8"),
					netip.MustParseAddr("8.8.4.4"),
				},
			},
			{
				name:                "persistent keepalive is set",
				persistentKeepalive: 25,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				configs, err := configGeneratorImpl.List(
					context.Background(),
					tt.interfaceAddresses,
					tt.allowedIPs,
					tt.persistentKeepalive,
					tt.dns,
				)

				assert.Nil(t, err)
				assert.Greater(t, len(configs), 0)

				config := configs[0]

				assert.Equal(t, "test_key", config.PrivateKey)
				expectedIpPort := netip.MustParseAddrPort("62.3.36.228:51820")
				assert.Equal(
					t,
					0,
					config.Peers[0].Endpoint.Compare(expectedIpPort),
				)
				assert.Equal(t, expectedPublicKey, config.Peers[0].PublicKey)
				assert.True(
					t,
					slices.Equal(tt.allowedIPs, config.Peers[0].AllowedIPs),
				)
				assert.Equal(
					t,
					tt.persistentKeepalive,
					config.Peers[0].PersistentKeepalive,
				)
				assert.True(t, slices.Equal(tt.dns, config.DNS))
				assert.True(
					t,
					slices.Equal(
						tt.interfaceAddresses,
						config.InterfaceAddresses,
					),
				)
			})
		}
	})
}
