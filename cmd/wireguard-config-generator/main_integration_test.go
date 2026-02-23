package main

import (
	"context"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"

	"github.com/xbnz/wireguard-config-generator/internal/enums"
	wireguard2 "github.com/xbnz/wireguard-config-generator/pkg/wireguard"
)

type SpyConfigGenerator struct {
	ListCalledTimes int
	ListFunc        func(
		ctx context.Context,
		interfaceAddresses []netip.Prefix,
		allowedIPs []netip.Prefix,
		persistentKeepalive uint16,
		dns []netip.Addr,
	) ([]wireguard2.Configuration, error)
}

func (s *SpyConfigGenerator) List(
	ctx context.Context,
	interfaceAddresses []netip.Prefix,
	allowedIPs []netip.Prefix,
	persistentKeepalive uint16,
	dns []netip.Addr,
) ([]wireguard2.Configuration, error) {
	s.ListCalledTimes++
	return s.ListFunc(
		ctx,
		interfaceAddresses,
		allowedIPs,
		persistentKeepalive,
		dns,
	)
}

func TestMain_Run(t *testing.T) {
	t.Run("test main run()", func(t *testing.T) {
		spyConfigGenerator := &SpyConfigGenerator{}
		spyConfigGenerator.ListFunc = func(ctx context.Context, interfaceAddresses []netip.Prefix, allowedIPs []netip.Prefix, persistentKeepalive uint16, dns []netip.Addr) ([]wireguard2.Configuration, error) {
			return []wireguard2.Configuration{
				wireguard2.NewConfiguration(
					"private_key",
					interfaceAddresses,
					dns,
					[]wireguard2.PeerConfig{
						wireguard2.NewPeerConfig(
							"public_key",
							netip.MustParseAddrPort("1.1.1.1:51820"),
							[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
							25,
						),
					},
				),
			}, nil
		}
		tempDir := t.TempDir()
		app := &App{}
		app.Config.Provider = "test"
		app.Config.OutputDir = tempDir
		app.Config.InterfaceAddresses = "10.0.0.0/24,10.0.1.0/24"
		app.Config.AllowedIPs = "10.0.0.0/24,10.0.1.0/24"
		app.Config.DNS = "8.8.8.8, 1.1.1.1"
		app.Config.PersistentKeepalive = "25"

		app.Provider = enums.NopProvider()
		app.Ctx = context.Background()
		app.Validator = validator.New(validator.WithRequiredStructEnabled())
		app.ConfigGenerator = spyConfigGenerator

		err := run(app)
		if err != nil {
			t.Fatal(err)
		}

		assert.DirExists(t, tempDir)
		assert.FileExists(t, filepath.Join(tempDir, "test_0.conf"))
		assert.Equal(t, 1, spyConfigGenerator.ListCalledTimes)

		fileContent, err := os.ReadFile(filepath.Join(tempDir, "test_0.conf"))
		if err != nil {
			log.Fatal(err)
		}

		goldenContent, err := os.ReadFile("testdata/test_0.conf.golden")
		if err != nil {
			log.Fatal(err)
		}
		assert.Equal(t, goldenContent, fileContent)
	})
}
