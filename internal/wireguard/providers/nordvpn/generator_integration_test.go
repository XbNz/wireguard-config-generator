//go:build integration

package nordvpn

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/xbnz/wireguard-config-generator/internal/path"
)

func TestMain(m *testing.M) {
	moduleRoot, _ := path.ToModuleRoot()
	fileName := filepath.Join(moduleRoot, ".env.testing")

	if _, err := os.Stat(fileName); err == nil {
		if err := godotenv.Load(fileName); err != nil {
			panic(err)
		}
	}

	os.Exit(m.Run())
}

func TestConfigGenerator_List(t *testing.T) {
	t.Parallel()

	t.Run("it can list configurations", func(t *testing.T) {
		serverImpl := NewServer(
			http.DefaultClient,
			os.Getenv("NORDVPN_SERVER_LIST_URL"),
			validator.New(validator.WithRequiredStructEnabled()),
		)

		privateKeyImpl := NewPrivateKey(
			http.DefaultClient,
			os.Getenv("NORDVPN_TOKEN"),
			os.Getenv("NORDVPN_CREDENTIALS_URL"),
		)

		configGeneratorImpl := NewConfigGenerator(
			http.DefaultClient,
			&privateKeyImpl,
			&serverImpl,
		)

		iface, _ := netip.ParsePrefix("10.5.0.2/32")
		allowedIPs, _ := netip.ParsePrefix("0.0.0.0/0")
		dns, _ := netip.ParseAddr("8.8.8.8")

		configs, err := configGeneratorImpl.List(
			context.Background(),
			[]netip.Prefix{iface},
			[]netip.Prefix{allowedIPs},
			25,
			[]netip.Addr{dns},
		)

		assert.Nil(t, err)
		assert.Greater(t, len(configs), 100)
	})
}
