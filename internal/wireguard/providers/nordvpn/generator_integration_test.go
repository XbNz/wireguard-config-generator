//go:build integration

package nordvpn

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"

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
		redactAuth := func(i *cassette.Interaction) error {
			delete(i.Request.Headers, "Authorization")
			return nil
		}

		opts := []recorder.Option{
			recorder.WithSkipRequestLatency(true),
			recorder.WithHook(redactAuth, recorder.BeforeSaveHook),
			recorder.WithMatcher(cassette.NewDefaultMatcher(cassette.WithIgnoreAuthorization())),
		}

		serverRecorder, err := recorder.New(
			filepath.Join(
				"testdata",
				"vcr",
				strings.ReplaceAll(t.Name(), "/", "_")+"_server",
			),
			opts...)
		if err != nil {
			t.Fatal(err)
		}

		privateKeyRecorder, err := recorder.New(
			filepath.Join(
				"testdata",
				"vcr",
				strings.ReplaceAll(t.Name(), "/", "_")+"_private_key",
			),
			opts...)
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() {
			if err := serverRecorder.Stop(); err != nil {
				t.Error(err)
			}

			if err := privateKeyRecorder.Stop(); err != nil {
				t.Error(err)
			}
		})

		serverImpl := NewServer(
			serverRecorder.GetDefaultClient(),
			os.Getenv("NORDVPN_SERVER_LIST_URL"),
			validator.New(validator.WithRequiredStructEnabled()),
		)

		privateKeyImpl := NewPrivateKey(
			privateKeyRecorder.GetDefaultClient(),
			os.Getenv("NORDVPN_TOKEN"),
			os.Getenv("NORDVPN_CREDENTIALS_URL"),
		)

		configGeneratorImpl := NewConfigGenerator(
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
