//go:build integration

package mullvad

import (
	"context"
	"net/http"
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

func TestServer_List(t *testing.T) {
	t.Parallel()

	serverImpl := NewServer(
		http.DefaultClient,
		os.Getenv("MULLVAD_SERVER_LIST_URL"),
		validator.New(validator.WithRequiredStructEnabled()),
	)

	t.Run("it can List servers", func(t *testing.T) {
		configs, err := serverImpl.List(context.Background())

		assert.Nil(t, err)
		assert.Greater(t, len(configs), 100)

		for _, config := range configs {
			assert.True(t, config.Endpoint.IsValid())
			assert.True(t, config.EndpointV6.IsValid())
			assert.NotEmpty(t, config.PublicKey)
		}
	})
}
