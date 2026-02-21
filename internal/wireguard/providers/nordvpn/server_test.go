//go:build integration

package nordvpn

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func TestServerImpl_List(t *testing.T) {
	t.Parallel()

	serverImpl := NewServer(
		http.DefaultClient,
		os.Getenv("NORDVPN_SERVER_LIST_URL"),
		validator.New(validator.WithRequiredStructEnabled()),
	)

	t.Run("it can list servers", func(t *testing.T) {
		configs, err := serverImpl.list(context.Background())

		assert.Nil(t, err)
		assert.Greater(t, len(configs), 100)
	})
}
