package nordvpn

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrivateKeyImpl_Fetch(t *testing.T) {
	t.Parallel()
	const expectedToken = "test_token"

	t.Run("table tests", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				if req.Header.Get(
					"Authorization",
				) != "Basic "+base64.StdEncoding.EncodeToString(
					[]byte("token:"+expectedToken),
				) {
					rw.WriteHeader(http.StatusUnauthorized)
					return
				}
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(`{"nordlynx_private_key":"test_key"}`))
			}),
		)
		defer server.Close()

		tests := []struct {
			name      string
			token     string
			wantKey   key
			wantErr   bool
			errSubstr string
		}{
			{
				name:    "happy path",
				token:   "test_token",
				wantKey: key("test_key"),
			},
			{
				name:      "wrong token",
				token:     "wrong",
				wantErr:   true,
				errSubstr: "unexpected status code",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc := NewPrivateKey(
					server.Client(),
					tt.token,
					server.URL,
				)

				k, err := svc.fetch(context.Background())
				if tt.wantErr {
					assert.ErrorContains(t, err, tt.errSubstr)
					return
				}

				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(t, tt.wantKey, k)
			})
		}
	})

	t.Run("error is thrown when 200 with invalid json", func(t *testing.T) {
		t.Parallel()

		badServer := httptest.NewServer(
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(`{"nordlynx_private_key":""}`))
			}),
		)
		defer badServer.Close()

		svc := NewPrivateKey(
			badServer.Client(),
			expectedToken,
			badServer.URL,
		)

		_, err := svc.fetch(context.Background())
		assert.ErrorContains(t, err, "validating nordvpn wireguard private key")
	})
}
