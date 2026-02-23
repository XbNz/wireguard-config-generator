package nordvpn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
)

type privateKey interface {
	Fetch(ctx context.Context) (string, error)
}

// PrivateKey represents a structure for managing HTTP client, token, and URL
// for private Key retrieval for NordVPN
type PrivateKey struct {
	client *http.Client
	token  string
	url    string
}

// NewPrivateKey initializes and returns a PrivateKey with the provided HTTP
// client, token, and URL.
func NewPrivateKey(
	client *http.Client,
	token string,
	url string,
) PrivateKey {
	return PrivateKey{client: client, token: token, url: url}
}

// Fetch retrieves and validates a WireGuard private key from the configured URL
// using the provided HTTP client and token.
func (p *PrivateKey) Fetch(ctx context.Context) (string, error) {
	type responseShape struct {
		WireGuardPrivateKey string `json:"nordlynx_private_key" validate:"required,min=1"`
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		p.url,
		nil,
	)

	if err != nil {
		return "", fmt.Errorf("creating nordvpn wireguard private Key: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("token", p.token)

	response, err := p.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("fetching nordvpn wireguard private Key: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code %d", response.StatusCode)
	}

	jsonResponse := responseShape{}

	err = json.NewDecoder(response.Body).Decode(&jsonResponse)
	if err != nil {
		return "", fmt.Errorf(
			"decoding nordvpn wireguard private Key failed: %w",
			err,
		)
	}

	err = validator.New().Struct(jsonResponse)
	if err != nil {
		return "", fmt.Errorf(
			"validating nordvpn wireguard private Key: %w",
			err,
		)
	}

	return jsonResponse.WireGuardPrivateKey, nil
}
