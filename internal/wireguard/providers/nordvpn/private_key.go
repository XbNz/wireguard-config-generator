package nordvpn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
)

type key string

type privateKey interface {
	fetch(ctx context.Context) (key, error)
}

type PrivateKeyImpl struct {
	client *http.Client
	token  string
	url    string
}

func NewPrivateKey(
	client *http.Client,
	token string,
	url string,
) PrivateKeyImpl {
	return PrivateKeyImpl{client: client, token: token, url: url}
}

func (p *PrivateKeyImpl) fetch(ctx context.Context) (key, error) {
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
		return "", fmt.Errorf("creating nordvpn wireguard private key: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("token", p.token)

	response, err := p.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("fetching nordvpn wireguard private key: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code %d", response.StatusCode)
	}

	jsonResponse := responseShape{}

	err = json.NewDecoder(response.Body).Decode(&jsonResponse)
	if err != nil {
		return "", fmt.Errorf(
			"decoding nordvpn wireguard private key failed: %w",
			err,
		)
	}

	err = validator.New().Struct(jsonResponse)
	if err != nil {
		return "", fmt.Errorf(
			"validating nordvpn wireguard private key: %w",
			err,
		)
	}

	return key(jsonResponse.WireGuardPrivateKey), nil
}
