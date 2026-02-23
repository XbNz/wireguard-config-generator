package mullvad

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/go-playground/validator/v10"
	"github.com/samber/lo"
	"github.com/xbnz/wireguard-config-generator/pkg/wireguard"
)

const (
	mullvadDefaultWireguardPort = 51820
)

type server interface {
	List(ctx context.Context) ([]wireguard.Server, error)
}

// Server represents a service for interacting with server resources through
// HTTP requests and validation.
type Server struct {
	client    *http.Client
	validator *validator.Validate
	url       string
}

// NewServer initializes and returns a new Server instance with an HTTP client,
// base URL, and validator configuration.
func NewServer(
	client *http.Client,
	url string,
	validate *validator.Validate,
) Server {
	return Server{client: client, url: url, validator: validate}
}

// List retrieves a list of Mullvad servers supporting WireGuard UDP and
// converts them into wireguard.Server instances.
func (s *Server) List(ctx context.Context) (servers []wireguard.Server, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	type Server struct {
		IPv4   string `json:"ipv4_addr_in" validate:"required_without=IPv6"`
		IPv6   string `json:"ipv6_addr_in" validate:"required_without=IPv4"`
		PubKey string `json:"pubkey"`
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		s.url,
		nil,
	)

	if err != nil {
		return nil, fmt.Errorf("create mullvad Server List request: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetching mullvad Server List: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", response.StatusCode)
	}

	var jsonResponse []Server

	err = json.NewDecoder(response.Body).Decode(&jsonResponse)
	if err != nil {
		return nil, fmt.Errorf("decoding mullvad Server List: %w", err)
	}

	err = s.validator.VarCtx(ctx, jsonResponse, "required,dive")

	if err != nil {
		if ve, ok := errors.AsType[validator.ValidationErrors](err); ok {
			return nil, fmt.Errorf(
				"invalid structure for mullvad servers: %w",
				ve,
			)
		}

		return nil, fmt.Errorf("validating mullvad servers: %w", err)
	}

	wireguardCapableServers := lo.Filter(
		jsonResponse,
		func(s Server, _ int) bool {
			return s.PubKey != ""
		},
	)

	wireguardConfigs := lo.Map(
		wireguardCapableServers,
		func(s Server, _ int) wireguard.Server {
			var addr netip.Addr
			var addr6 netip.Addr

			switch {
			case s.IPv4 != "":
				addr, err = netip.ParseAddr(s.IPv4)
				if err != nil {
					panic("invalid ipv4 address")
				}
				fallthrough
			case s.IPv6 != "":
				addr6, err = netip.ParseAddr(s.IPv6)
				if err != nil {
					panic("invalid ipv6 address")
				}
			}

			return wireguard.NewServer(
				s.PubKey,
				netip.AddrPortFrom(addr, mullvadDefaultWireguardPort),
				netip.AddrPortFrom(addr6, mullvadDefaultWireguardPort),
			)
		},
	)

	return wireguardConfigs, nil
}
