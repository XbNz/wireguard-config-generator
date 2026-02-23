package nordvpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/go-playground/validator/v10"
	"github.com/samber/lo"
)

const (
	nordVpnDefaultWireguardPort = 51820
)

type server interface {
	List(ctx context.Context) ([]NordServer, error)
}

// NordServer represents a server with a public WireGuard key and an associated
// network endpoint.
type NordServer struct {
	PublicKey string
	Endpoint  netip.AddrPort
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

// List retrieves a list of NordVPN servers supporting WireGuard UDP and
// converts them into NordServer instances.
func (s *Server) List(ctx context.Context) ([]NordServer, error) {
	filteredUrl, err := url.Parse(s.url)

	type Metadata struct {
		Name  string `json:"name"  validate:"required"`
		Value string `json:"value" validate:"required"`
	}

	type Technology struct {
		Identifier string     `json:"identifier" validate:"required"`
		Metadata   []Metadata `json:"metadata"   validate:"omitempty,dive"`
	}

	type Server struct {
		IPAddress    string       `json:"station"      validate:"required,ip"`
		Technologies []Technology `json:"technologies" validate:"required,dive"`
	}

	if err != nil {
		return nil, fmt.Errorf("parsing nordvpn Server List url: %w", err)
	}

	queries := url.Values{
		"filters[servers_technologies][identifier]": {"wireguard_udp"},
		"limit": {"100000"},
	}

	filteredUrl.RawQuery = queries.Encode()

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		filteredUrl.String(),
		nil,
	)

	if err != nil {
		return nil, fmt.Errorf("create nordvpn Server List request: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetching nordvpn Server List: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", response.StatusCode)
	}

	var jsonResponse []Server

	err = json.NewDecoder(response.Body).Decode(&jsonResponse)
	if err != nil {
		return nil, fmt.Errorf("decoding nordvpn Server List: %w", err)
	}

	err = s.validator.VarCtx(ctx, jsonResponse, "required,dive")

	if err != nil {
		if ve, ok := errors.AsType[validator.ValidationErrors](err); ok {
			return nil, fmt.Errorf(
				"invalid structure for nordvpn servers: %w",
				ve,
			)
		}

		return nil, fmt.Errorf("validating nordvpn servers: %w", err)
	}

	wireguardCapableServers := lo.Filter(
		jsonResponse,
		func(s Server, _ int) bool {
			wgTechs := lo.Filter(
				s.Technologies,
				func(tech Technology, _ int) bool {
					return tech.Identifier == "wireguard_udp"
				},
			)

			return len(wgTechs) > 0
		},
	)

	wireguardConfigs := lo.Map(
		wireguardCapableServers,
		func(s Server, _ int) NordServer {
			wgTechs := lo.Reject(
				s.Technologies,
				func(tech Technology, _ int) bool {
					return tech.Identifier != "wireguard_udp"
				},
			)

			wgTech, ok := lo.First(wgTechs)

			if !ok {
				panic("expected at least one wireguard technology")
			}

			publicKeyMetas := lo.Reject(
				wgTech.Metadata,
				func(meta Metadata, _ int) bool {
					return meta.Name != "public_key"
				},
			)

			publicKeyMeta, ok := lo.First(publicKeyMetas)

			if !ok {
				panic("expected at least one public Key metadata")
			}

			addr, err := netip.ParseAddr(s.IPAddress)

			if err != nil {
				panic("invalid ip address")
			}

			return NordServer{
				publicKeyMeta.Value,
				netip.AddrPortFrom(addr, nordVpnDefaultWireguardPort),
			}
		},
	)

	return wireguardConfigs, nil
}
