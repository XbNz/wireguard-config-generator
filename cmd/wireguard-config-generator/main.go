package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"

	"github.com/xbnz/wireguard-config-generator/internal/cidr"
	"github.com/xbnz/wireguard-config-generator/internal/ip"
	"github.com/xbnz/wireguard-config-generator/internal/wireguard"
	"github.com/xbnz/wireguard-config-generator/internal/wireguard/providers/nordvpn"
)

type Config struct {
	Provider            string `ff:"long=provider, default=nordvpn, usage=Provider to use for fetching servers"                                                                 validate:"required,oneof=nordvpn"`
	NordServerListUrl   string `ff:"long=nord-server-list-url, default=https://api.nordvpn.com/v1/servers/recommendations, usage=URL to fetch server list from"                 validate:"omitempty,url"`
	NordCredentialsUrl  string `ff:"long=nord-credentials-url, default=https://api.nordvpn.com/v1/users/services/credentials, usage=URL to fetch credentials from"              validate:"omitempty,url"`
	NordToken           string `ff:"long=nord-token, usage=Your NordVPN API token, nodefault"                                                                                   validate:"omitempty"`
	InterfaceAddresses  string `ff:"long=interface-addresses, usage=Comma separated list of interface addresses to use for the WireGuard interface. This is provider-dependant" validate:"required"`
	DNS                 string `ff:"long=dns, default=1.1.1.1, usage=Comma separated list of DNS servers to use for the WireGuard interface"                                    validate:"required"`
	AllowedIPs          string `ff:"long=allowed-ips, default=0.0.0.0/0, usage=Comma separated list of allowed IPs for the WireGuard peer"                                      validate:"required"`
	PersistentKeepalive string `ff:"long=persistent-keepalive, default=25, usage=Persistent keepalive interval in seconds"                                                      validate:"required,numeric,min=1,max=65535"`
	OutputDir           string `ff:"long=output-dir, usage=Directory to output WireGuard configuration files to"                                                                validate:"required"`
}

type App struct {
	Config          Config
	Ctx             context.Context
	Provider        wireguard.Provider
	ConfigGenerator wireguard.ConfigGenerator
	HttpClient      *http.Client
	Validator       *validator.Validate
}

func newApp(ctx context.Context) (*App, error) {
	var cfg Config
	fs := ff.NewFlagSet("wireguard-config-generator")
	if err := fs.AddStruct(&cfg); err != nil {
		return nil, fmt.Errorf("add struct flags: %w", err)
	}

	if err := ff.Parse(
		fs,
		os.Args[1:],
		ff.WithEnvVarPrefix("WIREGUARD_CONFIG_GENERATOR"),
	); err != nil {
		if errors.Is(err, ff.ErrHelp) {
			fmt.Fprint(os.Stderr, ffhelp.Flags(fs))
			return nil, err
		}
		return nil, fmt.Errorf("parse flags: %w", err)
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	err := validate.StructCtx(ctx, cfg)
	if err != nil {
		return nil, err
	}

	provider, err := wireguard.NewProvider(cfg.Provider)
	if err != nil {
		return nil, fmt.Errorf("create provider: %w", err)
	}

	err = ensureConfigValuesForProvider(provider, cfg)

	if err != nil {
		return nil, fmt.Errorf("ensure config values for provider: %w", err)
	}

	transport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	var configGeneratorImpl wireguard.ConfigGenerator

	switch provider {
	case wireguard.NordVPNProvider():
		configGeneratorImpl = nordvpn.NewConfigGenerator(
			new(nordvpn.NewPrivateKey(
				client,
				cfg.NordToken,
				cfg.NordCredentialsUrl,
			)),
			new(nordvpn.NewServer(
				client,
				cfg.NordServerListUrl,
				validate,
			)),
		)
	}

	return &App{
		Config:          cfg,
		Ctx:             ctx,
		Provider:        provider,
		ConfigGenerator: configGeneratorImpl,
		HttpClient:      client,
		Validator:       validate,
	}, nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	app, err := newApp(ctx)
	if err != nil {
		log.Printf("Error creating app: %v", err)
		os.Exit(1)
	}

	if err := run(app); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}

func run(app *App) error {
	interfaceAddresses, err := cidr.ParseSeparated(
		app.Config.InterfaceAddresses,
		",",
	)
	if err != nil {
		return fmt.Errorf("parse interface addresses: %w", err)
	}

	allowedIPs, err := cidr.ParseSeparated(app.Config.AllowedIPs, ",")
	if err != nil {
		return fmt.Errorf("parse allowed IPs: %w", err)
	}

	dns, err := ip.ParseSeparated(app.Config.DNS, ",")
	if err != nil {
		return fmt.Errorf("parse DNS servers: %w", err)
	}

	persistentKeepalive, err := strconv.Atoi(app.Config.PersistentKeepalive)

	configs, err := app.ConfigGenerator.List(
		app.Ctx,
		interfaceAddresses,
		allowedIPs,
		uint16(persistentKeepalive),
		dns,
	)

	if err != nil {
		return fmt.Errorf("list configs: %w", err)
	}

	for i, config := range configs {
		ini, err := config.ToINIFormat()
		if err != nil {
			return fmt.Errorf("convert config to INI format: %w", err)
		}

		absolutePath, err := filepath.Abs(app.Config.OutputDir)

		if err != nil {
			return fmt.Errorf("get absolute path of output directory: %w", err)
		}

		if err := os.MkdirAll(absolutePath, 0755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}

		fileName := filepath.Join(
			absolutePath,
			fmt.Sprintf("%s_%d.conf", app.Config.Provider, i),
		)

		file, err := os.Create(fileName)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}

		if err := writeContent(file, ini); err != nil {
			return fmt.Errorf("write content to file: %w", err)
		}
	}

	return nil
}

func ensureConfigValuesForProvider(
	provider wireguard.Provider,
	cfg Config,
) error {
	switch provider {
	case wireguard.NordVPNProvider():
		if cfg.NordToken == "" {
			return errors.New("NordVPN token is required")
		}
	}

	return nil
}

func writeContent(closer io.WriteCloser, content string) error {
	defer closer.Close()
	_, err := closer.Write([]byte(content))
	return err
}
