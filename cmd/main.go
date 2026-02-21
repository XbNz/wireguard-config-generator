package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	Provider            string `ff:"long=provider, default=nordvpn, usage=Provider to use for fetching servers" validate:"required,oneof=nordvpn"`
	NordServerListUrl   string `ff:"long=nord-server-list-url, default=https://api.nordvpn.com/v1/servers/recommendations, usage=URL to fetch server list from"    validate:"omitempty,url"`
	NordCredentialsUrl  string `ff:"long=nord-credentials-url, default=https://api.nordvpn.com/v1/users/services/credentials, usage=URL to fetch credentials from" validate:"omitempty,url"`
	NordToken           string `ff:"long=nord-token, usage=Your NordVPN API token, nodefault"                                                                      validate:"omitempty"`
	InterfaceAddresses  string `ff:"long=interface-addresses, usage=Comma separated list of interface addresses to use for the WireGuard interface. This is provider-dependant" validate:"required"`
	DNS                 string `ff:"long=dns, default=1.1.1.1, usage=Comma separated list of DNS servers to use for the WireGuard interface"                                    validate:"required"`
	AllowedIPs          string `ff:"long=allowed-ips, default=0.0.0.0/0, usage=Comma separated list of allowed IPs for the WireGuard peer"                             validate:"required"`
	PersistentKeepalive string `ff:"long=persistent-keepalive, default=25, usage=Persistent keepalive interval in seconds"                                           validate:"required,numeric,min=1,max=65535"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := run(ctx); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	var cfg Config
	fs := ff.NewFlagSet("wireguard-config-generator")
	if err := fs.AddStruct(&cfg); err != nil {
		return fmt.Errorf("add struct flags: %w", err)
	}

	if err := ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix("WIREGUARD_CONFIG_GENERATOR")); err != nil {
		if errors.Is(err, ff.ErrHelp) {
			fmt.Fprint(os.Stderr, ffhelp.Flags(fs))
			return nil
		}
		return fmt.Errorf("parse flags: %w", err)
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	err := validate.StructCtx(ctx, cfg)
	if err != nil {
		return err
	}

	provider, err := wireguard.NewProvider(cfg.Provider)
	if err != nil {
		return fmt.Errorf("create provider: %w", err)
	}

	err = ensureConfigValuesForProvider(provider, cfg)

	if err != nil {
		return fmt.Errorf("ensure config values for provider: %w", err)
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
			client,
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

	interfaceAddresses, err := cidr.ParseSeparated(cfg.InterfaceAddresses, ",")
	if err != nil {
		return fmt.Errorf("parse interface addresses: %w", err)
	}

	allowedIPs, err := cidr.ParseSeparated(cfg.AllowedIPs, ",")
	if err != nil {
		return fmt.Errorf("parse allowed IPs: %w", err)
	}

	dns, err := ip.ParseSeparated(cfg.DNS, ",")
	if err != nil {
		return fmt.Errorf("parse DNS servers: %w", err)
	}

	persistentKeepalive, err := strconv.Atoi(cfg.PersistentKeepalive)

	configs, err := configGeneratorImpl.List(
		ctx,
		interfaceAddresses,
		allowedIPs,
		uint16(persistentKeepalive),
		dns,
	)

	if err != nil {
		return fmt.Errorf("list configs: %w", err)
	}

	log.Fatal(configs)

	return nil
}

func ensureConfigValuesForProvider(provider wireguard.Provider, cfg Config) error {
	switch provider {
	case wireguard.NordVPNProvider():
		if cfg.NordToken == "" {
			return errors.New("NordVPN token is required")
		}
	}

	return nil
}
