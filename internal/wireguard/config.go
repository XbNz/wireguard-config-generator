package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

type Configuration struct {
	PrivateKey         string
	InterfaceAddresses []netip.Prefix
	DNS                []netip.Addr
	Peers              []PeerConfig
}

func NewConfiguration(
	privateKey string,
	interfaceAddresses []netip.Prefix,
	dns []netip.Addr,
	peers []PeerConfig,
) Configuration {
	return Configuration{
		PrivateKey:         privateKey,
		InterfaceAddresses: interfaceAddresses,
		DNS:                dns,
		Peers:              peers,
	}
}

type PeerConfig struct {
	PublicKey           string
	Endpoint            netip.AddrPort
	AllowedIPs          []netip.Prefix
	PersistentKeepalive uint16
}

func NewPeerConfig(
	publicKey string,
	endpoint netip.AddrPort,
	allowedIPs []netip.Prefix,
	persistentKeepalive uint16,
) PeerConfig {
	return PeerConfig{
		PublicKey:           publicKey,
		Endpoint:            endpoint,
		AllowedIPs:          allowedIPs,
		PersistentKeepalive: persistentKeepalive,
	}
}

// ToIPCFormat serialises the configuration into the WireGuard UAPI key-value format
func (c *Configuration) ToIPCFormat() (string, error) {
	var sb strings.Builder

	privHex, err := wgKeyToHex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid private_key: %w", err)
	}

	fmt.Fprintf(&sb, "private_key=%s\nlisten_port=0\n", privHex)

	for i, peer := range c.Peers {
		pubHex, err := wgKeyToHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("invalid public_key for peer %d: %w", i, err)
		}

		fmt.Fprintf(&sb, "public_key=%s\n", pubHex)

		if peer.Endpoint.IsValid() {
			fmt.Fprintf(&sb, "endpoint=%s\n", peer.Endpoint.String())
		}

		fmt.Fprintf(&sb, "replace_allowed_ips=true\n")
		for _, ip := range peer.AllowedIPs {
			fmt.Fprintf(&sb, "allowed_ip=%s\n", ip.String())
		}

		if peer.PersistentKeepalive > 0 {
			fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n\n", peer.PersistentKeepalive)
		}
	}

	sb.WriteString("\n")
	return sb.String(), nil
}

// ToINIFormat serialises the configuration into the WireGuard INI format
func (c *Configuration) ToINIFormat() (string, error) {
	var sb strings.Builder

	fmt.Fprintf(&sb, "[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\n", c.PrivateKey)

	interfaceAddresses := make([]string, 0, len(c.InterfaceAddresses))
	for _, addr := range c.InterfaceAddresses {
		interfaceAddresses = append(interfaceAddresses, addr.String())
	}

	dnsAddresses := make([]string, 0, len(c.DNS))
	for _, addr := range c.DNS {
		dnsAddresses = append(dnsAddresses, addr.String())
	}

	fmt.Fprintf(&sb, "Address = %s\n", strings.Join(interfaceAddresses, ", "))
	fmt.Fprintf(&sb, "DNS = %s\n", strings.Join(dnsAddresses, ", "))

	for _, peer := range c.Peers {
		fmt.Fprintf(&sb, "\n[Peer]\n")
		fmt.Fprintf(&sb, "PublicKey = %s\n", peer.PublicKey)

		allowedIPs := make([]string, 0, len(peer.AllowedIPs))
		for _, addr := range peer.AllowedIPs {
			allowedIPs = append(allowedIPs, addr.String())
		}

		fmt.Fprintf(&sb, "AllowedIPs = %s\n", strings.Join(allowedIPs, ", "))
		fmt.Fprintf(&sb, "Endpoint = %s\n", peer.Endpoint.String())
		fmt.Fprintf(&sb, "PersistentKeepalive = %d\n", peer.PersistentKeepalive)
	}

	return sb.String(), nil
}

func wgKeyToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("parse key: invalid key length %d (expected 32)", len(decoded))
	}
	return hex.EncodeToString(decoded), nil
}
