package wireguard

import "fmt"

type Provider struct {
	slug string
}

func (r Provider) String() string { return r.slug }

func NewProvider(slug string) (Provider, error) {
	var provider Provider
	switch slug {
	case "nordvpn":
		provider = Provider{slug: slug}
	case "nop":
		provider = Provider{slug: slug}
	default:
		return provider, fmt.Errorf("unknown provider: %s", slug)
	}

	return provider, nil
}

func NordVPNProvider() Provider {
	provider, err := NewProvider("nordvpn")
	if err != nil {
		panic(err)
	}
	return provider
}

func NopProvider() Provider {
	provider, err := NewProvider("nop")
	if err != nil {
		panic(err)
	}
	return provider
}
