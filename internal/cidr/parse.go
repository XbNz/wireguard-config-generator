package cidr

import (
	"net/netip"
	"strings"
)

func ParseSeparated(cidrs string, delim string) ([]netip.Prefix, error) {
	cidrSlice := strings.Split(cidrs, delim)

	prefixes := make([]netip.Prefix, 0, len(cidrSlice))

	for _, cidr := range cidrSlice {
		prefix, err := netip.ParsePrefix(cidr)

		if err != nil {
			return nil, err
		}

		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}
