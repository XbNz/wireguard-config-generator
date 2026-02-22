package cidr

import (
	"net/netip"
	"strings"

	"github.com/samber/lo"
)

func ParseSeparated(cidrs string, delim string) ([]netip.Prefix, error) {
	cidrSlice := strings.Split(cidrs, delim)
	cidrSlice = lo.Map(cidrSlice, func(cidr string, _ int) string {
		return strings.TrimSpace(cidr)
	})

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
