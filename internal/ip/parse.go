package ip

import (
	"net/netip"
	"strings"
)

func ParseSeparated(addrs string, delim string) ([]netip.Addr, error) {
	addrSlice := strings.Split(addrs, delim)

	result := make([]netip.Addr, 0, len(addrSlice))

	for _, addr := range addrSlice {
		a, err := netip.ParseAddr(addr)

		if err != nil {
			return nil, err
		}

		result = append(result, a)
	}

	return result, nil
}
