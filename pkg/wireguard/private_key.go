package wireguard

import "context"

type PrivateKeyer interface {
	Fetch(ctx context.Context) (string, error)
}
