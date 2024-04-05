package auth

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Verifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}
