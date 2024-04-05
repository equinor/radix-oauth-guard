package token

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
)

type Validator struct {
	validator *validator.Validator
}

func NewValidator(issuerUrl *url.URL, audience string) (*Validator, error) {
	provider := jwks.NewCachingProvider(issuerUrl, 5*time.Minute)

	validator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerUrl.String(),
		[]string{audience},
	)
	if err != nil {
		return nil, err
	}

	return &Validator{validator: validator}, nil
}

func (v *Validator) ValidateToken(ctx context.Context, token string) (validator.ValidatedClaims, error) {
	maybeClaims, err := v.validator.ValidateToken(ctx, token)
	if err != nil {
		return validator.ValidatedClaims{}, err
	}

	claims, ok := maybeClaims.(*validator.ValidatedClaims)
	if !ok {
		return validator.ValidatedClaims{}, errors.New("unknown ValidateToken response")
	}

	return *claims, err
}
