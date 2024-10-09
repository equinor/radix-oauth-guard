package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/rs/zerolog/log"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

var (
	errInvalidAuthorizationHeader = errors.New("invalid Authorization header")
)

type KeyFunc func(ctx context.Context) (interface{}, error)
type controller struct {
	providers map[string]KeyFunc
	audience  string
	subjects  []string
}

// NewAuthHandler returns a Handler to authenticate requests
func NewAuthHandler(audience string, subjects, issuers []string) (RouteMapper, error) {
	providers := make(map[string]KeyFunc, len(issuers))
	for _, issuer := range issuers {
		issuerUrl, err := url.Parse(issuer)
		if err != nil {
			return nil, err
		}

		provider := jwks.NewCachingProvider(issuerUrl, 5*time.Hour)
		providers[issuer] = provider.KeyFunc
	}

	c := &controller{
		providers: providers,
		audience:  audience,
		subjects:  subjects,
	}
	return func(mux *http.ServeMux) {
		mux.Handle("/auth", c)
	}, nil
}

func (c *controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	authHeader, err := parseAuthHeader(auth)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
		log.Info().Err(err).Msg("Unauthorized: Invalid auth header")
		return
	}

	claims, err := c.getClaims(r.Context(), authHeader)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
		log.Warn().Err(err).Msg("Forbidden: Invalid token")
		return
	}

	subject := claims.Subject

	found := slices.Contains(c.subjects, subject)
	if !found {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Forbidden"))
		log.Warn().Str("sub", subject).Msg("Forbidden")
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
	log.Info().Str("sub", subject).Msg("Authorized")
}

func (c *controller) getClaims(ctx context.Context, authHeader string) (*jwt.Claims, error) {
	var unsafeClaims jwt.Claims
	token, err := jwt.ParseSigned(authHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}
	err = token.UnsafeClaimsWithoutVerification(&unsafeClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JWT unsafeClaims: %w", err)
	}
	var keyId string
	if len(token.Headers) == 1 {
		keyId = token.Headers[0].KeyID
	}
	if keyId == "" {
		return nil, fmt.Errorf("failed to find keyId in headers")
	}

	issuer := unsafeClaims.Issuer
	keyFunc, ok := c.providers[issuer]
	if !ok {
		return nil, fmt.Errorf("unknown issuer: %s", issuer)
	}
	key, err := keyFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting the keys from the key func: %w", err)
	}

	var verifiedClaims jwt.Claims
	err = token.Claims(key, &verifiedClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token unsafeClaims: %w", err)
	}

	expected := jwt.Expected{Audience: []string{c.audience}}
	if err = verifiedClaims.Validate(expected); err != nil {
		return nil, fmt.Errorf("failed to verify token unsafeClaims: %w", err)
	}

	return &verifiedClaims, nil
}

func parseAuthHeader(authorization string) (string, error) {
	auths := strings.Split(authorization, "Bearer ")
	if len(auths) != 2 {
		return "", errInvalidAuthorizationHeader
	}

	token := strings.TrimSpace(auths[1])
	if len(token) == 0 {
		return "", errInvalidAuthorizationHeader
	}

	return token, nil
}
