package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/equinor/radix-oauth-guard/middleware/token"
	"github.com/rs/zerolog/log"
)

var (
	errInvalidAuthorizationHeader = errors.New("invalid Authorization header")
)

// Authentication middleware
type Authentication struct {
	validator    *token.Validator
	SubjectRegex *regexp.Regexp
}

// NewAuthenticationFromConfig creates a new Authentication middleware from config
func NewAuthenticationFromConfig(issuer, audience string, subjectRegex *regexp.Regexp) *Authentication {
	issuerUrl, err := url.Parse(issuer)
	if err != nil {
		panic(err)
	}

	validator, err := token.NewValidator(issuerUrl, audience)
	if err != nil {
		panic(err)
	}

	return &Authentication{validator: validator, SubjectRegex: subjectRegex}
}

// Handler returns a Handler handler for the Authenitcation middleware
func (jwt *Authentication) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		auth := r.Header.Get("Authorization")
		claims, err := jwt.verifyAuthorization(auth)
		latency := time.Since(t)

		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
			log.Info().Err(err).Dur("latency", latency).Int("status", http.StatusForbidden).Msg("Forbidden")
			return
		}

		subject := claims.RegisteredClaims.Subject
		if !jwt.SubjectRegex.MatchString(subject) {
			log.Info().Err(err).Dur("latency", latency).Int("status", http.StatusForbidden).Str("sub", subject).Msg("Forbidden")
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		log.Info().Dur("latency", latency).Int("status", http.StatusOK).Str("sub", subject).Msg("Authorized")
		return
	})
}

func (jwt *Authentication) verifyAuthorization(authorization string) (*validator.ValidatedClaims, error) {
	auths := strings.Split(authorization, "Bearer ")
	if len(auths) != 2 {
		return nil, errInvalidAuthorizationHeader
	}

	token := strings.TrimSpace(auths[1])
	if len(token) == 0 {
		return nil, errInvalidAuthorizationHeader
	}

	claims, err := jwt.validator.ValidateToken(context.Background(), token)
	if err != nil {
		return nil, err
	}

	return &claims, nil
}
