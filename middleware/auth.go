package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/equinor/radix-oauth-guard/middleware/token"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

var (
	errInvalidAuthorizationHeader = errors.New("invalid Authorization header")
	errForbidden                  = errors.New("forbidden")
)

type authHeader struct {
	Authorization string `header:"Authorization" binding:"required"`
}

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

// Gin returns a Gin handler for the Authenitcation middleware
func (jwt *Authentication) Gin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var auth authHeader

		if err := ctx.ShouldBindHeader(&auth); err != nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		err := jwt.verifyAuthorization(auth.Authorization)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusForbidden, err)
			log.Error().Err(err).Msg("Authentication failed")
			return
		}
	}
}

func (jwt *Authentication) verifyAuthorization(authorization string) error {
	auths := strings.Split(authorization, "Bearer ")
	if len(auths) != 2 {
		return errInvalidAuthorizationHeader
	}

	token := strings.TrimSpace(auths[1])
	if len(token) == 0 {
		return errInvalidAuthorizationHeader
	}

	claims, err := jwt.validator.ValidateToken(context.Background(), token)
	if err != nil {
		return err
	}

	subject := claims.RegisteredClaims.Subject
	if !jwt.SubjectRegex.MatchString(subject) {
		return errForbidden
	}
	return nil
}
