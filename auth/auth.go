package auth

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

var (
	errInvalidAuthorizationHeader = errors.New("invalid Authorization header")
)

// AuthHandler returns a Handler to authenticate requests
func AuthHandler(subjectRegex *regexp.Regexp, verifier Verifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()

		auth := r.Header.Get("Authorization")
		jwt, err := parseAuthHeader(auth)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
			log.Info().Err(err).Dur("latency", time.Since(t)).Int("status", http.StatusForbidden).Msg("Forbidden")
			return
		}

		token, err := verifier.Verify(r.Context(), jwt)

		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
			log.Info().Err(err).Dur("latency", time.Since(t)).Int("status", http.StatusForbidden).Msg("Forbidden")
			return
		}

		subject := token.Subject
		if subjectRegex.MatchString(subject) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			log.Info().Dur("latency", time.Since(t)).Int("status", http.StatusOK).Str("sub", subject).Msg("Authorized")
			return
		}

		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Forbidden"))
		log.Info().Err(err).Dur("latency", time.Since(t)).Int("status", http.StatusForbidden).Str("sub", subject).Msg("Forbidden")
		return
	})
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
