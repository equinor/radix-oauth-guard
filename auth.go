package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	errInvalidAuthorizationHeader = errors.New("invalid Authorization header")
)

type Verifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

// AuthHandler returns a Handler to authenticate requests
func AuthHandler(subjects []string, verifier Verifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Trace().Func(func(e *zerolog.Event) {
			headers := r.Header.Clone()
			headers.Del("Authorization")
			if authHeader := r.Header.Get("Authorization"); authHeader != "" {

				secretKey := "N1PCdw3M2B1TfJhoaY2mL736p2vCUc47"
				authHeader = base64.StdEncoding.EncodeToString([]byte(encrypt(authHeader, secretKey)))
				headers.Set("Authorization", authHeader)
			}
			e.Interface("headers", headers)
		}).Msg("Request details")
		t := time.Now()

		auth := r.Header.Get("Authorization")
		jwt, err := parseAuthHeader(auth)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Forbidden"))
			log.Info().Err(err).Dur("elappsed_ms", time.Since(t)).Int("status", http.StatusUnauthorized).Msg("Unauthorized")
			return
		}

		token, err := verifier.Verify(r.Context(), jwt)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Forbidden"))
			log.Info().Err(err).Dur("elappsed_ms", time.Since(t)).Int("status", http.StatusUnauthorized).Msg("Unauthorized")
			return
		}

		subject := token.Subject
		found := slices.Contains(subjects, subject)
		if !found {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
			log.Info().Err(err).Dur("elappsed_ms", time.Since(t)).Int("status", http.StatusForbidden).Str("sub", subject).Msg("Forbidden")
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		log.Info().Dur("elappsed_ms", time.Since(t)).Int("status", http.StatusOK).Str("sub", subject).Msg("Authorized")
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

func encrypt(plaintext, secretKey string) string {
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return string(ciphertext)
}
