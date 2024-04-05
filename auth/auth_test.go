package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/equinor/radix-oauth-guard/auth"
	"github.com/stretchr/testify/assert"
)

type FakeVerifier func(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)

func (f FakeVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return f(ctx, rawIDToken)
}

func TestAuthHandler(t *testing.T) {
	handler := auth.AuthHandler(regexp.MustCompile("richard"), FakeVerifier(func(_ context.Context, _ string) (*oidc.IDToken, error) {
		return &oidc.IDToken{
			Subject: "richard",
		}, nil
	}))

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer abcd.abcd.abcd")
	handler.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Code)
	assert.Equal(t, `OK`, writer.Body.String())
}
