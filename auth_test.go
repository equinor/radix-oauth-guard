package main_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	guard "github.com/equinor/radix-oauth-guard"
	"github.com/stretchr/testify/assert"
)

type FakeVerifier func(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)

func (f FakeVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return f(ctx, rawIDToken)
}

func TestAuthHandler(t *testing.T) {
	handler := guard.AuthHandler([]string{"radix1", "radix2"}, FakeVerifier(func(_ context.Context, _ string) (*oidc.IDToken, error) {
		return &oidc.IDToken{
			Subject: "radix1",
		}, nil
	}))

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer abcd.abcd.abcd")
	handler.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Code)
	assert.Equal(t, `OK`, writer.Body.String())
}
func TestMissingAuthHeaderFails(t *testing.T) {
	handler := guard.AuthHandler([]string{"radix1", "radix2"}, FakeVerifier(func(_ context.Context, _ string) (*oidc.IDToken, error) {
		return &oidc.IDToken{
			Subject: "radix-fake",
		}, nil
	}))

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	handler.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusForbidden, writer.Code)
}

func TestAuthFailureFails(t *testing.T) {
	handler := guard.AuthHandler([]string{"radix1", "radix2"}, FakeVerifier(func(_ context.Context, _ string) (*oidc.IDToken, error) {
		return nil, errors.New("some error")
	}))

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer abcdabcd")
	handler.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusForbidden, writer.Code)
}

func TestInvalidJWTFails(t *testing.T) {
	handler := guard.AuthHandler([]string{"radix1", "radix2"}, FakeVerifier(func(_ context.Context, _ string) (*oidc.IDToken, error) {
		return &oidc.IDToken{
			Subject: "radix-fail",
		}, nil
	}))

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer abcd.abcd.abcd")
	handler.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusForbidden, writer.Code)
}
