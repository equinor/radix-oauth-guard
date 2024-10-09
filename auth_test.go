package main_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	guard "github.com/equinor/radix-oauth-guard"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fake_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkJCOENlRlZxeWFHckdOdWVoSklpTDRkZmp6dyIsImtpZCI6IkJCOENlRlZxeWFHckdOdWVoSklpTDRkZmp6dyJ9.eyJhdWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0MjQ1YTJlYzEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8xMjM0NTY3OC03NTY1LTIzNDItMjM0Mi0xMjM0MDViNDU5YjAvIiwiaWF0IjoxNTc1MzU1NTA4LCJuYmYiOjE1NzUzNTU1MDgsImV4cCI6MTU3NTM1OTQwOCwiYWNyIjoiMSIsImFpbyI6IjQyYXNkYXMiLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDc5MDM5YTkwIiwiYXBwaWRhY3IiOiIwIiwiZmFtaWx5X25hbWUiOiJKb2huIiwiZ2l2ZW5fbmFtZSI6IkRvZSIsImhhc2dyb3VwcyI6InRydWUiLCJpcGFkZHIiOiIxMC4xMC4xMC4xMCIsIm5hbWUiOiJKb2huIERvZSIsIm9pZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzRmYzhmYTBlYSIsIm9ucHJlbV9zaWQiOiJTLTEtNS0yMS0xMjM0NTY3ODktMTIzNDU2OTc4MC0xMjM0NTY3ODktMTIzNDU2NyIsInNjcCI6InVzZXJfaW1wZXJzb25hdGlvbiIsInN1YiI6IjBoa2JpbEo3MTIzNHpSU3h6eHZiSW1hc2RmZ3N4amI2YXNkZmVOR2FzZGYiLCJ0aWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0MDViNDU5YjAiLCJ1bmlxdWVfbmFtZSI6Im5vdC1leGlzdGluZy1yYWRpeC1lbWFpbEBlcXVpbm9yLmNvbSIsInVwbiI6Im5vdC1leGlzdGluZy10ZXN0LXJhZGl4LWVtYWlsQGVxdWlub3IuY29tIiwidXRpIjoiQlMxMmFzR2R1RXlyZUVjRGN2aDJBRyIsInZlciI6IjEuMCJ9.EB5z7Mk34NkFPCP8MqaNMo4UeWgNyO4-qEmzOVPxfoBqbgA16Ar4xeONXODwjZn9iD-CwJccusW6GP0xZ_PJHBFpfaJO_tLaP1k0KhT-eaANt112TvDBt0yjHtJg6He6CEDqagREIsH3w1mSm40zWLKGZeRLdnGxnQyKsTmNJ1rFRdY3AyoEgf6-pnJweUt0LaFMKmIJ2HornStm2hjUstBaji_5cSS946zqp4tgrc-RzzDuaQXzqlVL2J22SR2S_Oux_3yw88KmlhEFFP9axNcbjZrzW3L9XWnPT6UzVIaVRaNRSWfqDATg-jeHg4Gm1bp8w0aIqLdDxc9CfFMjuQ"

func TestValidTokenSucceeds(t *testing.T) {
	m, err := mockoidc.Run()
	require.NoError(t, err)
	defer m.Shutdown()
	issuer := m.Issuer()

	token, err := createUser(issuer, "audience", "radix1")

	mux := http.NewServeMux()
	mapper, err := guard.NewAuthHandler("audience", []string{"radix1", "radix2"}, []string{issuer})
	require.NoError(t, err)
	mapper(mux)

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	mux.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Code)
	assert.Equal(t, `OK`, writer.Body.String())
}
func TestMultipleIssuers(t *testing.T) {
	m, err := mockoidc.Run()
	require.NoError(t, err)
	defer m.Shutdown()
	issuer := m.Issuer()
	m2, err := mockoidc.Run()
	require.NoError(t, err)
	defer m2.Shutdown()
	issuer2 := m2.Issuer()
	m3, err := mockoidc.Run()
	require.NoError(t, err)
	defer m3.Shutdown()
	issuer3 := m3.Issuer()
	mux := http.NewServeMux()

	token, err := createUser(issuer, "audience", "radix1")
	token2, err := createUser(issuer2, "audience", "radix2")
	token3, err := createUser(issuer3, "audience", "radix3")

	mapper, err := guard.NewAuthHandler("audience", []string{"radix1", "radix2"}, []string{issuer, issuer2})
	require.NoError(t, err)
	mapper(mux)

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	mux.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Code)
	assert.Equal(t, `OK`, writer.Body.String())

	writer = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	mux.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusOK, writer.Code)
	assert.Equal(t, `OK`, writer.Body.String())

	writer = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer "+token3)
	mux.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusUnauthorized, writer.Code)
	assert.Equal(t, `Unauthorized`, writer.Body.String())
}
func TestInvalidAudienceFails(t *testing.T) {
	m, err := mockoidc.Run()
	require.NoError(t, err)
	defer m.Shutdown()
	issuer := m.Issuer()

	token, err := createUser(issuer, "audience-invalid", "radix1")

	mux := http.NewServeMux()
	mapper, err := guard.NewAuthHandler("audience", []string{"radix1", "radix2"}, []string{issuer})
	require.NoError(t, err)
	mapper(mux)

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	mux.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusUnauthorized, writer.Code)
	assert.Equal(t, `Unauthorized`, writer.Body.String())
}
func TestMissingAuthHeaderFails(t *testing.T) {
	m, err := mockoidc.Run()
	require.NoError(t, err)
	defer m.Shutdown()
	issuer := m.Issuer()

	mux := http.NewServeMux()
	mapper, err := guard.NewAuthHandler("audience", []string{"radix1", "radix2"}, []string{issuer})
	require.NoError(t, err)
	mapper(mux)

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	mux.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusUnauthorized, writer.Code)
	assert.Equal(t, `Unauthorized`, writer.Body.String())
}

func TestAuthInvalidSubjectFails(t *testing.T) {
	m, err := mockoidc.Run()
	require.NoError(t, err)
	defer m.Shutdown()
	issuer := m.Issuer()

	mux := http.NewServeMux()
	mapper, err := guard.NewAuthHandler("audience", []string{"radix1", "radix2"}, []string{issuer})
	require.NoError(t, err)
	mapper(mux)

	token, err := createUser(issuer, "audience", "radix3")
	require.NoError(t, err)

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	mux.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusForbidden, writer.Code)
	assert.Equal(t, `Forbidden`, writer.Body.String())
}

func TestInvalidJWTFails(t *testing.T) {
	m, err := mockoidc.Run()
	require.NoError(t, err)
	defer m.Shutdown()
	issuer := m.Issuer()

	mux := http.NewServeMux()
	mapper, err := guard.NewAuthHandler("audience", []string{"radix1", "radix2"}, []string{issuer})
	require.NoError(t, err)
	mapper(mux)

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer abcd.abcd.abcd")
	mux.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusUnauthorized, writer.Code)
	assert.Equal(t, `Unauthorized`, writer.Body.String())
}

func TestUnsupportedIssuerFails(t *testing.T) {
	m, err := mockoidc.Run()
	require.NoError(t, err)
	defer m.Shutdown()
	issuer := m.Issuer()

	mux := http.NewServeMux()
	mapper, err := guard.NewAuthHandler("audience", []string{"radix1", "radix2"}, []string{issuer})
	require.NoError(t, err)
	mapper(mux)

	writer := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer "+fake_token)
	mux.ServeHTTP(writer, req)

	assert.Equal(t, http.StatusUnauthorized, writer.Code)
	assert.Equal(t, `Unauthorized`, writer.Body.String())
}

func createUser(issuer, audience, subject string) (string, error) {
	user := mockoidc.DefaultUser()
	key, err := mockoidc.DefaultKeypair()
	if err != nil {
		return "", err
	}

	claims, err := user.Claims([]string{"profile", "email"}, &mockoidc.IDTokenClaims{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:   issuer,
			Subject:  subject,
			Audience: []string{audience},
		},
	})
	return key.SignJWT(claims)
}
