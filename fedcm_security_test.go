package obligator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

func TestSecurityFedCMDisabled(t *testing.T) {
	f := newSecurityFixture(t)
	b := f.browser()
	f.request(b, "GET", securityAuthPath, nil).want(t, http.StatusOK)
	for _, path := range []string{"/.well-known/web-identity", "/fedcm/config.json", "/fedcm/accounts", "/fedcm/id-assertion", "/login-fedcm", "/login-fedcm-auto", "/complete-login-fedcm"} {
		for _, method := range []string{"GET", "POST"} {
			t.Run(method+path, func(t *testing.T) { f.request(b, method, path, url.Values{}).want(t, http.StatusNotFound) })
		}
	}

	// A correctly signed arbitrary-issuer token reproduces the old attack input.
	// The endpoint must reject it without even discovering the issuer (SSRF).
	keys, err := GenerateJWKS()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.PublicSetOf(keys)
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	var attacker *httptest.Server
	attacker = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]string{"issuer": attacker.URL, "jwks_uri": attacker.URL + "/jwks"})
			return
		}
		json.NewEncoder(w).Encode(pub)
	}))
	defer attacker.Close()
	now := time.Now().UTC()
	token, err := openid.NewBuilder().Issuer(attacker.URL).Subject("victim@example.com").Audience([]string{securityOrigin}).Email("victim@example.com").EmailVerified(true).IssuedAt(now).Expiration(now.Add(time.Hour)).Build()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := keys.Key(0)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatal(err)
	}
	f.request(b, "POST", "/complete-login-fedcm", url.Values{"fedcm-token": {string(signed)}}).want(t, http.StatusNotFound)
	if hits.Load() != 0 {
		t.Fatalf("disabled FedCM triggered %d issuer requests", hits.Load())
	}
	if securityCookie(t, b, "test_login_key") != nil {
		t.Fatal("disabled FedCM injected a login cookie")
	}
	auth := f.request(b, "GET", securityAuthPath, nil)
	auth.want(t, http.StatusOK)
	if len(securityForms(auth.body, "/approve")) != 0 {
		t.Fatal("disabled FedCM added an identity to the authorization page")
	}
	proxy := f.request(b, "GET", "/validate?auth_server=obligator.test&redirect_uri=https://app.example/", nil)
	proxy.want(t, http.StatusTemporaryRedirect)
	if proxy.Header.Get("Remote-Id") != "" {
		t.Fatal("disabled FedCM granted proxy authentication")
	}
}
