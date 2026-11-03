package obligator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

func TestSecurityApproveRejectsCSRF(t *testing.T) {
	f := newSecurityFixture(t)
	b := f.browser()
	f.addIdentity(b, "victim@example.com")
	f.addIdentity(b, "*@example.com")
	f.request(b, "GET", "/login", nil).want(t, http.StatusOK)
	f.request(b, "GET", securityAuthPath, nil).want(t, http.StatusOK)
	csrf := f.authToken(b)
	get := f.request(b, "GET", "/approve?identity_id=victim%40example.com&csrf_token="+url.QueryEscape(csrf), nil)
	get.want(t, http.StatusMethodNotAllowed)
	if get.Header.Get("Allow") != "POST" {
		t.Fatalf("405 Allow=%q", get.Header.Get("Allow"))
	}

	for _, identity := range []string{"victim@example.com", "does-not-exist@example.com", "*@example.com"} {
		for _, bad := range []string{"", "mismatched"} {
			t.Run(identity+"/"+bad, func(t *testing.T) {
				form := url.Values{"identity_id": {identity}}
				if bad != "" {
					form.Set("csrf_token", bad)
				}
				resp := f.request(b, "POST", "/approve", form)
				resp.want(t, http.StatusForbidden)
				if !strings.Contains(strings.ToLower(resp.body), "csrf") {
					t.Fatalf("must reject CSRF before identity lookup/wildcard rendering: %s", resp.body)
				}
				if resp.Header.Get("Location") != "" || len(securityForms(resp.body, "/approve")) != 0 {
					t.Fatal("CSRF failure advanced authorization")
				}
			})
		}
	}
	// Query-string tokens cannot stand in for a POST body token.
	f.request(b, "POST", "/approve?csrf_token="+url.QueryEscape(csrf), url.Values{"identity_id": {"victim@example.com"}}).want(t, http.StatusForbidden)
	f.request(b, "POST", "/approve?csrf_token="+url.QueryEscape(csrf), url.Values{"identity_id": {"victim@example.com"}, "csrf_token": {"wrong-body"}}).want(t, http.StatusForbidden)

	original := *securityCookie(t, b, "test_auth_request")
	for _, variant := range []string{"old-missing-claim", "empty-claim", "non-string-claim"} {
		t.Run(variant, func(t *testing.T) {
			token, err := f.server.jose.Parse(original.Value)
			if err != nil {
				t.Fatal(err)
			}
			if err := token.Remove("csrf_token"); err != nil {
				t.Fatal(err)
			}
			if variant == "empty-claim" {
				if err := token.Set("csrf_token", ""); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "non-string-claim" {
				if err := token.Set("csrf_token", 123); err != nil {
					t.Fatal(err)
				}
			}
			signed, err := f.server.jose.Sign(token)
			if err != nil {
				t.Fatal(err)
			}
			modified := original
			modified.Value = signed
			b.Jar.SetCookies(securityURL(t, securityOrigin), []*http.Cookie{&modified})
			for _, supplied := range []string{"", csrf} {
				f.request(b, "POST", "/approve", url.Values{"identity_id": {"*@example.com"}, "csrf_token": {supplied}}).want(t, http.StatusForbidden)
			}
		})
	}
	b.Jar.SetCookies(securityURL(t, securityOrigin), []*http.Cookie{&original})
	// A rerender replaces the request token: an older tab cannot approve it.
	f.request(b, "GET", securityAuthPath, nil).want(t, http.StatusOK)
	if f.authToken(b) == csrf {
		t.Fatal("auth rerender reused CSRF token")
	}
	f.request(b, "POST", "/approve", url.Values{"identity_id": {"victim@example.com"}, "csrf_token": {csrf}}).want(t, http.StatusForbidden)

	// Invalid percent encoding must not silently fall through with partial form data.
	malformed, err := b.Post(securityOrigin+"/approve", "application/x-www-form-urlencoded", strings.NewReader("identity_id=victim%40example.com&csrf_token=%zz"))
	if err != nil {
		t.Fatal(err)
	}
	defer malformed.Body.Close()
	if malformed.StatusCode != http.StatusBadRequest || malformed.Header.Get("Location") != "" {
		t.Fatalf("malformed form: status=%d Location=%q", malformed.StatusCode, malformed.Header.Get("Location"))
	}
}

func TestSecurityApproveConsentFormsAndTokens(t *testing.T) {
	f := newSecurityFixture(t)
	b := f.browser()
	f.addIdentity(b, "first@example.com")
	f.request(b, "GET", "/login", nil).want(t, http.StatusOK)
	first := f.request(b, "GET", securityAuthPath, nil)
	first.want(t, http.StatusOK)
	form := securityOneForm(t, first.body, "/approve")
	if !form.hidden["csrf_token"] || form.values.Get("csrf_token") != f.authToken(b) {
		t.Fatal("remaining-identity form missing hidden request CSRF token")
	}
	// A body token takes precedence over a conflicting query token.
	f.redeem(b, f.request(b, "POST", "/approve?csrf_token=wrong-query", form.values), "first@example.com")
	// The successful login creates the previous-login branch; another identity
	// exercises the remaining-identity branch on the same page.
	f.addIdentity(b, "second@example.com")
	second := f.request(b, "GET", securityAuthPath, nil)
	second.want(t, http.StatusOK)
	forms := securityForms(second.body, "/approve")
	if len(forms) != 2 {
		t.Fatalf("want previous and remaining forms, got %d", len(forms))
	}
	seen := map[string]bool{}
	for _, form := range forms {
		if !strings.EqualFold(form.attrs["method"], "POST") || !form.hidden["csrf_token"] || form.values.Get("csrf_token") != f.authToken(b) {
			t.Fatalf("invalid approval form: %+v", form)
		}
		seen[form.values.Get("identity_id")] = true
	}
	if !seen["first@example.com"] || !seen["second@example.com"] {
		t.Fatalf("missing identities: %v", seen)
	}
	if !strings.Contains(second.body, "You previously logged") {
		t.Fatal("previous-login template branch not rendered")
	}
	f.redeem(b, f.request(b, "POST", "/approve", forms[0].values), "first@example.com")
	proxy := f.request(b, "GET", "/validate?auth_server=obligator.test&redirect_uri=https://app.example/", nil)
	proxy.want(t, http.StatusOK)
	if proxy.Header.Get("Remote-Id") != "second@example.com" || proxy.Header.Get("Remote-Id-Type") != "email" {
		t.Fatalf("valid login proxy headers: %v", proxy.Header)
	}
}

func TestSecurityWildcardApproval(t *testing.T) {
	f := newSecurityFixture(t)
	b := f.browser()
	f.addIdentity(b, "test+*@example.com")
	f.request(b, "GET", "/login", nil).want(t, http.StatusOK)
	auth := f.request(b, "GET", securityAuthPath, nil)
	auth.want(t, http.StatusOK)
	form := securityOneForm(t, auth.body, "/approve")
	wildcard := f.request(b, "POST", "/approve", form.values)
	wildcard.want(t, http.StatusOK)
	if wildcard.Header.Get("Location") != "" {
		t.Fatal("wildcard selection prematurely minted a code")
	}
	form = securityOneForm(t, wildcard.body, "/approve")
	if !form.hidden["csrf_token"] || form.values.Get("csrf_token") != f.authToken(b) || form.values.Get("identity_id") != "test+*@example.com" {
		t.Fatalf("wildcard form lost request binding: %+v", form)
	}
	form.values.Set("email-wildcard", "project")
	f.redeem(b, f.request(b, "POST", "/approve", form.values), "test+project@example.com")
}

func TestSecurityQRCrossDeviceApproval(t *testing.T) {
	f := newSecurityFixture(t)
	a, b := f.browser(), f.browser()
	f.addIdentity(a, "shared@example.com")
	f.request(a, "GET", "/login", nil).want(t, http.StatusOK)
	f.addIdentity(b, "existing@example.com")
	f.request(b, "GET", "/login", nil).want(t, http.StatusOK)
	f.request(b, "GET", securityAuthPath, nil).want(t, http.StatusOK)
	oldCSRF, oldLogin := f.authToken(b), securityCookie(t, b, "test_login_key").Value
	qr := f.request(b, "GET", "/login-qr", nil)
	qr.want(t, http.StatusOK)
	receive := securityOneForm(t, qr.body, "/receive")
	key := receive.values.Get("qr_key")
	if key == "" {
		t.Fatal("QR page has no qr_key")
	}
	scan := f.request(a, "GET", "/qr?key="+url.QueryEscape(key)+"&instance_id=security-test-instance", nil)
	scan.want(t, http.StatusOK)
	send := securityOneForm(t, scan.body, "/send")
	send.values.Set("checkbox_shared@example.com", "on")
	// Sharing past-login metadata is a separate feature, not needed for login.
	send.values.Del("checkbox_share_logins")
	f.request(a, "POST", "/send", send.values).want(t, http.StatusOK)
	received := f.request(b, "POST", "/receive", receive.values)
	received.want(t, http.StatusSeeOther)
	if received.Header.Get("Location") != securityAuthPath {
		t.Fatalf("QR lost auth return URI: %q", received.Header.Get("Location"))
	}
	if securityCookie(t, b, "test_login_key").Value == oldLogin {
		t.Fatal("QR receive did not rotate login key")
	}
	rerender := f.request(b, "GET", received.Header.Get("Location"), nil)
	rerender.want(t, http.StatusOK)
	if f.authToken(b) == oldCSRF {
		t.Fatal("post-QR auth rerender did not refresh CSRF token")
	}
	forms := securityForms(rerender.body, "/approve")
	var approval url.Values
	for _, form := range forms {
		if form.values.Get("identity_id") == "shared@example.com" {
			approval = form.values
		}
	}
	if approval == nil || approval.Get("csrf_token") != f.authToken(b) {
		t.Fatal("received identity not available with CSRF token")
	}
	f.redeem(b, f.request(b, "POST", "/approve", approval), "shared@example.com")
	// A's jar was not borrowed to make B's approval succeed.
	if securityCookie(t, a, "test_auth_request") != nil {
		t.Fatal("device A unexpectedly shares B's authorization cookies")
	}
}

// A local upstream OIDC provider exercises the complete callback, including
// discovery/JWKS, a real signed ID token, nonce, and PKCE exchange.
func securityUpstream(t *testing.T) *OAuth2Provider {
	t.Helper()
	keys, err := GenerateJWKS()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.PublicSetOf(keys)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := keys.Key(0)
	var mu sync.Mutex
	var nonce, challenge string
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(OAuth2ServerMetadata{Issuer: upstream.URL, AuthorizationEndpoint: upstream.URL + "/authorize", TokenEndpoint: upstream.URL + "/token", JwksUri: upstream.URL + "/jwks"})
		case "/jwks":
			json.NewEncoder(w).Encode(pub)
		case "/authorize":
			mu.Lock()
			nonce = r.URL.Query().Get("nonce")
			challenge = r.URL.Query().Get("code_challenge")
			mu.Unlock()
			callback := r.URL.Query().Get("redirect_uri") + "?" + url.Values{"code": {"upstream-code"}, "state": {r.URL.Query().Get("state")}}.Encode()
			http.Redirect(w, r, callback, http.StatusSeeOther)
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			mu.Lock()
			n, c := nonce, challenge
			mu.Unlock()
			if r.Method != "POST" || r.PostForm.Get("code") != "upstream-code" || n == "" || c == "" || GeneratePKCECodeChallenge(r.PostForm.Get("code_verifier")) != c {
				t.Error("upstream exchange missing valid code/nonce/PKCE")
				http.Error(w, "bad exchange", 400)
				return
			}
			now := time.Now().UTC()
			token, err := openid.NewBuilder().Issuer(upstream.URL).Subject("upstream-subject").Audience([]string{"test-client"}).Email("oauth@example.com").EmailVerified(true).Name("OAuth Name").Claim("nonce", n).IssuedAt(now).Expiration(now.Add(time.Hour)).Build()
			if err != nil {
				t.Error(err)
				http.Error(w, "token build", 500)
				return
			}
			signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
			if err != nil {
				t.Error(err)
				http.Error(w, "token sign", 500)
				return
			}
			json.NewEncoder(w).Encode(OAuth2TokenResponse{AccessToken: "upstream-access", IdToken: string(signed), TokenType: "bearer"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)
	return &OAuth2Provider{ID: "test-oidc", Name: "Test OIDC", URI: upstream.URL, ClientID: "test-client", ClientSecret: "test-secret", OpenIDConnect: true}
}

func (f *securityFixture) upstreamRoundTrip(b *http.Client, loginPath string) securityResponse {
	f.t.Helper()
	login := f.request(b, "GET", loginPath, nil)
	login.want(f.t, http.StatusSeeOther)
	upstream := f.request(b, "GET", login.Header.Get("Location"), nil)
	upstream.want(f.t, http.StatusSeeOther)
	return f.request(b, "GET", upstream.Header.Get("Location"), nil)
}

func TestSecurityShortcutOAuthCallbackApproval(t *testing.T) {
	provider := securityUpstream(t)
	f := newSecurityFixture(t, provider)
	b := f.browser()
	f.addIdentity(b, "existing@example.com")
	f.request(b, "GET", "/login", nil).want(t, http.StatusOK)
	oldLogin := securityCookie(t, b, "test_login_key").Value
	auth := f.request(b, "GET", securityAuthPath+"&provider="+provider.ID, nil)
	auth.want(t, http.StatusSeeOther)
	csrf := f.authToken(b)
	for _, c := range auth.Cookies() {
		if c.Name == "test_auth_request" && (c.SameSite != http.SameSiteLaxMode || !c.HttpOnly || !c.Secure) {
			t.Fatalf("auth_request must stay Secure/HttpOnly/SameSite=Lax: %+v", c)
		}
	}
	callback := f.upstreamRoundTrip(b, auth.Header.Get("Location"))
	callback.want(t, http.StatusOK)
	if callback.Header.Get("Location") != "" {
		t.Fatal("shortcut callback redirects instead of rendering POST form")
	}
	if !regexp.MustCompile(`(?is)<noscript\b[^>]*>.*?<button\b[^>]*type\s*=\s*["']submit["'][^>]*>.*?</noscript\s*>`).MatchString(callback.body) {
		t.Fatal("shortcut form lacks noscript submit fallback")
	}
	if !strings.Contains(callback.body, "<script") || !strings.Contains(callback.body, ".submit()") {
		t.Fatal("shortcut form does not auto-submit")
	}
	form := securityOneForm(t, callback.body, "/approve")
	if !form.hidden["csrf_token"] || !form.hidden["identity_id"] || form.values.Get("csrf_token") != csrf || form.values.Get("identity_id") != "oauth@example.com" {
		t.Fatalf("bad shortcut auto-submit fields: %+v", form)
	}
	if securityCookie(t, b, "test_login_key").Value == oldLogin {
		t.Fatal("OAuth callback did not rotate login key")
	}
	if f.authToken(b) != csrf {
		t.Fatal("callback lost or replaced auth_request token before posting")
	}
	if securityCookie(t, b, "test_upstream_oauth2_request") != nil {
		t.Fatal("callback retained upstream request cookie")
	}
	f.redeem(b, f.request(b, "POST", "/approve", form.values), "oauth@example.com")
}

func TestSecurityOAuthIdentityAddRerendersAuth(t *testing.T) {
	provider := securityUpstream(t)
	f := newSecurityFixture(t, provider)
	b := f.browser()
	f.addIdentity(b, "existing@example.com")
	f.request(b, "GET", "/login", nil).want(t, http.StatusOK)
	f.request(b, "GET", securityAuthPath, nil).want(t, http.StatusOK)
	oldCSRF, oldLogin := f.authToken(b), securityCookie(t, b, "test_login_key").Value
	callback := f.upstreamRoundTrip(b, "/login-oauth2?oauth2_provider_id="+provider.ID)
	callback.want(t, http.StatusSeeOther)
	if callback.Header.Get("Location") != securityAuthPath {
		t.Fatalf("identity-add return URI=%q", callback.Header.Get("Location"))
	}
	if securityCookie(t, b, "test_login_key").Value == oldLogin {
		t.Fatal("identity-add did not rotate login key")
	}
	rerender := f.request(b, "GET", callback.Header.Get("Location"), nil)
	rerender.want(t, http.StatusOK)
	if f.authToken(b) == oldCSRF {
		t.Fatal("identity-add auth rerender reused request CSRF token")
	}
	forms := securityForms(rerender.body, "/approve")
	if len(forms) != 2 {
		t.Fatalf("want existing and added identity, got %d forms", len(forms))
	}
	for _, form := range forms {
		if !form.hidden["csrf_token"] || form.values.Get("csrf_token") != f.authToken(b) {
			t.Fatal("identity-add rerender form missing CSRF token")
		}
		if form.values.Get("identity_id") == "oauth@example.com" {
			f.redeem(b, f.request(b, "POST", "/approve", form.values), "oauth@example.com")
			return
		}
	}
	t.Fatal("added OAuth identity missing from auth rerender")
}
