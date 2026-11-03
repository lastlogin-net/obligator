package obligator

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

const securityOrigin = "https://obligator.test"
const securityAuthPath = "/auth?client_id=https%3A%2F%2Frp.example&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&response_type=code&state=rp-state&scope=openid+email+profile&nonce=rp-nonce"

// Keep the real HTTPS handler stack, cookie domains and Secure-cookie behavior.
// Only DNS for obligator.test is redirected to the local httptest listener.
type securityFixture struct {
	t         *testing.T
	server    *Server
	transport *http.Transport
}

func newSecurityFixture(t *testing.T, providers ...*OAuth2Provider) *securityFixture {
	t.Helper()
	// The QR code contains this configured instance ID; no QR image decoder is needed.
	t.Setenv("FLY_ALLOC_ID", "security-test-instance")
	db, err := NewSqliteDatabase(filepath.Join(t.TempDir(), "security.sqlite"), "test_")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.db.Close() })
	s := NewServer(ServerConfig{Database: db, Prefix: "test_", Domains: []string{"obligator.test"}, ProxyType: "builtin", Public: true, OAuth2Providers: providers})
	ts := httptest.NewTLSServer(s)
	t.Cleanup(ts.Close)
	transport := ts.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "example.com" // httptest's certificate name
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "obligator.test:443" {
			addr = ts.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &securityFixture{t: t, server: s, transport: transport}
}

func (f *securityFixture) browser() *http.Client {
	f.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return &http.Client{Transport: f.transport, Jar: jar, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type securityResponse struct {
	*http.Response
	body string
}

func (f *securityFixture) request(b *http.Client, method, target string, form url.Values) securityResponse {
	f.t.Helper()
	if strings.HasPrefix(target, "/") {
		target = securityOrigin + target
	}
	// Browsers escape spaces in redirect Locations; net/http does not do so
	// when following an explicitly constructed request (upstream scope has spaces).
	target = strings.ReplaceAll(target, " ", "%20")
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequest(method, target, body)
	if err != nil {
		f.t.Fatal(err)
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := b.Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return securityResponse{resp, string(data)}
}

func (r securityResponse) want(t *testing.T, status int) {
	t.Helper()
	if r.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d; body=%s", r.Request.Method, r.Request.URL, r.StatusCode, status, r.body)
	}
}

func securityURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func securityCookie(t *testing.T, b *http.Client, name string) *http.Cookie {
	t.Helper()
	for _, c := range b.Jar.Cookies(securityURL(t, securityOrigin)) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (f *securityFixture) addIdentity(b *http.Client, email string) {
	f.t.Helper()
	value := ""
	if c := securityCookie(f.t, b, "test_login_key"); c != nil {
		value = c.Value
	}
	c, err := addIdentToCookie("obligator.test", f.server.db, value, &Identity{IdType: IdentityTypeEmail, Id: email, ProviderName: "email", Email: email, EmailVerified: true}, f.server.jose)
	if err != nil {
		f.t.Fatal(err)
	}
	b.Jar.SetCookies(securityURL(f.t, securityOrigin), []*http.Cookie{c})
}

func (f *securityFixture) authToken(b *http.Client) string {
	f.t.Helper()
	c := securityCookie(f.t, b, "test_auth_request")
	if c == nil {
		f.t.Fatal("missing auth_request cookie")
	}
	tok, err := f.server.jose.Parse(c.Value)
	if err != nil {
		f.t.Fatal(err)
	}
	csrf := claimFromToken("csrf_token", tok)
	if csrf == "" {
		f.t.Fatal("auth_request has no nonempty csrf_token claim")
	}
	return csrf
}

// These deliberately small HTML helpers read the actual rendered forms instead
// of duplicating production form fields. All template attributes are quoted.
var securityFormRE = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form\s*>`)
var securityInputRE = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
var securityAttrRE = regexp.MustCompile(`([\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')`)

func securityAttrs(text string) map[string]string {
	attrs := map[string]string{}
	for _, m := range securityAttrRE.FindAllStringSubmatch(text, -1) {
		v := m[2]
		if v == "" {
			v = m[3]
		}
		attrs[strings.ToLower(m[1])] = html.UnescapeString(v)
	}
	return attrs
}

type securityForm struct {
	attrs  map[string]string
	values url.Values
	hidden map[string]bool
}

func securityForms(body, action string) []securityForm {
	var forms []securityForm
	for _, match := range securityFormRE.FindAllStringSubmatch(body, -1) {
		attrs := securityAttrs(match[1])
		if attrs["action"] != action {
			continue
		}
		form := securityForm{attrs: attrs, values: url.Values{}, hidden: map[string]bool{}}
		for _, input := range securityInputRE.FindAllStringSubmatch(match[2], -1) {
			a := securityAttrs(input[1])
			if a["name"] == "" {
				continue
			}
			form.values.Add(a["name"], a["value"])
			form.hidden[a["name"]] = strings.EqualFold(a["type"], "hidden")
		}
		forms = append(forms, form)
	}
	return forms
}

func securityOneForm(t *testing.T, body, action string) securityForm {
	t.Helper()
	forms := securityForms(body, action)
	if len(forms) != 1 {
		t.Fatalf("got %d forms for %s, want one; HTML=%s", len(forms), action, body)
	}
	if !strings.EqualFold(forms[0].attrs["method"], "POST") {
		t.Fatalf("%s form must POST", action)
	}
	return forms[0]
}

func (f *securityFixture) redeem(b *http.Client, approval securityResponse, email string) {
	f.t.Helper()
	approval.want(f.t, http.StatusSeeOther)
	loc := securityURL(f.t, approval.Header.Get("Location"))
	if loc.Scheme != "https" || loc.Host != "rp.example" || loc.Path != "/callback" || loc.Query().Get("state") != "rp-state" || loc.Query().Get("code") == "" {
		f.t.Fatalf("bad RP redirect: %s", loc)
	}
	resp := f.request(b, "POST", "/token", url.Values{"code": {loc.Query().Get("code")}})
	resp.want(f.t, http.StatusOK)
	var tokens OAuth2TokenResponse
	if err := json.Unmarshal([]byte(resp.body), &tokens); err != nil {
		f.t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.IdToken == "" {
		f.t.Fatalf("missing tokens: %+v", tokens)
	}
	pub, err := f.server.jose.GetPublicJwks()
	if err != nil {
		f.t.Fatal(err)
	}
	id, err := jwt.Parse([]byte(tokens.IdToken), jwt.WithKeySet(pub), jwt.WithToken(openid.New()))
	if err != nil {
		f.t.Fatalf("ID token signature/validation failed: %v", err)
	}
	if id.Subject() != email || claimFromToken("email", id) != email || len(id.Audience()) != 1 || id.Audience()[0] != "https://rp.example" || claimFromToken("nonce", id) != "rp-nonce" {
		f.t.Fatalf("incorrect ID token: sub=%s aud=%v", id.Subject(), id.Audience())
	}
	r, err := http.NewRequest("GET", securityOrigin+"/userinfo", nil)
	if err != nil {
		f.t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	uiResp, err := b.Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	defer uiResp.Body.Close()
	var ui UserinfoResponse
	if err := json.NewDecoder(uiResp.Body).Decode(&ui); err != nil {
		f.t.Fatal(err)
	}
	if uiResp.StatusCode != http.StatusOK || ui.Sub != email || ui.Email != email {
		f.t.Fatalf("userinfo status=%d value=%+v", uiResp.StatusCode, ui)
	}
	if securityCookie(f.t, b, "test_auth_request") != nil {
		f.t.Fatal("approval did not clear auth_request")
	}
}
