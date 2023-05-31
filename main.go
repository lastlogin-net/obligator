package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

type SmtpConfig struct {
	Server     string `json:"server,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Port       int    `json:"port,omitempty"`
	Sender     string `json:"sender,omitempty"`
	SenderName string `json:"sender_name,omitempty"`
}

type OIDCDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksUri               string `json:"jwks_uri"`
}

type OAuth2AuthRequest struct {
	LoginKey         string `json:"login_key"`
	RawQuery         string `json:"raw_query"`
	ClientId         string `json:"client_id"`
	RedirectUri      string `json:"redirect_uri"`
	State            string `json:"state"`
	Scope            string `json:"scope"`
	Provider         string `json:"provider"`
	Nonce            string `json:"nonce"`
	ProviderNonce    string `json:"provider_nonce"`
	PKCECodeVerifier string `json:"pkce_code_verifier"`
}

type Oauth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IdToken     string `json:"id_token"`
}

type OathgateMux struct {
	mux *http.ServeMux
}

type UserinfoResponse struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

func NewOathgateMux() *OathgateMux {
	s := &OathgateMux{
		mux: http.NewServeMux(),
	}

	return s
}

func (s *OathgateMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *OathgateMux) HandleFunc(p string, f func(w http.ResponseWriter, r *http.Request)) {
	s.mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")

		timestamp := time.Now().Format(time.RFC3339)

		remoteIp, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
		fmt.Println(fmt.Sprintf("%s\t%s\t%s\t%s\t%s", timestamp, remoteIp, r.Method, r.Host, r.URL.Path))

		f(w, r)
	})
}

//go:embed templates assets
var fs embed.FS

func main() {

	port := flag.Int("port", 9002, "Port")
	flag.Parse()

	storage, err := NewFileStorage("oathgate_db.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if storage.GetJWKSet().Len() == 0 {
		key, err := GenerateJWK()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		storage.AddJWKKey(key)
	}

	emailAuth := NewEmailAuth(storage)

	publicJwks, err := jwk.PublicSetOf(storage.GetJWKSet())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	rootUri := storage.GetRootUri()
	callbackUri := fmt.Sprintf("%s/callback", rootUri)

	ctx := context.Background()

	oidcConfigs := make(map[string]*OIDCDiscoveryDoc)
	jwksRefreshers := make(map[string]*jwk.AutoRefresh)
	// TODO: This is not thread-safe
	go func() {
		for _, oidcProvider := range storage.GetOAuth2Providers() {
			if !oidcProvider.OpenIDConnect {
				continue
			}
			oidcConfigs[oidcProvider.ID], err = GetOidcConfiguration(oidcProvider.URI)
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}

			jwksRefreshers[oidcProvider.ID] = jwk.NewAutoRefresh(ctx)
			jwksRefreshers[oidcProvider.ID].Configure(oidcConfigs[oidcProvider.ID].JwksUri)

			_, err = jwksRefreshers[oidcProvider.ID].Refresh(ctx, oidcConfigs[oidcProvider.ID].JwksUri)
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
		}
	}()

	providerLogoMap := make(map[string]template.HTML)
	for _, prov := range storage.GetOAuth2Providers() {
		logoPath := fmt.Sprintf("assets/logo_%s.svg", prov.ID)
		logoBytes, err := fs.ReadFile(logoPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		providerLogoMap[prov.ID] = template.HTML(logoBytes)
	}

	tmpl, err := template.ParseFS(fs, "templates/*.tmpl")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	httpClient := &http.Client{}

	mux := NewOathgateMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<h1>Welcome to LastLogin.io</h1>"))
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")

		doc := OIDCDiscoveryDoc{
			Issuer:                rootUri,
			AuthorizationEndpoint: fmt.Sprintf("%s/auth", rootUri),
			TokenEndpoint:         fmt.Sprintf("%s/token", rootUri),
			UserinfoEndpoint:      fmt.Sprintf("%s/userinfo", rootUri),
			JwksUri:               fmt.Sprintf("%s/jwks", rootUri),
		}

		json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(publicJwks)
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		parts := strings.Split(authHeader, " ")

		if len(parts) != 2 {
			w.WriteHeader(400)
			io.WriteString(w, "Invalid Authorization header")
			return
		}

		unhashedToken := parts[1]

		tokenData, err := storage.GetToken(Hash(unhashedToken))
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		expired, err := tokenExpired(tokenData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
		if expired {
			storage.DeleteToken(Hash(unhashedToken))
			w.WriteHeader(401)
			io.WriteString(w, "Token expired")
			return
		}

		ident, err := storage.GetIdentityById(tokenData.IdentityId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		userResponse := UserinfoResponse{
			Sub:   ident.Id,
			Email: ident.Email,
		}

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(userResponse)
	})

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		clientId := r.Form.Get("client_id")
		if clientId == "" {
			w.WriteHeader(400)
			io.WriteString(w, "client_id missing")
			return
		}

		clientIdUrl, err := url.Parse(clientId)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		redirectUri := r.Form.Get("redirect_uri")
		if redirectUri == "" {
			w.WriteHeader(400)
			io.WriteString(w, "redirect_uri missing")
			return
		}

		if !strings.HasPrefix(redirectUri, clientId) {
			w.WriteHeader(400)
			io.WriteString(w, "redirect_uri must be on the same domain as client_id")
			return
		}

		state := r.Form.Get("state")

		promptParam := r.Form.Get("prompt")
		if promptParam == "none" {
			errUrl := fmt.Sprintf("%s?error=interaction_required&state=%s",
				redirectUri, state)
			http.Redirect(w, r, errUrl, 302)
			return
		}

		responseType := r.Form.Get("response_type")
		if responseType == "" {
			errUrl := fmt.Sprintf("%s?error=unsupported_response_type&state=%s",
				redirectUri, state)
			http.Redirect(w, r, errUrl, 302)
			return
		}

		identities := []*Identity{}

		var loginKey string

		loginKeyCookie, err := r.Cookie("login_key")
		if err == nil {
			loginKey = Hash(loginKeyCookie.Value)
			identities = storage.GetIdentitiesByLoginKey(loginKey)
		}

		req := OAuth2AuthRequest{
			LoginKey:    loginKey,
			RawQuery:    r.URL.RawQuery,
			ClientId:    clientId,
			RedirectUri: redirectUri,
			State:       state,
			Scope:       r.Form.Get("scope"),
			Nonce:       r.Form.Get("nonce"),
		}

		requestId, err := storage.AddRequest(req)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		data := struct {
			ClientId        string
			RequestId       string
			Identities      []*Identity
			OAuth2Providers []*OAuth2Provider
			LogoMap         map[string]template.HTML
			URL             string
		}{
			ClientId:        clientIdUrl.Host,
			RequestId:       requestId,
			Identities:      identities,
			OAuth2Providers: storage.GetOAuth2Providers(),
			LogoMap:         providerLogoMap,
			URL:             fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery),
		}

		err = tmpl.ExecuteTemplate(w, "auth.tmpl", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/approve", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			io.WriteString(w, err.Error())
			return
		}

		loginKeyCookie, err := r.Cookie("login_key")
		if err != nil {
			w.WriteHeader(401)
			io.WriteString(w, "Only logged-in users can access this endpoint")
			return
		}

		loginKey := Hash(loginKeyCookie.Value)

		requestId := r.Form.Get("request_id")

		request, err := storage.GetRequest(requestId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		if request.LoginKey != loginKey {
			w.WriteHeader(403)
			io.WriteString(w, "Not your request")
			return
		}

		identId := r.Form.Get("identity_id")

		identity, err := storage.GetIdentityById(identId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		owner := false
		for _, mapping := range storage.GetLoginMap() {
			if mapping.LoginKey == loginKey && mapping.IdentityId == identId {
				owner = true
				break
			}
		}

		if !owner {
			w.WriteHeader(403)
			io.WriteString(w, "You don't have permissions for this identity")
			return
		}

		issuedAt := time.Now().UTC()
		expiresAt := issuedAt.Add(10 * time.Minute)

		token, err := openid.NewBuilder().
			Subject(identId).
			Audience([]string{request.ClientId}).
			Issuer(rootUri).
			Email(identity.Email).
			EmailVerified(true).
			IssuedAt(issuedAt).
			Expiration(expiresAt).
			Claim("nonce", request.Nonce).
			Build()
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		oauth2Token := &PendingOAuth2Token{
			IdToken: token,
		}

		code, err := storage.AddPendingToken(oauth2Token)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		url := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&code=%s&state=%s&scope=%s",
			request.RedirectUri,
			request.ClientId,
			request.RedirectUri,
			code,
			request.State,
			request.Scope)

		http.Redirect(w, r, url, 302)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		code := r.Form.Get("code")

		token, err := storage.GetPendingToken(code)
		if err != nil {

			// Check if code has been used more than once
			for token, tokenData := range storage.GetTokens() {
				if code == tokenData.AuthorizationCode {
					storage.DeleteToken(token)
					w.WriteHeader(401)
					io.WriteString(w, "Attempt to use authorization code multiple times. Someone may be trying to hack your account. Deleting access token as a precaution.")
					return
				}
			}

			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		storage.DeletePendingToken(code)

		tokenData := &Token{
			IdentityId:        token.IdToken.Subject(),
			CreatedAt:         time.Now().UTC().Format(time.RFC3339),
			ExpiresIn:         10,
			AuthorizationCode: code,
		}

		err = storage.SetToken(Hash(token.AccessToken), tokenData)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		key, exists := storage.GetJWKSet().Get(0)
		if !exists {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, "No keys available")
			return
		}

		signed, err := jwt.Sign(token.IdToken, jwa.RS256, key)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")

		tokenRes := Oauth2TokenResponse{
			AccessToken: token.AccessToken,
			ExpiresIn:   3600,
			IdToken:     string(signed),
			TokenType:   "bearer",
		}

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(tokenRes)
	})

	mux.HandleFunc("/login-email", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		if r.Method != "POST" {
			w.WriteHeader(405)
			io.WriteString(w, "Invalid method")
			return
		}

		requestId := r.Form.Get("request_id")

		templateData := struct {
			RequestId string
		}{
			RequestId: requestId,
		}

		err = tmpl.ExecuteTemplate(w, "login-email.tmpl", templateData)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/email-code", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		if r.Method != "POST" {
			w.WriteHeader(405)
			io.WriteString(w, "Invalid method")
			return
		}

		email := r.Form.Get("email")
		if email == "" {
			w.WriteHeader(400)
			io.WriteString(w, "email param missing")
			return
		}

		requestId := r.Form.Get("request_id")

		emailRequestId, err := emailAuth.StartEmailValidation(email)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		data := struct {
			RequestId      string
			EmailRequestId string
		}{
			RequestId:      requestId,
			EmailRequestId: emailRequestId,
		}

		err = tmpl.ExecuteTemplate(w, "email-code.tmpl", data)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/complete-email-login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			io.WriteString(w, "Invalid method")
			return
		}

		r.ParseForm()

		requestId := r.Form.Get("request_id")
		request, err := storage.GetRequest(requestId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		emailRequestId := r.Form.Get("email_request_id")
		if emailRequestId == "" {
			w.WriteHeader(400)
			io.WriteString(w, "email_request_id param missing")
			return
		}

		code := r.Form.Get("code")
		if code == "" {
			w.WriteHeader(400)
			io.WriteString(w, "code param missing")
			return
		}

		_, email, err := emailAuth.CompleteEmailValidation(emailRequestId, code)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		var loginKey string
		loggedIn := false

		loginKeyCookie, err := r.Cookie("login_key")
		if err == nil {
			loginKey = Hash(loginKeyCookie.Value)
			_, err := storage.GetLoginData(loginKey)
			if err == nil {
				loggedIn = true
			}
		}

		if !loggedIn {
			unhashedLoginKey, err := storage.AddLoginData()
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			cookie := &http.Cookie{
				Name:     "login_key",
				Value:    unhashedLoginKey,
				Secure:   true,
				HttpOnly: true,
				MaxAge:   86400 * 365,
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
				//SameSite: http.SameSiteStrictMode,
			}
			http.SetCookie(w, cookie)

			loginKey = Hash(unhashedLoginKey)
		}

		identId, err := storage.EnsureIdentity(email, "Email", email)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		storage.EnsureLoginMapping(identId, loginKey)

		redirUrl := fmt.Sprintf("%s/auth?%s", rootUri, request.RawQuery)

		http.Redirect(w, r, redirUrl, 302)
	})

	mux.HandleFunc("/login-oauth2", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		requestId := r.Form.Get("request_id")

		oauth2ProviderId := r.Form.Get("oauth2_provider_id")

		provider, err := storage.GetOAuth2ProviderByID(oauth2ProviderId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		request, err := storage.GetRequest(requestId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		request.Provider = provider.ID

		scope := "openid email"
		if provider.Scope != "" {
			scope = provider.Scope
		}

		var authURL string
		if provider.OpenIDConnect {
			authURL = oidcConfigs[provider.ID].AuthorizationEndpoint
		} else {
			authURL = provider.AuthorizationURI
		}

		pkceCodeChallenge, pkceCodeVerifier, err := GeneratePKCEData()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		request.PKCECodeVerifier = pkceCodeVerifier

		request.ProviderNonce, err = genRandomKey()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, "Failed to generate nonce")
			return
		}

		storage.SetRequest(requestId, request)

		url := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&state=%s&scope=%s&response_type=code&code_challenge_method=S256&code_challenge=%s&nonce=%s",
			authURL, provider.ClientID, callbackUri, requestId,
			scope, pkceCodeChallenge, request.ProviderNonce)

		http.Redirect(w, r, url, 302)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		requestId := r.Form.Get("state")
		request, err := storage.GetRequest(requestId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		storage.DeleteRequest(requestId)

		oauth2Provider, err := storage.GetOAuth2ProviderByID(request.Provider)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		providerCode := r.Form.Get("code")

		body := url.Values{}
		body.Set("code", providerCode)
		body.Set("client_id", oauth2Provider.ClientID)
		body.Set("client_secret", oauth2Provider.ClientSecret)
		body.Set("redirect_uri", callbackUri)
		body.Set("grant_type", "authorization_code")
		body.Set("code_verifier", request.PKCECodeVerifier)

		var tokenEndpoint string
		if oauth2Provider.OpenIDConnect {
			if oauth2Provider.ID == "facebook" {
				// Facebook strangely appears to implement all of OIDC except the token endpoint...
				tokenEndpoint = oauth2Provider.TokenURI
			} else {
				tokenEndpoint = oidcConfigs[oauth2Provider.ID].TokenEndpoint
			}
		} else {
			tokenEndpoint = oauth2Provider.TokenURI
		}

		upstreamReq, err := http.NewRequest(http.MethodPost,
			tokenEndpoint,
			strings.NewReader(body.Encode()))
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, "Creating request failed")
			return
		}

		upstreamReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		upstreamReq.Header.Add("Accept", "application/json")

		resp, err := httpClient.Do(upstreamReq)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, "Doing request failed")
			return
		}

		if resp.StatusCode != 200 {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, "Request failed with invalid status")
			b, _ := io.ReadAll(resp.Body)
			fmt.Println(string(b))
			return
		}

		var tokenRes Oauth2TokenResponse

		err = json.NewDecoder(resp.Body).Decode(&tokenRes)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		var providerIdentityId string
		var email string

		if oauth2Provider.OpenIDConnect {
			keyset, err := jwksRefreshers[oauth2Provider.ID].Fetch(ctx, oidcConfigs[oauth2Provider.ID].JwksUri)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			providerOauth2Token, err := jwt.Parse([]byte(tokenRes.IdToken), jwt.WithKeySet(keyset), jwt.WithToken(openid.New()))
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			providerOidcToken, ok := providerOauth2Token.(openid.Token)
			if !ok {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, "Not a valid OpenId Connect token")
				return
			}

			printJson(providerOidcToken)

			nonceClaim, exists := providerOidcToken.Get("nonce")
			if !exists {
				w.WriteHeader(400)
				fmt.Fprintf(os.Stderr, "Nonce missing")
				return
			}

			nonce, ok := nonceClaim.(string)
			if !ok {
				w.WriteHeader(400)
				fmt.Fprintf(os.Stderr, "Invalid nonce format")
				return
			}

			if request.ProviderNonce != nonce {
				w.WriteHeader(403)
				fmt.Fprintf(os.Stderr, "Invalid nonce")
				return
			}

			providerIdentityId = providerOidcToken.Subject()
			email = providerOidcToken.Email()
		} else {
			providerIdentityId, email, _ = GetProfile(oauth2Provider, tokenRes.AccessToken)
		}

		loggedIn := false

		var loginKey string

		loginKeyCookie, err := r.Cookie("login_key")
		if err == nil {
			loginKey = Hash(loginKeyCookie.Value)
			_, err := storage.GetLoginData(loginKey)
			if err == nil {
				loggedIn = true
			}
		}

		// Since no identities exist for the user, create a new user
		if !loggedIn {
			unhashedLoginKey, err := storage.AddLoginData()
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			cookie := &http.Cookie{
				Name:     "login_key",
				Value:    unhashedLoginKey,
				Secure:   true,
				HttpOnly: true,
				MaxAge:   86400 * 365,
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
				//SameSite: http.SameSiteStrictMode,
			}
			http.SetCookie(w, cookie)

			loginKey = Hash(unhashedLoginKey)
		}

		identId, err := storage.EnsureIdentity(providerIdentityId, oauth2Provider.Name, email)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		storage.EnsureLoginMapping(identId, loginKey)

		redirUrl := fmt.Sprintf("%s/auth?%s", rootUri, request.RawQuery)

		http.Redirect(w, r, redirUrl, 302)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}

		r.ParseForm()

		loginKeyCookie, err := r.Cookie("login_key")
		if err == nil {
			loginKey := Hash(loginKeyCookie.Value)
			storage.DeleteLoginData(loginKey)
		}

		redirect := r.Form.Get("prev_page")

		cookie := &http.Cookie{
			Name:     "login_key",
			Value:    "",
			Secure:   true,
			HttpOnly: true,
			MaxAge:   86400 * 365,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			//SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, cookie)

		http.Redirect(w, r, redirect, 303)
	})

	mux.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		printJson(r.Header)
	})

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: mux,
	}

	// Clean up expired tokens occasionally
	go func() {
		for {
			for token, tokenData := range storage.GetTokens() {
				expired, err := tokenExpired(tokenData)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to parse time\n")
					continue
				}
				if expired {
					storage.DeleteToken(token)
				}
			}

			time.Sleep(1 * time.Hour)
		}
	}()

	fmt.Println("Running")

	err = server.ListenAndServe()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func GetOidcConfiguration(baseUrl string) (*OIDCDiscoveryDoc, error) {

	url := fmt.Sprintf("%s/.well-known/openid-configuration", baseUrl)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New("Invalid HTTP response")
	}

	var doc OIDCDiscoveryDoc

	err = json.NewDecoder(resp.Body).Decode(&doc)
	if err != nil {
		return nil, err
	}

	return &doc, nil
}

func GenerateJWK() (jwk.Key, error) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	key, err := jwk.New(raw)
	if err != nil {
		return nil, err
	}

	if _, ok := key.(jwk.RSAPrivateKey); !ok {
		return nil, err
	}

	//key.Set(jwk.KeyIDKey, "lastlogin-key-1")

	err = jwk.AssignKeyID(key)
	if err != nil {
		return nil, err
	}

	//key.Set(jwk.KeyUsageKey, "sig")
	//keyset := jwk.NewSet()
	//keyset.Add(key)
	//return keyset, nil

	return key, nil
}

type GitHubEmailResponse []*GitHubEmail

type GitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func GetProfile(provider *OAuth2Provider, accessToken string) (string, string, error) {
	httpClient := &http.Client{}

	switch provider.ID {
	case "github":
		req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user/emails", nil)
		if err != nil {
			return "", "", err
		}

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", "", err
		}

		if resp.StatusCode != 200 {
			return "", "", errors.New("Bad status getting profile")
		}

		var profileResponse GitHubEmailResponse

		err = json.NewDecoder(resp.Body).Decode(&profileResponse)
		if err != nil {
			return "", "", err
		}

		for _, email := range profileResponse {
			if email.Primary {
				return provider.URI, email.Email, nil
			}
		}

	}

	return "", "", errors.New("Unknown GetProfile error")
}
