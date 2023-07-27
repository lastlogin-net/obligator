package main

import (
	"crypto/rand"
	"crypto/rsa"
	"embed"
	"encoding/json"
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

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

type SmtpConfig struct {
	Server     string `json:"server,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Port       int    `json:"port,omitempty"`
	Sender     string `json:"sender,omitempty"`
	SenderName string `json:"sender_name,omitempty"`
}

type OAuth2ServerMetadata struct {
	Issuer                           string   `json:"issuer,omitempty"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                    string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	JwksUri                          string   `json:"jwks_uri,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported,omitempty"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

type OAuth2AuthRequest struct {
	LoginKey          string `json:"login_key"`
	RawQuery          string `json:"raw_query"`
	ClientId          string `json:"client_id"`
	RedirectUri       string `json:"redirect_uri"`
	State             string `json:"state"`
	Scope             string `json:"scope"`
	Provider          string `json:"provider"`
	Nonce             string `json:"nonce"`
	ProviderNonce     string `json:"provider_nonce"`
	PKCECodeVerifier  string `json:"pkce_code_verifier"`
	PKCECodeChallenge string `json:"pkce_code_challenge"`
}

type Oauth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IdToken     string `json:"id_token"`
}

type ObligatorMux struct {
	mux *http.ServeMux
}

type UserinfoResponse struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

func NewObligatorMux() *ObligatorMux {
	s := &ObligatorMux{
		mux: http.NewServeMux(),
	}

	return s
}

func (s *ObligatorMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; script-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")

	timestamp := time.Now().Format(time.RFC3339)

	remoteIp, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}
	fmt.Println(fmt.Sprintf("%s\t%s\t%s\t%s\t%s", timestamp, remoteIp, r.Method, r.Host, r.URL.Path))
	s.mux.ServeHTTP(w, r)
}

func (s *ObligatorMux) Handle(p string, h http.Handler) {
	s.mux.Handle(p, h)
}

func (s *ObligatorMux) HandleFunc(p string, f func(w http.ResponseWriter, r *http.Request)) {
	s.mux.HandleFunc(p, f)
}

//go:embed templates assets
var fs embed.FS

func main() {

	port := flag.Int("port", 9002, "Port")
	rootUri := flag.String("root-uri", "", "Root URI")
	flag.Parse()

	storage, err := NewSqliteStorage("obligator_storage.sqlite3")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if *rootUri != "" {
		storage.SetRootUri(*rootUri)
	}

	if storage.GetRootUri() == "" {
		fmt.Fprintln(os.Stderr, "No root-uri in storage. You must provide one")
		os.Exit(1)
	}

	jsonStorage, err := NewJsonStorage("obligator_storage.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	_, err = NewApi(storage, jsonStorage)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if jsonStorage.GetJWKSet().Len() == 0 {
		key, err := GenerateJWK()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		jsonStorage.AddJWKKey(key)
	}

	publicJwks, err := jwk.PublicSetOf(jsonStorage.GetJWKSet())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	tmpl, err := template.ParseFS(fs, "templates/*.tmpl")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	oauth2Handler := NewOauth2Handler(storage, jsonStorage)
	mux := NewObligatorMux()

	mux.Handle("/login-oauth2", oauth2Handler)
	mux.Handle("/callback", oauth2Handler)

	emailHandler := NewEmailHander(storage, jsonStorage)
	mux.Handle("/login-email", emailHandler)
	mux.Handle("/email-code", emailHandler)
	mux.Handle("/complete-email-login", emailHandler)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<h1>Welcome to LastLogin.io</h1>"))
	})

	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		redirectUri := r.Form.Get("redirect_uri")
		url := fmt.Sprintf("%s/auth?client_id=%s&redirect_uri=%s&response_type=code&state=&scope=",
			storage.GetRootUri(), redirectUri, redirectUri)

		loginKeyCookie, err := r.Cookie("login_key")
		if err != nil {
			http.Redirect(w, r, url, 307)
			return
		}

		loginKey := Hash(loginKeyCookie.Value)

		for _, mapping := range jsonStorage.GetLoginMap() {
			if mapping.LoginKey == loginKey {
				// found a valid user
				return
			}
		}

		http.Redirect(w, r, url, 307)
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		rootUri := storage.GetRootUri()

		doc := OAuth2ServerMetadata{
			Issuer:                           rootUri,
			AuthorizationEndpoint:            fmt.Sprintf("%s/auth", rootUri),
			TokenEndpoint:                    fmt.Sprintf("%s/token", rootUri),
			UserinfoEndpoint:                 fmt.Sprintf("%s/userinfo", rootUri),
			JwksUri:                          fmt.Sprintf("%s/jwks", rootUri),
			ScopesSupported:                  []string{"openid", "email", "profile"},
			ResponseTypesSupported:           []string{"code"},
			IdTokenSigningAlgValuesSupported: []string{"RS256"},
		}

		json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

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

		tokenData, err := jsonStorage.GetToken(Hash(unhashedToken))
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
			jsonStorage.DeleteToken(Hash(unhashedToken))
			w.WriteHeader(401)
			io.WriteString(w, "Token expired")
			return
		}

		ident, err := jsonStorage.GetIdentityById(tokenData.IdentityId)
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
			http.Redirect(w, r, errUrl, http.StatusSeeOther)
			return
		}

		responseType := r.Form.Get("response_type")
		if responseType == "" {
			errUrl := fmt.Sprintf("%s?error=unsupported_response_type&state=%s",
				redirectUri, state)
			http.Redirect(w, r, errUrl, http.StatusSeeOther)
			return
		}

		identities := []*Identity{}

		var loginKey string

		loginKeyCookie, err := r.Cookie("login_key")
		if err == nil {
			loginKey = Hash(loginKeyCookie.Value)
			identities = jsonStorage.GetIdentitiesByLoginKey(loginKey)
		}

		req := OAuth2AuthRequest{
			LoginKey:          loginKey,
			RawQuery:          r.URL.RawQuery,
			ClientId:          clientId,
			RedirectUri:       redirectUri,
			State:             state,
			Scope:             r.Form.Get("scope"),
			Nonce:             r.Form.Get("nonce"),
			PKCECodeChallenge: r.Form.Get("code_challenge"),
		}

		requestId, err := jsonStorage.AddRequest(req)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		providers, err := storage.GetOAuth2Providers()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		data := struct {
			ClientId        string
			RequestId       string
			Identities      []*Identity
			OAuth2Providers []OAuth2Provider
			LogoMap         map[string]template.HTML
			URL             string
		}{
			ClientId:        clientIdUrl.Host,
			RequestId:       requestId,
			Identities:      identities,
			OAuth2Providers: providers,
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

		request, err := jsonStorage.GetRequest(requestId)
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

		identity, err := jsonStorage.GetIdentityById(identId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		owner := false
		for _, mapping := range jsonStorage.GetLoginMap() {
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
			Issuer(storage.GetRootUri()).
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
			IdToken:           token,
			PKCECodeChallenge: request.PKCECodeChallenge,
		}

		code, err := jsonStorage.AddPendingToken(oauth2Token)
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

		http.Redirect(w, r, url, http.StatusSeeOther)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		code := r.Form.Get("code")
		defer jsonStorage.DeletePendingToken(code)

		token, err := jsonStorage.GetPendingToken(code)
		if err != nil {

			// Check if code has been used more than once
			for token, tokenData := range jsonStorage.GetTokens() {
				if code == tokenData.AuthorizationCode {
					jsonStorage.DeleteToken(token)
					w.WriteHeader(401)
					io.WriteString(w, "Attempt to use authorization code multiple times. Someone may be trying to hack your account. Deleting access token as a precaution.")
					return
				}
			}

			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.8.2
		pkceCodeVerifier := r.Form.Get("code_verifier")
		if token.PKCECodeChallenge != "" {
			challenge := GeneratePKCECodeChallenge(pkceCodeVerifier)
			if challenge != token.PKCECodeChallenge {
				w.WriteHeader(401)
				io.WriteString(w, "Invalid code_verifier")
				return
			}
		} else {
			if pkceCodeVerifier != "" {
				w.WriteHeader(401)
				io.WriteString(w, "code_verifier provided for request that did not include code_challenge")
				return
			}
		}

		tokenData := &Token{
			IdentityId:        token.IdToken.Subject(),
			CreatedAt:         time.Now().UTC().Format(time.RFC3339),
			ExpiresIn:         10,
			AuthorizationCode: code,
		}

		err = jsonStorage.SetToken(Hash(token.AccessToken), tokenData)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		key, exists := jsonStorage.GetJWKSet().Key(0)
		if !exists {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, "No keys available")
			return
		}

		signed, err := jwt.Sign(token.IdToken, jwt.WithKey(jwa.RS256, key))
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

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}

		r.ParseForm()

		loginKeyCookie, err := r.Cookie("login_key")
		if err == nil {
			loginKey := Hash(loginKeyCookie.Value)
			jsonStorage.DeleteLoginData(loginKey)
		}

		redirect := r.Form.Get("prev_page")

		cookieDomain, err := buildCookieDomain(storage.GetRootUri())
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		cookie := &http.Cookie{
			Domain:   cookieDomain,
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

		http.Redirect(w, r, redirect, http.StatusSeeOther)
	})

	mux.HandleFunc("/no-account", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			URL string
		}{
			URL: fmt.Sprintf("/auth?%s", r.URL.RawQuery),
		}

		err = tmpl.ExecuteTemplate(w, "no-account.tmpl", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
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
			for token, tokenData := range jsonStorage.GetTokens() {
				expired, err := tokenExpired(tokenData)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to parse time\n")
					continue
				}
				if expired {
					jsonStorage.DeleteToken(token)
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

func GenerateJWK() (jwk.Key, error) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	key, err := jwk.FromRaw(raw)
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

	key.Set("alg", "RS256")

	//key.Set(jwk.KeyUsageKey, "sig")
	//keyset := jwk.NewSet()
	//keyset.Add(key)
	//return keyset, nil

	return key, nil
}
