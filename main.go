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
	"math/big"
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

type Config struct {
	RootUri string  `json:"root_uri"`
	Jwks    jwk.Set `json:"jwks"`
}

type OIDCDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksUri               string `json:"jwks_uri"`
}

type OAuth2AuthRequest struct {
	OwnerId     string `json:"owner_id"`
	RawQuery    string `json:"raw_query"`
	ClientId    string `json:"client_id"`
	RedirectUri string `json:"redirect_uri"`
	State       string `json:"state"`
	Scope       string `json:"scope"`
	Provider    string `json:"provider"`
	Nonce       string `json:"nonce"`
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

//go:embed templates
var fs embed.FS

func main() {

	port := flag.Int("port", 9002, "Port")
	flag.Parse()

	config := &Config{
		Jwks: jwk.NewSet(),
	}

	configJson, err := os.ReadFile("oathgate_config.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	err = json.Unmarshal(configJson, config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	publicJwks, err := jwk.PublicSetOf(config.Jwks)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	rootUri := config.RootUri
	callbackUri := fmt.Sprintf("%s/callback", rootUri)

	storage, err := NewFileStorage("oathgate_db.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	ctx := context.Background()

	oidcConfigs := make(map[string]*OIDCDiscoveryDoc)
	jwksRefreshers := make(map[string]*jwk.AutoRefresh)
	// TODO: This is not thread-safe
	go func() {
		for _, oidcProvider := range storage.GetOIDCProviders() {
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

		token := parts[1]

		tok, err := storage.GetToken(token)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		ident, err := storage.GetIdentityById(tok.IdentityId)
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

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		requestId := r.Form.Get("state")
		request, err := storage.GetRequest(requestId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		oidcProvider, err := storage.GetOIDCProviderByID(request.Provider)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		providerCode := r.Form.Get("code")

		body := url.Values{}
		body.Set("code", providerCode)
		body.Set("client_id", oidcProvider.ClientID)
		body.Set("client_secret", oidcProvider.ClientSecret)
		body.Set("redirect_uri", callbackUri)
		body.Set("grant_type", "authorization_code")

		upstreamReq, err := http.NewRequest(http.MethodPost,
			oidcConfigs[oidcProvider.ID].TokenEndpoint,
			strings.NewReader(body.Encode()))
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, "Creating request failed")
			return
		}

		upstreamReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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

		keyset, err := jwksRefreshers[oidcProvider.ID].Fetch(ctx, oidcConfigs[oidcProvider.ID].JwksUri)
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

		providerToken, ok := providerOauth2Token.(openid.Token)
		if !ok {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, "Not a valid OpenId Connect token")
			return
		}

		var userId string
		loggedIn := false

		loginKeyCookie, err := r.Cookie("login_key")
		if err == nil {
			loginData, err := storage.GetLoginData(loginKeyCookie.Value)
			if err == nil {
				userId = loginData.OwnerId
				loggedIn = true
			}
		}

		// Login cookie didn't point to a user. See if the provider identity we just received
		// is associated with an existing user
		if !loggedIn {
			allIdentities := storage.GetAllIdentities()
			for _, ident := range allIdentities {
				if ident.ProviderId == providerToken.Subject() {
					userId = ident.OwnerId
					loggedIn = true
					break
				}
			}
		}

		// Since no identities exist for the user, create a new user
		if !loggedIn {
			userId, err = storage.AddUser()
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}
		}

		loginKey, err := storage.AddLoginData(userId)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		cookie := &http.Cookie{
			Name:     "login_key",
			Value:    loginKey,
			Secure:   true,
			HttpOnly: true,
			MaxAge:   86400 * 365,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			//SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, cookie)

		storage.AddIdentity(userId, providerToken.Subject(), oidcProvider.Name, providerToken.Email())

		redirUrl := fmt.Sprintf("%s/auth?%s", rootUri, request.RawQuery)

		http.Redirect(w, r, redirUrl, 302)
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

		responseType := r.Form.Get("response_type")
		if responseType == "" {
			errUrl := fmt.Sprintf("%s?error=unsupported_response_type&state=%s",
				redirectUri, state)
			http.Redirect(w, r, errUrl, 302)
			return
		}

		userId := ""
		loginKeyCookie, err := r.Cookie("login_key")
		if err == nil {
			loginData, err := storage.GetLoginData(loginKeyCookie.Value)
			if err == nil {
				userId = loginData.OwnerId
			}
		}

		req := OAuth2AuthRequest{
			OwnerId:     userId,
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

		identities := storage.GetIdentitiesByUser(userId)

		data := struct {
			ClientId      string
			RequestId     string
			Identities    []*Identity
			OIDCProviders []*OIDCProvider
			URL           string
		}{
			ClientId:      clientIdUrl.Host,
			RequestId:     requestId,
			Identities:    identities,
			OIDCProviders: storage.GetOIDCProviders(),
			URL:           fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery),
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

		loginData, err := storage.GetLoginData(loginKeyCookie.Value)
		if err != nil {
			w.WriteHeader(403)
			io.WriteString(w, "Forbidden")
			return
		}

		userId := loginData.OwnerId

		requestId := r.Form.Get("request_id")

		request, err := storage.GetRequest(requestId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		if request.OwnerId != userId {
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

		if identity.OwnerId != userId {
			w.WriteHeader(403)
			io.WriteString(w, "User doesn't own identity")
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
			OwnerId: userId,
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
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		err = storage.SetToken(token.AccessToken, token.IdToken.Subject())
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		key, exists := config.Jwks.Get(0)
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

	mux.HandleFunc("/login-oidc", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		requestId := r.Form.Get("request_id")

		oidcProviderId := r.Form.Get("oidc_provider_id")

		provider, err := storage.GetOIDCProviderByID(oidcProviderId)
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

		storage.SetRequest(requestId, request)

		url := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&state=%s&scope=openid email&response_type=code", oidcConfigs[provider.ID].AuthorizationEndpoint, provider.ClientID, callbackUri, requestId)

		http.Redirect(w, r, url, 302)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}

		r.ParseForm()

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

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: mux,
	}

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

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}

func genRandomKey() (string, error) {
	const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	id := ""
	for i := 0; i < 32; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}

func GenerateJwks() (jwk.Set, error) {
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

	key.Set(jwk.KeyUsageKey, "sig")

	keyset := jwk.NewSet()

	keyset.Add(key)

	return keyset, nil
}
