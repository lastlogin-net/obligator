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
	"path/filepath"
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
	Issuer                string `json:"issuer,omitempty"`
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	//UserinfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
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

	port := flag.Int("port", 1616, "Port")
	rootUri := flag.String("root-uri", "", "Root URI")
	loginKeyName := flag.String("login-key-name", "obligator_login_key", "Login key name")
	storageDir := flag.String("storage-dir", "./", "Storage directory")
	apiSocketDir := flag.String("api-socket-dir", "./", "API socket directory")
	flag.Parse()

	flyIoId := os.Getenv("FLY_ALLOC_ID")
	instanceId := flyIoId
	if instanceId == "" {
		var err error
		instanceId, err = genRandomKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}

	var identsType []*Identity
	jwt.RegisterCustomField("identities", identsType)

	//storage, err := NewSqliteStorage("obligator_storage.sqlite3")
	//if err != nil {
	//	fmt.Fprintln(os.Stderr, err.Error())
	//	os.Exit(1)
	//}

	storagePath := filepath.Join(*storageDir, "obligator_storage.json")
	storage, err := NewJsonStorage(storagePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if *rootUri != "" {
		storage.SetRootUri(*rootUri)
	}

	if *loginKeyName != "obligator_login_key" || storage.GetLoginKeyName() == "" {
		storage.SetLoginKeyName(*loginKeyName)
	}

	if storage.GetRootUri() == "" {
		fmt.Fprintln(os.Stderr, "WARNING: No root URI set")
	}

	_, err = NewApi(storage, *apiSocketDir)
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

	publicJwks, err := jwk.PublicSetOf(storage.GetJWKSet())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	tmpl, err := template.ParseFS(fs, "templates/*.tmpl")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	oauth2Handler := NewOauth2Handler(storage)
	mux := NewObligatorMux()

	mux.Handle("/login-oauth2", oauth2Handler)
	mux.Handle("/callback", oauth2Handler)

	emailHandler := NewEmailHander(storage)
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

		loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
		if err != nil {
			http.Redirect(w, r, url, 307)
			return
		}

		// TODO: add Remote-Email to header
		_, err = jwt.Parse([]byte(loginKeyCookie.Value), jwt.WithKeySet(publicJwks))
		if err != nil {
			http.Redirect(w, r, url, 307)
			return
		}
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		rootUri := storage.GetRootUri()

		doc := OAuth2ServerMetadata{
			Issuer:                rootUri,
			AuthorizationEndpoint: fmt.Sprintf("%s/auth", rootUri),
			TokenEndpoint:         fmt.Sprintf("%s/token", rootUri),
			//UserinfoEndpoint:                 fmt.Sprintf("%s/userinfo", rootUri),
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

		loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
		if err == nil && loginKeyCookie.Value != "" {
			loginKey = Hash(loginKeyCookie.Value)

			parsed, err := jwt.Parse([]byte(loginKeyCookie.Value), jwt.WithKeySet(publicJwks))
			if err != nil {
				// Only add identities from current cookie if it's valid
			} else {
				tokIdentsInterface, exists := parsed.Get("identities")
				if exists {
					if tokIdents, ok := tokIdentsInterface.([]*Identity); ok {
						identities = tokIdents
					}
				}
			}

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

		requestId, err := storage.AddRequest(req)
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

		loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
		if err != nil {
			w.WriteHeader(401)
			io.WriteString(w, "Only logged-in users can access this endpoint")
			return
		}

		parsed, err := jwt.Parse([]byte(loginKeyCookie.Value), jwt.WithKeySet(publicJwks))
		if err != nil {
			w.WriteHeader(401)
			io.WriteString(w, err.Error())
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

		var identity *Identity
		tokIdentsInterface, exists := parsed.Get("identities")
		if exists {
			if tokIdents, ok := tokIdentsInterface.([]*Identity); ok {
				for _, ident := range tokIdents {
					if ident.Id == identId {
						identity = ident
						break
					}
				}
			}
		}

		if identity == nil {
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
			instanceId+"-"+code,
			request.State,
			request.Scope)

		http.Redirect(w, r, url, http.StatusSeeOther)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		codeParam := r.Form.Get("code")

		codeParts := strings.Split(codeParam, "-")
		if len(codeParts) != 2 {
			w.WriteHeader(400)
			io.WriteString(w, "Invalid code")
			return
		}

		reqInstanceId := codeParts[0]
		if reqInstanceId != instanceId {
			// If we're running on fly.io, we can have fly replay the request to the correct instance
			if flyIoId != "" {
				w.Header().Set("fly-replay", fmt.Sprintf("instance=%s", reqInstanceId))
				return
			} else {
				w.WriteHeader(400)
				io.WriteString(w, "Invalid code")
				return
			}
		}

		code := codeParts[1]
		defer storage.DeletePendingToken(code)

		token, err := storage.GetPendingToken(code)
		if err != nil {
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

		key, exists := storage.GetJWKSet().Key(0)
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

		redirect := r.Form.Get("prev_page")

		err = deleteLoginKeyCookie(storage, w)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
		}

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
