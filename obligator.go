package obligator

import (
	"crypto/rand"
	"crypto/rsa"
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/ip2location/ip2location-go/v9"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Server struct {
	api     *Api
	Config  ServerConfig
	Mux     *ObligatorMux
	storage Storage
}

type ServerConfig struct {
	Port         int
	RootUri      string
	AuthDomains  []string
	Prefix       string
	StorageDir   string
	DatabaseDir  string
	ApiSocketDir string
	BehindProxy  bool
	DisplayName  string
	GeoDbPath    string
}

type SmtpConfig struct {
	Server     string `json:"server,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Port       int    `json:"port,omitempty"`
	Sender     string `json:"sender,omitempty"`
	SenderName string `json:"sender_name,omitempty"`
}

type OAuth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IdToken     string `json:"id_token,omitempty"`
}

type ObligatorMux struct {
	behindProxy bool
	mux         *http.ServeMux
}

type UserinfoResponse struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

type Validation struct {
	Id     string `json:"id"`
	IdType string `json:"id_type"`
}

const RateLimitTime = 24 * time.Hour

// const RateLimitTime = 10 * time.Minute
const EmailValidationsPerTimeLimit = 12

func NewObligatorMux(behindProxy bool) *ObligatorMux {
	s := &ObligatorMux{
		behindProxy: behindProxy,
		mux:         http.NewServeMux(),
	}

	return s
}

func (s *ObligatorMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; script-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")

	timestamp := time.Now().Format(time.RFC3339)

	remoteIp, err := getRemoteIp(r, s.behindProxy)
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

func NewServer(conf ServerConfig) *Server {

	if conf.Port == 0 {
		conf.Port = 1616
	}

	if conf.Prefix == "" {
		conf.Prefix = "obligator"
	}

	if conf.DisplayName == "" {
		conf.DisplayName = "obligator"
	}

	var identsType []*Identity
	jwt.RegisterCustomField("identities", identsType)
	var loginsType map[string][]*Login
	jwt.RegisterCustomField("logins", loginsType)
	var idTokenType string
	jwt.RegisterCustomField("id_token", idTokenType)

	storagePath := filepath.Join(conf.StorageDir, conf.Prefix+"storage.json")
	storage, err := NewJsonStorage(storagePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if conf.Prefix != "obligator" || storage.GetPrefix() == "" {
		storage.SetPrefix(conf.Prefix)
	}

	prefix := storage.GetPrefix()
	loginKeyName := prefix + "login_key"

	//sqliteStorage, err := NewSqliteStorage(prefix + "storage.sqlite")
	//if err != nil {
	//	fmt.Fprintln(os.Stderr, err.Error())
	//	os.Exit(1)
	//}

	dbPath := filepath.Join(conf.DatabaseDir, prefix+"db.sqlite")
	db, err := NewDatabase(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cluster := NewCluster()

	if conf.DisplayName != "obligator" {
		storage.SetDisplayName(conf.DisplayName)
	}

	if conf.RootUri != "" {
		storage.SetRootUri(conf.RootUri)
	}

	rootUrl, err := url.Parse(conf.RootUri)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	conf.AuthDomains = append(conf.AuthDomains, rootUrl.Host)

	if storage.GetRootUri() == "" {
		fmt.Fprintln(os.Stderr, "WARNING: No root URI set")
	}

	oauth2MetaMan := NewOAuth2MetadataManager(storage)
	err = oauth2MetaMan.Update()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	api, err := NewApi(storage, conf.ApiSocketDir, oauth2MetaMan)
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

	tmpl, err := template.ParseFS(fs, "templates/*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	mux := NewObligatorMux(conf.BehindProxy)

	var geoDb *ip2location.DB
	if conf.GeoDbPath != "" {
		geoDb, err = ip2location.OpenDB(conf.GeoDbPath)
		if err != nil {
			fmt.Println(err.Error())
			return nil
		}
	}

	oidcHandler := NewOIDCHandler(storage, tmpl)
	mux.Handle("/", oidcHandler)

	addIdentityOauth2Handler := NewAddIdentityOauth2Handler(storage, oauth2MetaMan)
	mux.Handle("/login-oauth2", addIdentityOauth2Handler)
	mux.Handle("/callback", addIdentityOauth2Handler)

	addIdentityEmailHandler := NewAddIdentityEmailHandler(storage, db, cluster, tmpl, conf.BehindProxy, geoDb)
	mux.Handle("/login-email", addIdentityEmailHandler)
	mux.Handle("/email-sent", addIdentityEmailHandler)
	mux.Handle("/magic", addIdentityEmailHandler)
	mux.Handle("/confirm-magic", addIdentityEmailHandler)
	mux.Handle("/complete-email-login", addIdentityEmailHandler)

	addIdentityGamlHandler := NewAddIdentityGamlHandler(storage, cluster, tmpl)
	mux.Handle("/login-gaml", addIdentityGamlHandler)
	mux.Handle("/gaml-code", addIdentityGamlHandler)
	mux.Handle("/complete-gaml-login", addIdentityGamlHandler)

	qrHandler := NewQrHandler(storage, cluster, tmpl)
	mux.Handle("/login-qr", qrHandler)
	mux.Handle("/qr", qrHandler)
	mux.Handle("/send", qrHandler)
	mux.Handle("/receive", qrHandler)

	mux.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
		remoteIp, err := getRemoteIp(r, conf.BehindProxy)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		data := struct {
			RootUri     string
			DisplayName string
			RemoteIp    string
		}{
			RootUri:     storage.GetRootUri(),
			DisplayName: storage.GetDisplayName(),
			RemoteIp:    remoteIp,
		}

		err = tmpl.ExecuteTemplate(w, "ip.html", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		redirectUri := r.Form.Get("redirect_uri")
		url := fmt.Sprintf("%s/auth?client_id=%s&redirect_uri=%s&response_type=code&state=&scope=",
			storage.GetRootUri(), redirectUri, redirectUri)

		loginKeyCookie, err := r.Cookie(loginKeyName)
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
			URL         string
			RootUri     string
			DisplayName string
		}{
			URL:         fmt.Sprintf("/auth?%s", r.URL.RawQuery),
			RootUri:     storage.GetRootUri(),
			DisplayName: storage.GetDisplayName(),
		}

		err = tmpl.ExecuteTemplate(w, "no-account.html", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		printJson(r.Header)
	})

	s := &Server{
		Config:  conf,
		Mux:     mux,
		api:     api,
		storage: storage,
	}

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Mux.ServeHTTP(w, r)
}

func (s *Server) Start() error {
	server := http.Server{
		Addr:    fmt.Sprintf(":%d", s.Config.Port),
		Handler: s.Mux,
	}

	fmt.Println("Running")

	err := server.ListenAndServe()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		return err
	}

	return nil
}

func (s *Server) AuthUri(authReq *OAuth2AuthRequest) string {
	return AuthUri(s.Config.RootUri+"/auth", authReq)
}

func AuthUri(serverUri string, authReq *OAuth2AuthRequest) string {
	uri := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=%s&state=%s&scope=%s",
		serverUri, authReq.ClientId, authReq.RedirectUri,
		authReq.ResponseType, authReq.State, authReq.Scope)
	return uri
}

func (s *Server) AuthDomains() []string {
	return s.Config.AuthDomains
}

func (s *Server) SetOAuth2Provider(prov OAuth2Provider) error {
	return s.api.SetOAuth2Provider(prov)
}

func (s *Server) AddUser(user User) error {
	return s.api.AddUser(user)
}

func (s *Server) GetUsers() ([]User, error) {
	return s.api.GetUsers()
}

func (s *Server) Validate(r *http.Request) (*Validation, error) {
	r.ParseForm()

	loginKeyName := s.storage.GetPrefix() + "login_key"

	loginKeyCookie, err := r.Cookie(loginKeyName)
	if err != nil {
		return nil, err
	}

	// TODO: don't generate publicJwks every time
	publicJwks, err := jwk.PublicSetOf(s.storage.GetJWKSet())
	if err != nil {
		return nil, err
	}

	// TODO: add Remote-Email to header
	_, err = jwt.Parse([]byte(loginKeyCookie.Value), jwt.WithKeySet(publicJwks))
	if err != nil {
		return nil, err
	}

	v := &Validation{}

	return v, nil
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
