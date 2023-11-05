package main

import (
	"crypto/rand"
	"crypto/rsa"
	"embed"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type SmtpConfig struct {
	Server     string `json:"server,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Port       int    `json:"port,omitempty"`
	Sender     string `json:"sender,omitempty"`
	SenderName string `json:"sender_name,omitempty"`
}

type OIDCTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IdToken     string `json:"id_token"`
}

type ObligatorMux struct {
	behindProxy bool
	mux         *http.ServeMux
}

type UserinfoResponse struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
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

	remoteIp, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	if s.behindProxy {
		xffHeader := r.Header.Get("X-Forwarded-For")
		if xffHeader != "" {
			parts := strings.Split(xffHeader, ",")
			remoteIp = parts[0]
		}
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
	dbDir := flag.String("database-dir", "./", "Database directory")
	apiSocketDir := flag.String("api-socket-dir", "./", "API socket directory")
	behindProxy := flag.Bool("behind-proxy", false, "Whether we are behind a reverse proxy")
	displayName := flag.String("display-name", "obligator", "Display name")
	flag.Parse()

	var identsType []*Identity
	jwt.RegisterCustomField("identities", identsType)
	var loginsType map[string][]*Login
	jwt.RegisterCustomField("logins", loginsType)
	var idTokenType string
	jwt.RegisterCustomField("id_token", idTokenType)

	storagePath := filepath.Join(*storageDir, "obligator_storage.json")
	storage, err := NewJsonStorage(storagePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	//sqliteStorage, err := NewSqliteStorage("obligator_storage.sqlite")
	//if err != nil {
	//	fmt.Fprintln(os.Stderr, err.Error())
	//	os.Exit(1)
	//}

	dbPath := filepath.Join(*dbDir, "obligator_db.sqlite")
	db, err := NewDatabase(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cluster := NewCluster()

	flyIoId := os.Getenv("FLY_ALLOC_ID")
	if flyIoId != "" {
		storage.SetInstanceId(flyIoId)
	}

	instanceId := storage.GetInstanceId()

	if instanceId == "" {
		var err error
		instanceId, err = genRandomKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		storage.SetInstanceId(instanceId)
	}

	if *displayName != "obligator" {
		storage.SetDisplayName(*displayName)
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

	mux := NewObligatorMux(*behindProxy)

	oidcHandler := NewOIDCHandler(storage, tmpl)
	mux.Handle("/", oidcHandler)

	addIdentityOauth2Handler := NewAddIdentityOauth2Handler(storage)
	mux.Handle("/login-oauth2", addIdentityOauth2Handler)
	mux.Handle("/callback", addIdentityOauth2Handler)

	addIdentityEmailHandler := NewAddIdentityEmailHandler(storage, db, cluster)
	mux.Handle("/login-email", addIdentityEmailHandler)
	mux.Handle("/email-code", addIdentityEmailHandler)
	mux.Handle("/complete-email-login", addIdentityEmailHandler)

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
