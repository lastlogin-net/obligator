package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/big"
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
	RootUri   string    `json:"root_uri"`
	Providers Providers `json:"providers"`
	Jwks      jwk.Set   `json:"jwks"`
}

type Providers struct {
	Google *GoogleProvider `json:"google"`
}

type GoogleProvider struct {
	Uri          string `json:"uri"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type OIDCDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksUri               string `json:"jwks_uri"`
}

type OAuth2AuthRequest struct {
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

//go:embed templates
var fs embed.FS

func main() {

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

	if config.Providers.Google == nil {
		fmt.Fprintln(os.Stderr, "Google provider is required")
		os.Exit(1)
	}

	googClientId := config.Providers.Google.ClientId
	googClientSecret := config.Providers.Google.ClientSecret
	googConfig, err := GetOidcConfiguration(config.Providers.Google.Uri)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	ctx := context.Background()
	googJwksRefresher := jwk.NewAutoRefresh(ctx)
	googJwksRefresher.Configure(googConfig.JwksUri)

	_, err = googJwksRefresher.Refresh(ctx, googConfig.JwksUri)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	storage := NewFileStorage()

	tmpl, err := template.ParseFS(fs, "templates/*.tmpl")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	httpClient := &http.Client{}

	http.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := OIDCDiscoveryDoc{
			Issuer:                rootUri,
			AuthorizationEndpoint: fmt.Sprintf("%s/auth", rootUri),
			TokenEndpoint:         fmt.Sprintf("%s/token", rootUri),
			UserinfoEndpoint:      fmt.Sprintf("%s/userinfo", rootUri),
			JwksUri:               fmt.Sprintf("%s/jwks", rootUri),
		}

		json.NewEncoder(w).Encode(doc)
	})

	http.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(publicJwks)
	})

	http.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		requestId := r.Form.Get("state")
		request, err := storage.GetRequest(requestId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		switch request.Provider {
		case "google":

			googCode := r.Form.Get("code")

			body := url.Values{}
			body.Set("code", googCode)
			body.Set("client_id", googClientId)
			body.Set("client_secret", googClientSecret)
			body.Set("redirect_uri", callbackUri)
			body.Set("grant_type", "authorization_code")

			r, err := http.NewRequest(http.MethodPost, googConfig.TokenEndpoint, strings.NewReader(body.Encode()))
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, "Creating request failed")
				return
			}

			r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			resp, err := httpClient.Do(r)
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

			keyset, err := googJwksRefresher.Fetch(ctx, googConfig.JwksUri)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			googOauth2Token, err := jwt.Parse([]byte(tokenRes.IdToken), jwt.WithKeySet(keyset), jwt.WithToken(openid.New()))
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			googToken, ok := googOauth2Token.(openid.Token)

			if !ok {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			userId, err := genRandomKey()
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			issuedAt := time.Now().UTC()
			expiresAt := issuedAt.Add(10 * time.Minute)

			token, err := openid.NewBuilder().
				Subject(userId).
				Audience([]string{request.ClientId}).
				Issuer(rootUri).
				Email(googToken.Email()).
				EmailVerified(googToken.EmailVerified()).
				IssuedAt(issuedAt).
				Expiration(expiresAt).
				Claim("nonce", request.Nonce).
				Build()
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			key, exists := config.Jwks.Get(0)
			if !exists {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, "No keys available")
				return
			}

			signed, err := jwt.Sign(token, jwa.RS256, key)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			code, err := storage.AddPendingToken(string(signed))
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

		default:
			w.WriteHeader(500)
			io.WriteString(w, "Invalid provider")
			return
		}
	})

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {

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

		printJson(clientIdUrl)

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

		req := OAuth2AuthRequest{
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
			ClientId  string
			RequestId string
		}{
			ClientId:  clientIdUrl.Host,
			RequestId: requestId,
		}

		err = tmpl.ExecuteTemplate(w, "login.tmpl", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		code := r.Form.Get("code")

		idToken, err := storage.GetPendingToken(code)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")

		tokenRes := Oauth2TokenResponse{
			AccessToken: "inert-token",
			ExpiresIn:   3600,
			IdToken:     idToken,
			TokenType:   "bearer",
		}

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(tokenRes)
	})

	http.HandleFunc("/google", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		requestId := r.Form.Get("request_id")

		request, err := storage.GetRequest(requestId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		request.Provider = "google"

		storage.SetRequest(requestId, request)

		googUrl := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&state=%s&scope=openid email&response_type=code", googConfig.AuthorizationEndpoint, googClientId, callbackUri, requestId)

		http.Redirect(w, r, googUrl, 302)
	})

	err = http.ListenAndServe(":9002", nil)
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
