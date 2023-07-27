package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

type Oauth2Handler struct {
	mux *http.ServeMux
}

var oidcConfigs map[string]*OAuth2ServerMetadata
var jwksRefreshers map[string]*jwk.Cache
var providerLogoMap map[string]template.HTML

// TODO: This is not thread-safe
func updateOidcConfigs(storage Storage, jsonStorage *JsonStorage) {
	oidcConfigs = make(map[string]*OAuth2ServerMetadata)
	jwksRefreshers = make(map[string]*jwk.Cache)
	providerLogoMap = make(map[string]template.HTML)

	ctx := context.Background()

	providers, err := storage.GetOAuth2Providers()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	for _, oidcProvider := range providers {
		if !oidcProvider.OpenIDConnect {
			continue
		}
		var err error
		oidcConfigs[oidcProvider.ID], err = GetOidcConfiguration(oidcProvider.URI)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		jwksRefreshers[oidcProvider.ID] = jwk.NewCache(ctx)
		jwksRefreshers[oidcProvider.ID].Register(oidcConfigs[oidcProvider.ID].JwksUri)

		_, err = jwksRefreshers[oidcProvider.ID].Refresh(ctx, oidcConfigs[oidcProvider.ID].JwksUri)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		logoPath := fmt.Sprintf("assets/logo_%s.svg", oidcProvider.ID)
		logoBytes, err := fs.ReadFile(logoPath)
		if err != nil {
			logoBytes, err = fs.ReadFile("assets/logo_generic_openid.svg")
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
		}

		providerLogoMap[oidcProvider.ID] = template.HTML(logoBytes)
	}
}

func NewOauth2Handler(storage Storage, jsonStorage *JsonStorage) *Oauth2Handler {
	mux := http.NewServeMux()

	h := &Oauth2Handler{
		mux: mux,
	}

	httpClient := &http.Client{}

	ctx := context.Background()

	go updateOidcConfigs(storage, jsonStorage)

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

		request, err := jsonStorage.GetRequest(requestId)
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

		jsonStorage.SetRequest(requestId, request)

		callbackUri := fmt.Sprintf("%s/callback", storage.GetRootUri())

		url := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&state=%s&scope=%s&response_type=code&code_challenge_method=S256&code_challenge=%s&nonce=%s&prompt=consent",
			authURL, provider.ClientID, callbackUri, requestId,
			scope, pkceCodeChallenge, request.ProviderNonce)

		http.Redirect(w, r, url, http.StatusSeeOther)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		requestId := r.Form.Get("state")
		request, err := jsonStorage.GetRequest(requestId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		jsonStorage.DeleteRequest(requestId)

		oauth2Provider, err := storage.GetOAuth2ProviderByID(request.Provider)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		providerCode := r.Form.Get("code")

		rootUri := storage.GetRootUri()
		callbackUri := fmt.Sprintf("%s/callback", rootUri)

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
			keyset, err := jwksRefreshers[oauth2Provider.ID].Get(ctx, oidcConfigs[oauth2Provider.ID].JwksUri)
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
			providerIdentityId, email, _ = GetProfile(&oauth2Provider, tokenRes.AccessToken)
		}

		users, err := storage.GetUsers()
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		if !jsonStorage.GetPublic() && !validUser(email, users) {
			redirUrl := fmt.Sprintf("%s/no-account?%s", rootUri, request.RawQuery)
			http.Redirect(w, r, redirUrl, http.StatusSeeOther)
			return
		}

		loggedIn := false

		var loginKey string

		loginKeyCookie, err := r.Cookie("login_key")
		if err == nil {
			loginKey = Hash(loginKeyCookie.Value)
			_, err := jsonStorage.GetLoginData(loginKey)
			if err == nil {
				loggedIn = true
			}
		}

		// Since no identities exist for the user, create a new user
		if !loggedIn {
			unhashedLoginKey, err := jsonStorage.AddLoginData()
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			cookieDomain, err := buildCookieDomain(rootUri)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}

			cookie := &http.Cookie{
				Domain:   cookieDomain,
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

		identId, err := jsonStorage.EnsureIdentity(providerIdentityId, oauth2Provider.Name, email)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		jsonStorage.EnsureLoginMapping(identId, loginKey)

		redirUrl := fmt.Sprintf("%s/auth?%s", storage.GetRootUri(), request.RawQuery)

		http.Redirect(w, r, redirUrl, http.StatusSeeOther)
	})

	return h
}

func (h *Oauth2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// Modified from https://chrisguitarguy.com/2022/12/07/oauth-pkce-with-go/
func GeneratePKCECodeVerifier() (string, error) {
	const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~"
	verifier := ""
	for i := 0; i < 64; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		verifier += string(chars[randIndex.Int64()])
	}

	return verifier, nil
}

func GeneratePKCECodeChallenge(verifier string) string {
	sha2 := sha256.New()
	io.WriteString(sha2, verifier)
	return base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))
}

func GeneratePKCEData() (string, string, error) {

	verifier, err := GeneratePKCECodeVerifier()
	if err != nil {
		return "", "", err
	}

	challenge := GeneratePKCECodeChallenge(verifier)

	return challenge, verifier, nil
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

func GetOidcConfiguration(baseUrl string) (*OAuth2ServerMetadata, error) {

	url := fmt.Sprintf("%s/.well-known/openid-configuration", baseUrl)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New("Invalid HTTP response")
	}

	var doc OAuth2ServerMetadata

	err = json.NewDecoder(resp.Body).Decode(&doc)
	if err != nil {
		return nil, err
	}

	return &doc, nil
}
