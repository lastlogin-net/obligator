package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

type OIDCHandler struct {
	mux *http.ServeMux
}

func NewOIDCHandler(storage Storage, tmpl *template.Template) *OIDCHandler {
	mux := http.NewServeMux()

	mux.Handle("/", http.FileServer(http.Dir("static")))

	h := &OIDCHandler{
		mux: mux,
	}

	publicJwks, err := jwk.PublicSetOf(storage.GetJWKSet())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// draft-ietf-oauth-security-topics-24 2.6
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
			// draft-ietf-oauth-security-topics-24 2.1.1
			CodeChallengeMethodsSupported: []string{"S256"},
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

		accessToken := parts[1]

		parsed, err := jwt.Parse([]byte(accessToken), jwt.WithKeySet(publicJwks))
		if err != nil {
			w.WriteHeader(401)
			io.WriteString(w, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		userResponse := UserinfoResponse{
			Sub:   parsed.Subject(),
			Email: parsed.Subject(),
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

		// draft-ietf-oauth-security-topics-24 4.1
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
		logins := make(map[string][]*Login)

		var hashedLoginKey string

		loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
		if err == nil && loginKeyCookie.Value != "" {
			hashedLoginKey = Hash(loginKeyCookie.Value)

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

				tokLoginsInterface, exists := parsed.Get("logins")
				if exists {
					if tokLogins, ok := tokLoginsInterface.(map[string][]*Login); ok {
						logins = tokLogins
					}
				}
			}

		}

		previousLogins, ok := logins[clientId]
		if !ok {
			previousLogins = []*Login{}
		}

		sort.Slice(previousLogins, func(i, j int) bool {
			return previousLogins[i].Timestamp > previousLogins[j].Timestamp
		})

		remainingIdents := []*Identity{}
		for _, ident := range identities {
			found := false
			for _, login := range previousLogins {
				if login.Id == ident.Id && login.ProviderName == ident.ProviderName {
					found = true
					break
				}
			}
			if !found {
				remainingIdents = append(remainingIdents, ident)
			}
		}

		issuedAt := time.Now().UTC()
		authRequestJwt, err := jwt.NewBuilder().
			IssuedAt(issuedAt).
			Expiration(issuedAt.Add(8*time.Minute)).
			Claim("login_key_hash", hashedLoginKey).
			Claim("raw_query", r.URL.RawQuery).
			Claim("client_id", clientId).
			Claim("redirect_uri", redirectUri).
			Claim("state", state).
			Claim("scope", r.Form.Get("scope")).
			Claim("nonce", r.Form.Get("nonce")).
			Claim("pkce_code_challenge", r.Form.Get("code_challenge")).
			Build()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		setJwtCookie(storage, authRequestJwt, "obligator_auth_request", w, r)

		providers, err := storage.GetOAuth2Providers()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		data := struct {
			RootUri         string
			DisplayName     string
			ClientId        string
			Identities      []*Identity
			PreviousLogins  []*Login
			OAuth2Providers []OAuth2Provider
			LogoMap         map[string]template.HTML
			URL             string
		}{
			RootUri:         storage.GetRootUri(),
			DisplayName:     storage.GetDisplayName(),
			ClientId:        clientIdUrl.Host,
			Identities:      remainingIdents,
			PreviousLogins:  previousLogins,
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

		parsedLoginKey, err := jwt.Parse([]byte(loginKeyCookie.Value), jwt.WithKeySet(publicJwks))
		if err != nil {
			w.WriteHeader(401)
			io.WriteString(w, err.Error())
			return
		}

		// delete auth request cookie
		cookieDomain, err := buildCookieDomain(storage.GetRootUri())
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
		cookie := &http.Cookie{
			Domain:   cookieDomain,
			Name:     "obligator_auth_request",
			Value:    "",
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)

		parsedAuthReq, err := getJwtFromCookie("obligator_auth_request", storage, w, r)
		if err != nil {
			w.WriteHeader(401)
			io.WriteString(w, err.Error())
			return
		}

		identId := r.Form.Get("identity_id")

		var identity *Identity
		tokIdentsInterface, exists := parsedLoginKey.Get("identities")
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

		clientId := claimFromToken("client_id", parsedAuthReq)

		newLoginCookie, err := addLoginToCookie(storage, clientId, "email", identity.Id, identity.ProviderName, loginKeyCookie.Value)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}
		http.SetCookie(w, newLoginCookie)

		issuedAt := time.Now().UTC()
		expiresAt := issuedAt.Add(8 * time.Minute)

		idToken, err := openid.NewBuilder().
			Subject(identId).
			Audience([]string{clientId}).
			Issuer(storage.GetRootUri()).
                        // TODO: eventually we'll want to support non-email identities
			Email(identity.Id).
			EmailVerified(true).
			IssuedAt(issuedAt).
			Expiration(expiresAt).
			Claim("nonce", claimFromToken("nonce", parsedAuthReq)).
			Build()
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		key, exists := storage.GetJWKSet().Key(0)
		if !exists {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, "No keys available")
			return
		}

		signedIdToken, err := jwt.Sign(idToken, jwt.WithKey(jwa.RS256, key))
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		codeJwt, err := jwt.NewBuilder().
			IssuedAt(issuedAt).
			Expiration(issuedAt.Add(16*time.Second)).
			Subject(idToken.Email()).
			Claim("id_token", string(signedIdToken)).
			Claim("pkce_code_challenge", claimFromToken("pkce_code_challenge", parsedAuthReq)).
			Build()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		signedCode, err := jwt.Sign(codeJwt, jwt.WithKey(jwa.RS256, key))
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		url := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&code=%s&state=%s&scope=%s",
			claimFromToken("redirect_uri", parsedAuthReq),
			claimFromToken("client_id", parsedAuthReq),
			claimFromToken("redirect_uri", parsedAuthReq),
			string(signedCode),
			claimFromToken("state", parsedAuthReq),
			claimFromToken("scope", parsedAuthReq))

		http.Redirect(w, r, url, http.StatusSeeOther)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		codeJwt := r.Form.Get("code")

		parsedCodeJwt, err := jwt.Parse([]byte(codeJwt), jwt.WithKeySet(publicJwks))
		if err != nil {
			fmt.Println(err.Error())
			w.WriteHeader(401)
			io.WriteString(w, err.Error())
			return
		}

		signedIdTokenIface, exists := parsedCodeJwt.Get("id_token")
		if !exists {
			w.WriteHeader(401)
			io.WriteString(w, "Invalid id_token in code")
			return
		}

		signedIdToken, ok := signedIdTokenIface.(string)
		if !ok {
			w.WriteHeader(401)
			io.WriteString(w, "Invalid id_token in code")
			return
		}

		pkceCodeChallenge, exists := parsedCodeJwt.Get("pkce_code_challenge")
		if !exists {
			w.WriteHeader(401)
			io.WriteString(w, "Invalid pkce_code_challenge in code")
			return
		}

		// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.8.2
		// draft-ietf-oauth-security-topics-24 2.1.1
		pkceCodeVerifier := r.Form.Get("code_verifier")
		if pkceCodeChallenge != "" {
			challenge := GeneratePKCECodeChallenge(pkceCodeVerifier)
			if challenge != pkceCodeChallenge {
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

		issuedAt := time.Now().UTC()
		accessTokenJwt, err := jwt.NewBuilder().
			IssuedAt(issuedAt).
			Expiration(issuedAt.Add(16 * time.Second)).
			Subject(parsedCodeJwt.Subject()).
			Build()
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		signedAccessToken, err := jwt.Sign(accessTokenJwt, jwt.WithKey(jwa.RS256, key))
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")

		tokenRes := OIDCTokenResponse{
			AccessToken: string(signedAccessToken),
			ExpiresIn:   3600,
			IdToken:     string(signedIdToken),
			TokenType:   "bearer",
		}

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(tokenRes)
	})

	return h
}

func (h *OIDCHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}
