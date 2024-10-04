package obligator

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type OAuth2ServerMetadata struct {
	Issuer                            string   `json:"issuer,omitempty"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JwksUri                           string   `json:"jwks_uri,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
}

type OAuth2AuthRequest struct {
	ClientId      string `json:"client_id"`
	RedirectUri   string `json:"redirect_uri"`
	Scope         string `json:"scope"`
	State         string `json:"state"`
	ResponseType  string `json:"response_type"`
	CodeChallenge string `json:"code_challenge"`
}

type OIDCHandler struct {
	mux  *http.ServeMux
	db   Database
	tmpl *template.Template
}

type OIDCRegistrationResponse struct {
	ClientId string `json:"client_id"`
}

type OIDCRegistrationRequest struct {
	RedirectUris []string `json:"redirect_uris"`
}

func NewOIDCHandler(db Database, config ServerConfig, tmpl *template.Template, jose *JOSE) *OIDCHandler {
	mux := http.NewServeMux()

	h := &OIDCHandler{
		mux:  mux,
		db:   db,
		tmpl: tmpl,
	}

	prefix, err := db.GetPrefix()
	checkErr(err)

	// draft-ietf-oauth-security-topics-24 2.6
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		uri := fmt.Sprintf("https://%s", r.Host)

		doc := OAuth2ServerMetadata{
			Issuer:                           uri,
			AuthorizationEndpoint:            fmt.Sprintf("%s/auth", uri),
			TokenEndpoint:                    fmt.Sprintf("%s/token", uri),
			UserinfoEndpoint:                 fmt.Sprintf("%s/userinfo", uri),
			JwksUri:                          fmt.Sprintf("%s/jwks", uri),
			ScopesSupported:                  []string{"openid", "email", "profile"},
			ResponseTypesSupported:           []string{"code"},
			IdTokenSigningAlgValuesSupported: []string{"RS256"},
			// draft-ietf-oauth-security-topics-24 2.1.1
			CodeChallengeMethodsSupported: []string{"S256"},
			// https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
			SubjectTypesSupported:             []string{"public"},
			RegistrationEndpoint:              fmt.Sprintf("%s/register", uri),
			TokenEndpointAuthMethodsSupported: []string{"none"},
			EndSessionEndpoint:                fmt.Sprintf("%s/end-session", uri),
		}

		json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/end-session", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		redirUri := r.Form.Get("post_logout_redirect_uri")

		parsedRedirUri, err := url.Parse(redirUri)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		data := struct {
			*commonData
			RpDomain    string
			RedirectUri string
		}{
			commonData:  newCommonData(nil, db, r),
			RpDomain:    parsedRedirUri.Host,
			RedirectUri: redirUri,
		}

		err = tmpl.ExecuteTemplate(w, "logout.html", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		publicJwks, err := jose.GetPublicJwks()
		if err != nil {
			w.WriteHeader(500)
			return
		}

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(publicJwks)
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {

		var regReq OIDCRegistrationRequest

		err := json.NewDecoder(r.Body).Decode(&regReq)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		if len(regReq.RedirectUris) == 0 {
			w.WriteHeader(400)
			io.WriteString(w, "Need at least one redirect_uri")
			return
		}

		parsedClientIdUrl, err := url.Parse(regReq.RedirectUris[0])
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		clientId := fmt.Sprintf("https://%s", parsedClientIdUrl.Host)

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(201)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")

		resp := OIDCRegistrationResponse{
			ClientId: clientId,
		}

		enc.Encode(resp)
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

		parsed, err := jose.Parse(accessToken)
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

		ar, err := ParseAuthRequest(w, r)
		if err != nil {
			return
		}

		previousLogins := []*Login{}
		remainingIdents := []*Identity{}

		identities, _ := getIdentities(db, r)

		logins, err := getLogins(db, r)
		if err == nil {
			previousLogins = logins[ar.ClientId]

			sort.Slice(previousLogins, func(i, j int) bool {
				return previousLogins[i].Timestamp > previousLogins[j].Timestamp
			})
		}

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

		maxAge := 8 * time.Minute
		issuedAt := time.Now().UTC()
		authRequestJwt, err := NewJWTBuilder().
			IssuedAt(issuedAt).
			Expiration(issuedAt.Add(maxAge)).
			// TODO: should we be checking login_key_hash?
			//Claim("login_key_hash", hashedLoginKey).
			Claim("client_id", ar.ClientId).
			Claim("redirect_uri", ar.RedirectUri).
			Claim("state", ar.State).
			Claim("scope", r.Form.Get("scope")).
			Claim("nonce", r.Form.Get("nonce")).
			Claim("pkce_code_challenge", r.Form.Get("code_challenge")).
			Claim("response_type", ar.ResponseType).
			Build()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		setJwtCookie(db, r.Host, authRequestJwt, prefix+"auth_request", maxAge, w, r)

		providers, err := db.GetOAuth2Providers()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		canEmail := true
		if _, err := db.GetSmtpConfig(); err != nil {
			canEmail = false
		}

		parsedClientId, err := url.Parse(ar.ClientId)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		returnUri := fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery)

		providerId := r.Form.Get("provider")

		if providerId != "" {

			returnUri := "/approve"
			setReturnUriCookie(r.Host, db, returnUri, w)

			uri := fmt.Sprintf("/login-oauth2?oauth2_provider_id=%s", providerId)
			http.Redirect(w, r, uri, 303)
			return
		}

		data := struct {
			*commonData
			ClientId            string
			RemainingIdentities []*Identity
			PreviousLogins      []*Login
			OAuth2Providers     []*OAuth2Provider
			LogoMap             map[string]template.HTML
			URL                 string
			CanEmail            bool
			DisableQrLogin      bool
		}{
			commonData: newCommonData(&commonData{
				ReturnUri: returnUri,
			}, db, r),
			ClientId:            parsedClientId.Host,
			RemainingIdentities: remainingIdents,
			PreviousLogins:      previousLogins,
			OAuth2Providers:     providers,
			LogoMap:             providerLogoMap,
			CanEmail:            canEmail,
			DisableQrLogin:      config.DisableQrLogin,
		}

		setReturnUriCookie(r.Host, db, returnUri, w)

		err = tmpl.ExecuteTemplate(w, "auth.html", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/approve", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		parsedAuthReq, err := getJwtFromCookie(prefix+"auth_request", w, r, jose)
		if err != nil {
			w.WriteHeader(401)
			io.WriteString(w, err.Error())
			return
		}

		identId := r.Form.Get("identity_id")

		idents, _ := getIdentities(db, r)

		var identity *Identity
		for _, ident := range idents {
			if ident.Id == identId {
				identity = ident
				break
			}
		}

		if identity == nil {
			w.WriteHeader(403)
			io.WriteString(w, "You don't have permissions for this identity")
			return
		}

		emailWildcard, done := h.handleWildcardEmail(w, r, identity)
		if done {
			return
		}

		clientId := claimFromToken("client_id", parsedAuthReq)

		newLogin := &Login{
			IdType:       IdentityTypeEmail,
			Id:           identity.Id,
			ProviderName: identity.ProviderName,
		}

		uri := domainToUri(r.Host)

		newLoginCookie, err := addLoginToCookie(db, r, clientId, newLogin)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}
		http.SetCookie(w, newLoginCookie)

		scope := claimFromToken("scope", parsedAuthReq)
		scopeParts := strings.Split(scope, " ")
		emailRequested := false
		profileRequested := false
		for _, scopePart := range scopeParts {
			if scopePart == "email" {
				emailRequested = true
			}

			if scopePart == "profile" {
				profileRequested = true
			}
		}

		issuedAt := time.Now().UTC()
		expiresAt := issuedAt.Add(24 * time.Hour)

		expandedId := identity.Id

		if emailWildcard != "" {
			wildcardParts := strings.Split(identity.Id, "*")
			expandedId = wildcardParts[0] + emailWildcard + wildcardParts[1]
		}

		clearCookie(r.Host, prefix+"auth_request", w)

		idTokenBuilder := NewOIDCTokenBuilder().
			Subject(expandedId).
			Audience([]string{clientId}).
			Issuer(uri).
			IssuedAt(issuedAt).
			Expiration(expiresAt).
			Claim("nonce", claimFromToken("nonce", parsedAuthReq))

		if emailRequested {
			idTokenBuilder.Email(expandedId).
				EmailVerified(identity.EmailVerified)
		}

		if profileRequested && identity.Name != "" {
			idTokenBuilder.Name(identity.Name)
		}

		idToken, err := idTokenBuilder.Build()
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		signedIdToken, err := jose.Sign(idToken)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		// TODO: should maybe be encrypting this
		codeJwt, err := NewJWTBuilder().
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

		signedCode, err := jose.Sign(codeJwt)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		responseType := claimFromToken("response_type", parsedAuthReq)

		// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
		if responseType == "none" {
			redirectUri := claimFromToken("redirect_uri", parsedAuthReq)
			http.Redirect(w, r, redirectUri, http.StatusSeeOther)
		} else {
			url := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&code=%s&state=%s&scope=%s",
				claimFromToken("redirect_uri", parsedAuthReq),
				claimFromToken("client_id", parsedAuthReq),
				claimFromToken("redirect_uri", parsedAuthReq),
				string(signedCode),
				claimFromToken("state", parsedAuthReq),
				claimFromToken("scope", parsedAuthReq))

			http.Redirect(w, r, url, http.StatusSeeOther)
		}
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		codeJwt := r.Form.Get("code")

		parsedCodeJwt, err := jose.Parse(codeJwt)
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

		issuedAt := time.Now().UTC()
		accessTokenJwt, err := NewJWTBuilder().
			IssuedAt(issuedAt).
			Expiration(issuedAt.Add(16 * time.Second)).
			Subject(parsedCodeJwt.Subject()).
			Build()
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		signedAccessToken, err := jose.Sign(accessTokenJwt)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")

		tokenRes := OAuth2TokenResponse{
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

func (h *OIDCHandler) handleWildcardEmail(w http.ResponseWriter, r *http.Request, identity *Identity) (string, bool) {

	emailWildcard := r.Form.Get("email-wildcard")

	if identity.IdType == IdentityTypeEmail && emailWildcard == "" {
		wildcardParts := strings.Split(identity.Id, "*")
		if len(wildcardParts) == 2 {
			data := struct {
				*commonData
				Id     string
				Prefix string
				Suffix string
			}{
				Id:         identity.Id,
				commonData: newCommonData(nil, h.db, r),
				Prefix:     wildcardParts[0],
				Suffix:     wildcardParts[1],
			}

			err := h.tmpl.ExecuteTemplate(w, "wildcard-email.html", data)
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return emailWildcard, true
			}

			return emailWildcard, true
		}
	}

	return emailWildcard, false
}

func ParseAuthRequest(w http.ResponseWriter, r *http.Request) (*OAuth2AuthRequest, error) {
	r.ParseForm()

	clientId := r.Form.Get("client_id")
	if clientId == "" {
		w.WriteHeader(400)
		io.WriteString(w, "client_id missing")
		return nil, errors.New("client_id missing")
	}

	redirectUri := r.Form.Get("redirect_uri")
	if redirectUri == "" {
		w.WriteHeader(400)
		io.WriteString(w, "redirect_uri missing")
		return nil, errors.New("redirect_uri missing")
	}

	parsedClientIdUri, err := url.Parse(clientId)
	if err != nil {
		w.WriteHeader(400)
		msg := "client_id is not a valid URI"
		io.WriteString(w, msg)
		return nil, errors.New(msg)
	}

	parsedRedirectUri, err := url.Parse(redirectUri)
	if err != nil {
		w.WriteHeader(400)
		msg := "redirect_uri is not a valid URI"
		io.WriteString(w, msg)
		return nil, errors.New(msg)
	}

	// draft-ietf-oauth-security-topics-24 4.1
	if parsedClientIdUri.Host != parsedRedirectUri.Host {
		w.WriteHeader(400)
		io.WriteString(w, "redirect_uri must be on the same domain as client_id")
		fmt.Println(redirectUri, clientId)
		return nil, errors.New("redirect_uri must be on the same domain as client_id")
	}

	scope := r.Form.Get("scope")
	state := r.Form.Get("state")

	promptParam := r.Form.Get("prompt")
	if promptParam == "none" {
		errUrl := fmt.Sprintf("%s?error=interaction_required&state=%s",
			redirectUri, state)
		http.Redirect(w, r, errUrl, http.StatusSeeOther)
		return nil, errors.New("interaction required")
	}

	responseType := r.Form.Get("response_type")
	if responseType == "" {
		errUrl := fmt.Sprintf("%s?error=unsupported_response_type&state=%s",
			redirectUri, state)
		http.Redirect(w, r, errUrl, http.StatusSeeOther)
		return nil, errors.New("unsupported_response_type")
	}

	pkceCodeChallenge := r.Form.Get("code_challenge")

	return &OAuth2AuthRequest{
		ClientId:      clientId,
		RedirectUri:   redirectUri,
		ResponseType:  responseType,
		Scope:         scope,
		State:         state,
		CodeChallenge: pkceCodeChallenge,
	}, nil
}

func (h *OIDCHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}
