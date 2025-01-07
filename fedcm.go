package obligator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
	//"time"
	//"net/http/httputil"
)

type FedCmWebId struct {
	ProviderUrls []string `json:"provider_urls"`
}

type FedCmConfig struct {
	AccountsEndpoint       string   `json:"accounts_endpoint,omitempty"`
	ClientMetadataEndpoint string   `json:"client_metadata_endpoint,omitempty"`
	IdAssertionEndpoint    string   `json:"id_assertion_endpoint,omitempty"`
	LoginUrl               string   `json:"login_url,omitempty"`
	Types                  []string `json:"types"`
}

type FedCmAccounts struct {
	Accounts []FedCmAccount `json:"accounts,omitempty"`
}

type FedCmAccount struct {
	Id        string `json:"id,omitempty"`
	GivenName string `json:"given_name,omitempty"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	Picture   string `json:"picture,omitempty"`
}

type FedCmClientMetadata struct {
	PrivacyPolicyUrl  string `json:"privacy_policy_url,omitempty"`
	TermsOfServiceUrl string `json:"terms_of_service_url,omitempty"`
}

type FedCmIdAssertionSuccessResponse struct {
	Token string `json:"token,omitempty"`
}

type FedCmIdAssertionErrorResponse struct {
	Error FedCmIdAssertionError `json:"error,omitempty"`
}

type FedCmIdAssertionError struct {
	Code string `json:"code,omitempty"`
	Url  string `json:"url,omitempty"`
}

type FedCmHandler struct {
	mux *http.ServeMux
}

type IndieAuthFedCmResponse struct {
	Code             string `json:"code"`
	MetadataEndpoint string `json:"metadata_endpoint"`
}

type IndieAuthFedCMParams struct {
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

func NewFedCmHandler(db Database, loginEndpoint string, jose *JOSE) *FedCmHandler {

	mux := http.NewServeMux()

	h := &FedCmHandler{
		mux: mux,
	}

	mux.HandleFunc("/.well-known/web-identity", func(w http.ResponseWriter, r *http.Request) {

		webId := FedCmWebId{
			ProviderUrls: []string{
				fmt.Sprintf("%s/fedcm/config.json", domainToUri(r.Host)),
			},
		}

		w.Header().Set("Content-Type", "application/json")

		err := json.NewEncoder(w).Encode(webId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})
	mux.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {

		uri := domainToUri(r.Host)

		config := FedCmConfig{
			AccountsEndpoint: fmt.Sprintf("%s/fedcm/accounts", uri),
			//ClientMetadataEndpoint: fmt.Sprintf("%s/fedcm/client-metadata", uri),
			IdAssertionEndpoint: fmt.Sprintf("%s/fedcm/id-assertion", uri),
			LoginUrl:            fmt.Sprintf("%s%s", uri, loginEndpoint),
			Types: []string{
				"indieauth",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(config)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})
	mux.HandleFunc("/accounts", func(w http.ResponseWriter, r *http.Request) {

		if r.Header.Get("Sec-Fetch-Dest") != "webidentity" {
			w.WriteHeader(401)
			io.WriteString(w, "Sec-Fetch-Dest != webidentity")
			return
		}

		idents, _ := getIdentitiesFedCm(db, r)

		if len(idents) == 0 {
			w.WriteHeader(401)
			io.WriteString(w, "No identities available")
			return
		}

		accounts := FedCmAccounts{
			Accounts: []FedCmAccount{},
		}

		for _, ident := range idents {

			name := "No Name"
			if ident.Name != "" {
				name = ident.Name
			}

			account := FedCmAccount{
				Id:    ident.Id,
				Name:  name,
				Email: ident.Id,
			}

			accounts.Accounts = append(accounts.Accounts, account)
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(accounts)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})
	mux.HandleFunc("/client-metadata", func(w http.ResponseWriter, r *http.Request) {

		uri := domainToUri(r.Host)

		md := FedCmClientMetadata{
			PrivacyPolicyUrl:  uri,
			TermsOfServiceUrl: uri,
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(md)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})
	mux.HandleFunc("/id-assertion", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		clientId := r.Form.Get("client_id")

		origin := r.Header.Get("Origin")

		parsedOrigin, err := url.Parse(origin)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		parsedClientId, err := url.Parse(clientId)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		if parsedOrigin.Host != parsedClientId.Host {
			w.WriteHeader(401)
			res := FedCmIdAssertionErrorResponse{
				Error: FedCmIdAssertionError{
					Code: "unauthorized_client",
				},
			}
			json.NewEncoder(w).Encode(res)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", "https://"+parsedClientId.Host)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")

		if r.Header.Get("Sec-Fetch-Dest") != "webidentity" {
			w.WriteHeader(401)
			io.WriteString(w, "Sec-Fetch-Dest != webidentity")
			return
		}

		idents, _ := getIdentitiesFedCm(db, r)

		accountId := r.Form.Get("account_id")

		paramsParam := r.Form.Get("params")

		pkceCodeChallenge := r.Form.Get("nonce")
		if paramsParam != "" {
			var params IndieAuthFedCMParams
			err = json.Unmarshal([]byte(paramsParam), &params)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}

			pkceCodeChallenge = params.CodeChallenge
		}

		//uri := domainToUri(r.Host)

		// TODO: Multiple idents might map to the same email. might
		// need to start using unique random IDs for accounts.
		var foundIdent *Identity = nil
		for _, ident := range idents {
			if accountId == ident.Id {

				foundIdent = ident
				break

				// TODO: this code is for directly returning the ID token. We're currently
				// hard coded for IndieAuth.

				//issuedAt := time.Now().UTC()
				//expiresAt := issuedAt.Add(8 * time.Minute)

				//idTokenBuilder := openid.NewBuilder().
				//	Email(ident.Id).
				//	Subject(ident.Id).
				//	Audience([]string{clientId}).
				//	Issuer(uri).
				//	IssuedAt(issuedAt).
				//	Expiration(expiresAt)
				//	//Claim("nonce", claimFromToken("nonce", parsedAuthReq))
				//if ident.Name != "" {
				//	idTokenBuilder.Name(ident.Name)
				//}

				//idToken, err := idTokenBuilder.Build()
				//if err != nil {
				//	fmt.Fprintf(os.Stderr, err.Error())
				//	break
				//}

				//key, exists := storage.GetJWKSet().Key(0)
				//if !exists {
				//	fmt.Fprintf(os.Stderr, "No keys available")
				//	break
				//}

				//signedIdToken, err := jwt.Sign(idToken, jwt.WithKey(jwa.RS256, key))
				//if err != nil {
				//	fmt.Fprintf(os.Stderr, err.Error())
				//	break
				//}

				//res.Token = string(signedIdToken)
				//break
			}
		}

		if foundIdent == nil {
			w.WriteHeader(403)
			io.WriteString(w, "No proper identity found")
			return
		}

		// TODO: re-enable domain login
		//domain, err := db.GetDomain(r.Host)
		//if err != nil {
		//	w.WriteHeader(500)
		//	io.WriteString(w, err.Error())
		//	return
		//}

		//if domain.HashedOwnerId != Hash(foundIdent.Id) {
		//	w.WriteHeader(403)
		//	io.WriteString(w, "You don't own this domain")
		//	return
		//}

		issuedAt := time.Now().UTC()
		codeJwt, err := NewJWTBuilder().
			IssuedAt(issuedAt).
			// TODO: make shorter
			//Expiration(issuedAt.Add(16*time.Second)).
			Expiration(issuedAt.Add(5*time.Minute)).
			//Subject(idToken.Email()).
			Claim("domain", r.Host).
			Claim("id", foundIdent.Id).
			Claim("pkce_code_challenge", pkceCodeChallenge).
			Build()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		signedCode, err := SignJWT(db, codeJwt)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		payload := IndieAuthFedCmResponse{
			Code:             string(signedCode),
			MetadataEndpoint: fmt.Sprintf("https://%s/.well-known/oauth-authorization-server", r.Host),
		}

		payloadJson, err := json.Marshal(payload)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		res := FedCmIdAssertionSuccessResponse{
			Token: string(payloadJson),
		}
		err = json.NewEncoder(w).Encode(res)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	return h
}

func (h *FedCmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}
