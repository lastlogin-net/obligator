package obligator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
	//"net/http/httputil"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

type FedCmWebId struct {
	ProviderUrls []string `json:"provider_urls"`
}

type FedCmConfig struct {
	AccountsEndpoint       string `json:"accounts_endpoint"`
	ClientMetadataEndpoint string `json:"client_metadata_endpoint"`
	IdAssertionEndpoint    string `json:"id_assertion_endpoint"`
	LoginUrl               string `json:"login_url"`
}

type FedCmAccounts struct {
	Accounts []FedCmAccount `json:"accounts"`
}

type FedCmAccount struct {
	Id        string `json:"id"`
	GivenName string `json:"given_name"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Picture   string `json:"picture"`
}

type FedCmClientMetadata struct {
	PrivacyPolicyUrl  string `json:"privacy_policy_url"`
	TermsOfServiceUrl string `json:"terms_of_service_url"`
}

type FedCmIdAssertionResponse struct {
	Token string `json:"token"`
}

type FedCmHandler struct {
	mux *http.ServeMux
}

func NewFedCmHandler(storage Storage, loginEndpoint string) *FedCmHandler {

	mux := http.NewServeMux()

	h := &FedCmHandler{
		mux: mux,
	}

	privateJwks := storage.GetJWKSet()
	publicJwks, err := jwk.PublicSetOf(privateJwks)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	mux.HandleFunc("/.well-known/web-identity", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/.well-known/web-identity")

		webId := FedCmWebId{
			ProviderUrls: []string{
				fmt.Sprintf("%s/fedcm/config.json", storage.GetRootUri()),
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
		config := FedCmConfig{
			AccountsEndpoint:       fmt.Sprintf("%s/fedcm/accounts", storage.GetRootUri()),
			ClientMetadataEndpoint: fmt.Sprintf("%s/fedcm/client-metadata", storage.GetRootUri()),
			IdAssertionEndpoint:    fmt.Sprintf("%s/fedcm/id-assertion", storage.GetRootUri()),
			LoginUrl:               fmt.Sprintf("%s%s", storage.GetRootUri(), loginEndpoint),
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

		idents, _ := getIdentities(storage, r, publicJwks)

		accounts := FedCmAccounts{
			Accounts: []FedCmAccount{},
		}

		for _, ident := range idents {
			account := FedCmAccount{
				Id: ident.Id,
				//GivenName: "Anders Pitman",
				Name:  "No Name",
				Email: ident.Id,
				//Picture:   "https://apitman.com/gemdrive/images/512/portrait.jpg",

			}
			if account.Name == "" {
				account.Name = "No Name"
			}
			accounts.Accounts = append(accounts.Accounts, account)
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(accounts)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})
	mux.HandleFunc("/client-metadata", func(w http.ResponseWriter, r *http.Request) {

		md := FedCmClientMetadata{
			PrivacyPolicyUrl:  storage.GetRootUri(),
			TermsOfServiceUrl: storage.GetRootUri(),
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

		if r.Header.Get("Sec-Fetch-Dest") != "webidentity" {
			w.WriteHeader(401)
			io.WriteString(w, "Sec-Fetch-Dest != webidentity")
			return
		}

		r.ParseForm()

		accountId := r.Form.Get("account_id")

		idents, _ := getIdentities(storage, r, publicJwks)

		res := FedCmIdAssertionResponse{
			Token: "fake-token",
		}

		clientId := r.Form.Get("client_id")
		clientId = clientId[:len(clientId)-1]

		// TODO: Multiple idents might map to the same email. might
		// need to start using unique random IDs for accounts.
		for _, ident := range idents {
			if accountId == ident.Id {

				issuedAt := time.Now().UTC()
				expiresAt := issuedAt.Add(8 * time.Minute)

				idTokenBuilder := openid.NewBuilder().
					Email(ident.Id).
					Subject(ident.Id).
					Audience([]string{clientId}).
					Issuer(storage.GetRootUri()).
					IssuedAt(issuedAt).
					Expiration(expiresAt)
					//Claim("nonce", claimFromToken("nonce", parsedAuthReq))

				idToken, err := idTokenBuilder.Build()
				if err != nil {
					fmt.Fprintf(os.Stderr, err.Error())
					break
				}

				key, exists := storage.GetJWKSet().Key(0)
				if !exists {
					fmt.Fprintf(os.Stderr, "No keys available")
					break
				}

				signedIdToken, err := jwt.Sign(idToken, jwt.WithKey(jwa.RS256, key))
				if err != nil {
					fmt.Fprintf(os.Stderr, err.Error())
					break
				}

				res.Token = string(signedIdToken)
				break
			}
		}

		w.Header().Set("Access-Control-Allow-Origin", clientId)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
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
