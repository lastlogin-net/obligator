package obligator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func NewFedCmHandler(storage Storage) *FedCmHandler {

	mux := http.NewServeMux()

	h := &FedCmHandler{
		mux: mux,
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
		fmt.Println("/fedcm/config.json")
		config := FedCmConfig{
			AccountsEndpoint:       fmt.Sprintf("%s/fedcm/accounts", storage.GetRootUri()),
			ClientMetadataEndpoint: fmt.Sprintf("%s/fedcm/client-metadata", storage.GetRootUri()),
			IdAssertionEndpoint:    fmt.Sprintf("%s/fedcm/id-assertion", storage.GetRootUri()),
			LoginUrl:               fmt.Sprintf("%s/fedcm/login-url", storage.GetRootUri()),
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
		fmt.Println("/fedcm/accounts")
		accounts := FedCmAccounts{
			Accounts: []FedCmAccount{
				FedCmAccount{
					Id:        "fake-id",
					GivenName: "Anders Pitman",
					Name:      "Anders",
					Email:     "&ers@apitman.com",
					Picture:   "https://apitman.com/gemdrive/images/512/portrait.jpg",
				},
			},
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
		fmt.Println("/fedcm/client-metadata")

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
		fmt.Println("/fedcm/id-assertion")

		r.ParseForm()

		fmt.Println(r)

		printJson(r.Form)

		res := FedCmIdAssertionResponse{
			Token: "fake-token",
		}

		clientId := r.Form.Get("client_id")

		clientId = clientId[:len(clientId)-1]

		fmt.Println("client_id", clientId)

		w.Header().Set("Access-Control-Allow-Origin", clientId)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(res)
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
