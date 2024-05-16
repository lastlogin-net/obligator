package obligator

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
