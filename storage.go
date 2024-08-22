package obligator

import ()

type Storage interface {
	GetSmtpConfig() (SmtpConfig, error)
}

type Identity struct {
	IdType        string `json:"id_type"`
	Id            string `json:"id"`
	ProviderName  string `json:"provider_name"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type Login struct {
	IdType       string `json:"id_type"`
	Id           string `json:"id"`
	ProviderName string `json:"provider_name"`
	Timestamp    string `json:"ts"`
}

type OAuth2Provider struct {
	ID               string `json:"id" db:"id"`
	Name             string `json:"name" db"name"`
	URI              string `json:"uri" db "uri"`
	ClientID         string `json:"client_id" db:"client_id"`
	ClientSecret     string `json:"client_secret" db:"client_secret"`
	AuthorizationURI string `json:"authorization_uri,omitempty" db:"authorization_uri"`
	TokenURI         string `json:"token_uri,omitempty" db:"token_uri"`
	Scope            string `json:"scope,omitempty" db:"scope"`
	OpenIDConnect    bool   `json:"openid_connect" db:"supports_openid_connect"`
}
