package obligator

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Storage interface {
	GetRootUri() string
	GetPrefix() string
	SetRootUri(string) error
	GetUsers() ([]User, error)
	CreateUser(User) error
	GetOAuth2Providers() ([]OAuth2Provider, error)
	GetOAuth2ProviderByID(string) (OAuth2Provider, error)
	SetOauth2Provider(OAuth2Provider) error
	GetPublic() bool
	GetSmtpConfig() (SmtpConfig, error)
	GetJWKSet() jwk.Set
	GetDisplayName() string
	SetDisplayName(string)
	GetFedCmEnabled() bool
	SetFedCmEnable(bool)
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
	ID               string `json:"id"`
	Name             string `json:"name"`
	URI              string `json:"uri"`
	ClientID         string `json:"client_id" db:"client_id"`
	ClientSecret     string `json:"client_secret" db:"client_secret"`
	AuthorizationURI string `json:"authorization_uri,omitempty" db:"authorization_uri"`
	TokenURI         string `json:"token_uri,omitempty" db:"token_uri"`
	Scope            string `json:"scope,omitempty"`
	OpenIDConnect    bool   `json:"openid_connect" db:"supports_openid_connect"`
}

type User struct {
	Email string `json:"email"`
}
