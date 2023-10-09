package main

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

type Storage interface {
	GetRootUri() string
	SetRootUri(string) error
	GetUsers() ([]User, error)
	CreateUser(User) error
	GetOAuth2Providers() ([]OAuth2Provider, error)
	GetOAuth2ProviderByID(string) (OAuth2Provider, error)
	SetOauth2Provider(OAuth2Provider) error
	GetRequest(requestId string) (OAuth2AuthRequest, error)
	SetRequest(requestId string, request OAuth2AuthRequest)
	DeleteRequest(requestId string)
	GetPublic() bool
	GetSmtpConfig() (SmtpConfig, error)
	GetJWKSet() jwk.Set
}

type Identity struct {
	Id           string `json:"id"`
	ProviderName string `json:"provider_name"`
	ProviderId   string `json:"provider_id"`
	Email        string `json:"email"`
}

type PendingOAuth2Token struct {
	AccessToken       string       `json:"access_token"`
	IdToken           openid.Token `json:"id_token"`
	PKCECodeChallenge string       `json:"pkce_code_challenge"`
}

type Token struct {
	IdentityId        string `json:"identity_id"`
	Email             string `json:"email"`
	CreatedAt         string `json:"created_at"`
	ExpiresIn         int    `json:"expires_in"`
	AuthorizationCode string `json:"authorization_code"`
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
