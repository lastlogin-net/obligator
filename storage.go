package main

import (
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

type Storage interface {
	GetRootUri() string
	SetRootUri(string) error
	GetUsers() ([]User, error)
	CreateUser(User) error
}

type Identity struct {
	Id           string `json:"id"`
	ProviderName string `json:"provider_name"`
	ProviderId   string `json:"provider_id"`
	Email        string `json:"email"`
}

type LoginData struct {
	Timestamp string `json:"timestamp"`
}

type PendingOAuth2Token struct {
	AccessToken       string       `json:"access_token"`
	IdToken           openid.Token `json:"id_token"`
	PKCECodeChallenge string       `json:"pkce_code_challenge"`
}

type Token struct {
	IdentityId        string `json:"identity_id"`
	CreatedAt         string `json:"created_at"`
	ExpiresIn         int    `json:"expires_in"`
	AuthorizationCode string `json:"authorization_code"`
}

type OAuth2Provider struct {
	Name             string `json:"name"`
	ID               string `json:"id"`
	URI              string `json:"uri"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	AuthorizationURI string `json:"authorization_uri,omitempty"`
	TokenURI         string `json:"token_uri,omitempty"`
	Scope            string `json:"scope,omitempty"`
	OpenIDConnect    bool   `json:"openid_connect"`
}

type LoginMapping struct {
	IdentityId string `json:"identity_id"`
	LoginKey   string `json:"login_key"`
}

type User struct {
	Email string `json:"email"`
}
