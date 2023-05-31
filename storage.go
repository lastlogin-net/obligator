package main

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

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
	AccessToken string       `json:"access_token"`
	IdToken     openid.Token `json:"id_token"`
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

type Storage struct {
	RootUri         string                `json:"root_uri"`
	OAuth2Providers []*OAuth2Provider     `json:"oauth2_providers"`
	Smtp            *SmtpConfig           `json:"smtp"`
	Jwks            jwk.Set               `json:"jwks"`
	Identities      []*Identity           `json:"identities"`
	LoginData       map[string]*LoginData `json:"login_data"`
	Tokens          map[string]*Token     `json:"tokens"`
	LoginMap        []*LoginMapping       `json:"login_map"`
	requests        map[string]*OAuth2AuthRequest
	pendingTokens   map[string]*PendingOAuth2Token
	mutex           *sync.Mutex
	path            string
}

func NewFileStorage(path string) (*Storage, error) {
	s := &Storage{
		OAuth2Providers: []*OAuth2Provider{},
		Jwks:            jwk.NewSet(),
		Identities:      []*Identity{},
		LoginData:       make(map[string]*LoginData),
		Tokens:          make(map[string]*Token),
		LoginMap:        []*LoginMapping{},
		requests:        make(map[string]*OAuth2AuthRequest),
		pendingTokens:   make(map[string]*PendingOAuth2Token),
		mutex:           &sync.Mutex{},
		path:            path,
	}

	dbJson, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(dbJson, s)
		if err != nil {
			return nil, err
		}
	}

	s.persist()

	return s, nil
}

func (s *Storage) GetRootUri() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.RootUri
}

func (s *Storage) GetLoginMap() []*LoginMapping {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.LoginMap
}

func (s *Storage) EnsureLoginMapping(identityId, loginKey string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, mapping := range s.LoginMap {
		if mapping.IdentityId == identityId && mapping.LoginKey == loginKey {
			return
		}
	}

	newMapping := &LoginMapping{
		IdentityId: identityId,
		LoginKey:   loginKey,
	}

	s.LoginMap = append(s.LoginMap, newMapping)

	s.persist()
}

func (s *Storage) AddJWKKey(key jwk.Key) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.Jwks.Add(key)
	s.persist()
}

func (s *Storage) GetJWKSet() jwk.Set {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.Jwks
}

func (s *Storage) GetOAuth2Providers() []*OAuth2Provider {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.OAuth2Providers
}

func (s *Storage) GetOAuth2ProviderByID(id string) (*OAuth2Provider, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, provider := range s.OAuth2Providers {
		if provider.ID == id {
			return provider, nil
		}
	}

	return nil, errors.New("No such provider")
}

func (s *Storage) GetAllIdentities() []*Identity {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.Identities
}

func (s *Storage) AddLoginData() (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	loginKey, err := genRandomKey()
	if err != nil {
		return "", err
	}

	loginKeyHash := Hash(loginKey)

	timestamp := time.Now().Format(time.RFC3339)

	s.LoginData[loginKeyHash] = &LoginData{
		Timestamp: timestamp,
	}

	s.persist()

	return loginKey, nil
}

func (s *Storage) DeleteLoginData(loginKey string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	newLoginMap := []*LoginMapping{}

	for _, mapping := range s.LoginMap {
		if mapping.LoginKey != loginKey {
			newLoginMap = append(newLoginMap, mapping)
		}
	}

	delete(s.LoginData, loginKey)
	s.LoginMap = newLoginMap

	s.persist()
}

func (s *Storage) GetLoginData(loginKey string) (*LoginData, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	data, ok := s.LoginData[loginKey]
	if !ok {
		return nil, errors.New("No such login")
	}

	return data, nil
}

func (s *Storage) EnsureIdentity(providerId, providerName, email string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, ident := range s.Identities {
		if ident.ProviderName == providerName && ident.ProviderId == providerId {
			return ident.Id, nil
		}
	}

	id, err := genRandomKey()
	if err != nil {
		return "", err
	}

	identity := &Identity{
		Id:           id,
		ProviderName: providerName,
		ProviderId:   providerId,
		Email:        email,
	}

	s.Identities = append(s.Identities, identity)

	s.persist()

	return id, nil
}

func (s *Storage) GetIdentityById(identId string) (*Identity, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.getIdentityById(identId)
}
func (s *Storage) getIdentityById(identId string) (*Identity, error) {

	for _, ident := range s.Identities {
		if ident.Id == identId {
			return ident, nil
		}
	}

	return nil, errors.New("Identity not found")
}

func (s *Storage) GetIdentitiesByLoginKey(loginKey string) []*Identity {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	idents := []*Identity{}

	for _, mapping := range s.LoginMap {
		if mapping.LoginKey == loginKey {
			ident, err := s.getIdentityById(mapping.IdentityId)
			if err != nil {
				continue
			} else {
				idents = append(idents, ident)
			}
		}
	}

	return idents
}

func (s *Storage) AddRequest(req OAuth2AuthRequest) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	requestId, err := genRandomKey()
	if err != nil {
		return "", err
	}

	s.requests[requestId] = &req

	s.persist()

	return requestId, nil
}

func (s *Storage) GetRequest(requestId string) (OAuth2AuthRequest, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	req, ok := s.requests[requestId]
	if !ok {
		return OAuth2AuthRequest{}, errors.New("No such request")
	}

	return *req, nil
}

func (s *Storage) SetRequest(requestId string, request OAuth2AuthRequest) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.requests[requestId] = &request

	s.persist()
}
func (s *Storage) DeleteRequest(requestId string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.requests, requestId)
}

func (s *Storage) AddPendingToken(token *PendingOAuth2Token) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	code, err := genRandomKey()
	if err != nil {
		return "", err
	}

	accessToken, err := genRandomKey()
	if err != nil {
		return "", err
	}

	token.AccessToken = accessToken

	s.pendingTokens[code] = token

	s.persist()

	return code, nil
}
func (s *Storage) GetPendingToken(code string) (*PendingOAuth2Token, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, ok := s.pendingTokens[code]
	if !ok {
		return token, errors.New("No token for code")
	}

	return token, nil
}
func (s *Storage) DeletePendingToken(code string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.pendingTokens, code)
}

func (s *Storage) SetToken(token string, tokenData *Token) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, ident := range s.Identities {
		if ident.Id == tokenData.IdentityId {
			s.Tokens[token] = tokenData
			s.persist()
			return nil
		}
	}

	return errors.New("No such identity")
}
func (s *Storage) GetToken(token string) (*Token, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tok, ok := s.Tokens[token]
	if ok {
		return tok, nil
	}

	return nil, errors.New("Invalid token")
}
func (s *Storage) GetTokens() map[string]*Token {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.Tokens
}
func (s *Storage) DeleteToken(token string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.Tokens, token)

	s.persist()
}

func (s *Storage) persist() {
	saveJson(s, s.path)
}
