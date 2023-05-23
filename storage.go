package main

import (
	"encoding/json"
	"errors"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"os"
	"sync"
)

type User struct {
}

type Identity struct {
	Id           string `json:"id"`
	ProviderName string `json:"provider_name"`
	ProviderId   string `json:"provider_id"`
	OwnerId      string `json:"owner_id"`
	Email        string `json:"email"`
}

type LoginData struct {
	OwnerId string `json:"owner_id"`
}

type PendingOAuth2Token struct {
	OwnerId     string       `json:"owner_id"`
	AccessToken string       `json:"access_token"`
	IdToken     openid.Token `json:"id_token"`
}

type Token struct {
	IdentityId string `json:"identity_id"`
}

type OIDCProvider struct {
	Name         string `json:"name"`
	ID           string `json:"id"`
	URI          string `json:"uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type Storage struct {
	OIDCProviders []*OIDCProvider       `json:"oidc_providers"`
	Users         map[string]*User      `json:"users"`
	Identities    []*Identity           `json:"identities"`
	LoginData     map[string]*LoginData `json:"login_data"`
	Tokens        map[string]*Token     `json:"tokens"`
	requests      map[string]*OAuth2AuthRequest
	pendingTokens map[string]*PendingOAuth2Token
	mutex         *sync.Mutex
	path          string
}

func NewFileStorage(path string) (*Storage, error) {
	s := &Storage{
		OIDCProviders: []*OIDCProvider{},
		Users:         make(map[string]*User),
		Identities:    []*Identity{},
		LoginData:     make(map[string]*LoginData),
		Tokens:        make(map[string]*Token),
		requests:      make(map[string]*OAuth2AuthRequest),
		pendingTokens: make(map[string]*PendingOAuth2Token),
		mutex:         &sync.Mutex{},
		path:          path,
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

func (s *Storage) GetOIDCProviders() []*OIDCProvider {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.OIDCProviders
}

func (s *Storage) GetOIDCProviderByID(id string) (*OIDCProvider, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, provider := range s.OIDCProviders {
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

func (s *Storage) AddLoginData(userId string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, ok := s.Users[userId]
	if !ok {
		return "", errors.New("No such user. Could not login")
	}

	id, err := genRandomKey()
	if err != nil {
		return "", err
	}

	s.LoginData[id] = &LoginData{
		OwnerId: userId,
	}

	s.persist()

	return id, nil
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

func (s *Storage) AddUser() (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	id, err := genRandomKey()
	if err != nil {
		return "", err
	}

	s.Users[id] = &User{}

	s.persist()

	return id, nil
}

func (s *Storage) AddIdentity(ownerId, providerId, providerName, email string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, ident := range s.Identities {
		if ident.OwnerId == ownerId && ident.ProviderId == providerId {
			return "", errors.New("Identity already exists")
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
		OwnerId:      ownerId,
		Email:        email,
	}

	s.Identities = append(s.Identities, identity)

	s.persist()

	return id, nil
}

func (s *Storage) GetIdentityById(identId string) (*Identity, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, ident := range s.Identities {
		if ident.Id == identId {
			return ident, nil
		}
	}

	return nil, errors.New("Identity not found")
}

func (s *Storage) GetIdentitiesByUser(userId string) []*Identity {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	idents := []*Identity{}

	for _, ident := range s.Identities {
		if ident.OwnerId == userId {
			idents = append(idents, ident)
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

func (s *Storage) SetToken(token, identityId string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, ident := range s.Identities {
		if ident.Id == identityId {
			tok := &Token{
				IdentityId: ident.Id,
			}
			s.Tokens[token] = tok
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

func (s *Storage) persist() {
	saveJson(s, s.path)
}

func saveJson(data interface{}, filePath string) error {
	jsonStr, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errors.New("Error serializing JSON")
	} else {
		err := os.WriteFile(filePath, jsonStr, 0644)
		if err != nil {
			return errors.New("Error saving JSON")
		}
	}
	return nil
}
