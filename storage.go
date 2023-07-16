package main

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
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

type User struct {
	Email string `json:"email"`
}

type Storage struct {
	RootUri         string                `json:"root_uri"`
	OAuth2Providers []OAuth2Provider      `json:"oauth2_providers"`
	Smtp            *SmtpConfig           `json:"smtp"`
	Jwks            jwk.Set               `json:"jwks"`
	Identities      []*Identity           `json:"identities"`
	LoginData       map[string]*LoginData `json:"login_data"`
	Tokens          map[string]*Token     `json:"tokens"`
	LoginMap        []*LoginMapping       `json:"login_map"`
	Users           []User                `json:"users"`
	Public          bool                  `json:"public"`
	requests        map[string]*OAuth2AuthRequest
	pendingTokens   map[string]*PendingOAuth2Token
	mutex           *sync.Mutex
	path            string
	message_chan    chan interface{}
}

func NewFileStorage(path string) (*Storage, error) {
	s := &Storage{
		OAuth2Providers: []OAuth2Provider{},
		Jwks:            jwk.NewSet(),
		Identities:      []*Identity{},
		LoginData:       make(map[string]*LoginData),
		Tokens:          make(map[string]*Token),
		LoginMap:        []*LoginMapping{},
		Users:           []User{},
		requests:        make(map[string]*OAuth2AuthRequest),
		pendingTokens:   make(map[string]*PendingOAuth2Token),
		mutex:           &sync.Mutex{},
		path:            path,
		message_chan:    make(chan interface{}),
	}

	dbJson, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(dbJson, s)
		if err != nil {
			return nil, err
		}
	}

	go func() {
		for {
			rawMessage := <-s.message_chan
			switch msg := rawMessage.(type) {
			case getPublicMessage:
				msg.resp <- s.Public
			case getUsersMessage:
				users := []User{}
				for _, user := range s.Users {
					users = append(users, user)
				}
				msg.resp <- users
			case createUserMessage:
				var err error
				for _, user := range s.Users {
					if user.Email == msg.user.Email {
						err = errors.New("User exists")
						break
					}
				}

				if err == nil {
					s.Users = append(s.Users, msg.user)
					s.Persist()
				}

				msg.resp <- err
			case setRootUriMessage:

				s.mutex.Lock()
				s.RootUri = msg.rootUri
				s.persist()
				s.mutex.Unlock()

				msg.resp <- nil
			case getOauth2ProvidersMessage:
				providers := []OAuth2Provider{}
				for _, prov := range s.OAuth2Providers {
					providers = append(providers, prov)
				}
				msg.resp <- providers
			case setOauth2ProviderMessage:

				foundIdx := -1
				for i, prov := range s.OAuth2Providers {
					if prov.ID == msg.provider.ID {
						foundIdx = i
						break
					}
				}

				if foundIdx != -1 {
					// replace
					tmp := append(s.OAuth2Providers[:foundIdx], msg.provider)
					s.OAuth2Providers = append(tmp, s.OAuth2Providers[foundIdx+1:]...)
				} else {
					// append a new one
					s.OAuth2Providers = append(s.OAuth2Providers, msg.provider)
				}

				s.Persist()

				msg.resp <- nil
			}
		}
	}()

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
	s.Jwks.AddKey(key)
	s.persist()
}

func (s *Storage) GetJWKSet() jwk.Set {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.Jwks
}

func (s *Storage) GetOAuth2ProviderByID(id string) (*OAuth2Provider, error) {

	providers := s.GetOAuth2Providers()

	for _, provider := range providers {
		if provider.ID == id {
			provCopy := provider
			return &provCopy, nil
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

type getPublicMessage struct {
	resp chan bool
}

func (s *Storage) GetPublic() bool {
	ch := make(chan bool)
	s.message_chan <- getPublicMessage{
		resp: ch,
	}
	public := <-ch
	return public
}

type getUsersMessage struct {
	resp chan []User
}

func (s *Storage) GetUsers() []User {
	ch := make(chan []User)
	s.message_chan <- getUsersMessage{
		resp: ch,
	}
	users := <-ch
	return users
}

type createUserMessage struct {
	user User
	resp chan error
}

func (s *Storage) CreateUser(user User) error {
	resp := make(chan error)
	s.message_chan <- createUserMessage{
		user,
		resp,
	}
	err := <-resp
	return err
}

type setRootUriMessage struct {
	rootUri string
	resp    chan error
}

func (s *Storage) SetRootUri(rootUri string) error {
	resp := make(chan error)
	s.message_chan <- setRootUriMessage{
		rootUri,
		resp,
	}
	err := <-resp
	return err
}

type getOauth2ProvidersMessage struct {
	resp chan []OAuth2Provider
}

func (s *Storage) GetOAuth2Providers() []OAuth2Provider {
	ch := make(chan []OAuth2Provider)
	s.message_chan <- getOauth2ProvidersMessage{
		resp: ch,
	}
	return <-ch
}

type setOauth2ProviderMessage struct {
	provider OAuth2Provider
	resp     chan error
}

func (s *Storage) SetOauth2Provider(provider OAuth2Provider) error {
	resp := make(chan error)
	s.message_chan <- setOauth2ProviderMessage{
		provider,
		resp,
	}
	err := <-resp
	return err
}

func (s *Storage) Persist() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	saveJson(s, s.path)
}

func (s *Storage) persist() {
	saveJson(s, s.path)
}
