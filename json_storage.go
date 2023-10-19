package main

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JsonStorage struct {
	RootUri         string           `json:"root_uri"`
	LoginKeyName    string           `json:"login_key_name"`
	OAuth2Providers []OAuth2Provider `json:"oauth2_providers"`
	Smtp            *SmtpConfig      `json:"smtp"`
	Jwks            jwk.Set          `json:"jwks"`
	Users           []User           `json:"users"`
	Public          bool             `json:"public"`
	requests        map[string]*OAuth2AuthRequest
	pendingTokens   map[string]*PendingOAuth2Token
	mutex           *sync.Mutex
	path            string
	message_chan    chan interface{}
}

func NewJsonStorage(path string) (*JsonStorage, error) {
	s := &JsonStorage{
		OAuth2Providers: []OAuth2Provider{},
		Jwks:            jwk.NewSet(),
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
			case getRootUriMessage:
				msg.resp <- s.RootUri
			case setRootUriMessage:
				s.RootUri = msg.rootUri
				msg.resp <- nil
				s.Persist()
			case getLoginKeyNameMessage:
				msg.resp <- s.LoginKeyName
			case setLoginKeyNameMessage:
				s.LoginKeyName = msg.loginKeyName
				msg.resp <- nil
				s.Persist()
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
			case getSmtpConfigMessage:
				if s.Smtp == nil {
					msg.resp <- nil
				} else {
					msg.resp <- &(*s.Smtp)
				}
			}
		}
	}()

	s.persist()

	return s, nil
}

type getRootUriMessage struct {
	resp chan string
}

func (s *JsonStorage) GetRootUri() string {
	ch := make(chan string)
	s.message_chan <- getRootUriMessage{
		resp: ch,
	}
	result := <-ch
	return result
}

type setRootUriMessage struct {
	rootUri string
	resp    chan error
}

func (s *JsonStorage) SetRootUri(rootUri string) error {
	resp := make(chan error)
	s.message_chan <- setRootUriMessage{
		rootUri,
		resp,
	}
	err := <-resp
	return err
}

type getLoginKeyNameMessage struct {
	resp chan string
}

func (s *JsonStorage) GetLoginKeyName() string {
	ch := make(chan string)
	s.message_chan <- getLoginKeyNameMessage{
		resp: ch,
	}
	result := <-ch
	return result
}

type setLoginKeyNameMessage struct {
	loginKeyName string
	resp         chan error
}

func (s *JsonStorage) SetLoginKeyName(loginKeyName string) {
	resp := make(chan error)
	s.message_chan <- setLoginKeyNameMessage{
		loginKeyName,
		resp,
	}
	<-resp
}

func (s *JsonStorage) AddJWKKey(key jwk.Key) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.Jwks.AddKey(key)
	s.persist()
}

func (s *JsonStorage) GetJWKSet() jwk.Set {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.Jwks
}

func (s *JsonStorage) GetOAuth2ProviderByID(id string) (OAuth2Provider, error) {

	providers, err := s.GetOAuth2Providers()
	if err != nil {
		return OAuth2Provider{}, err
	}

	for _, provider := range providers {
		if provider.ID == id {
			provCopy := provider
			return provCopy, nil
		}
	}

	return OAuth2Provider{}, errors.New("No such provider")
}

func (s *JsonStorage) AddRequest(req OAuth2AuthRequest) (string, error) {
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

func (s *JsonStorage) GetRequest(requestId string) (OAuth2AuthRequest, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	req, ok := s.requests[requestId]
	if !ok {
		return OAuth2AuthRequest{}, errors.New("No such request")
	}

	return *req, nil
}

func (s *JsonStorage) SetRequest(requestId string, request OAuth2AuthRequest) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.requests[requestId] = &request

	s.persist()
}
func (s *JsonStorage) DeleteRequest(requestId string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.requests, requestId)
}

func (s *JsonStorage) AddPendingToken(token *PendingOAuth2Token) (string, error) {
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
func (s *JsonStorage) GetPendingToken(code string) (*PendingOAuth2Token, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, ok := s.pendingTokens[code]
	if !ok {
		return token, errors.New("No token for code")
	}

	return token, nil
}
func (s *JsonStorage) DeletePendingToken(code string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.pendingTokens, code)
}

type getPublicMessage struct {
	resp chan bool
}

func (s *JsonStorage) GetPublic() bool {
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

func (s *JsonStorage) GetUsers() ([]User, error) {
	ch := make(chan []User)
	s.message_chan <- getUsersMessage{
		resp: ch,
	}
	users := <-ch
	return users, nil
}

type createUserMessage struct {
	user User
	resp chan error
}

func (s *JsonStorage) CreateUser(user User) error {
	resp := make(chan error)
	s.message_chan <- createUserMessage{
		user,
		resp,
	}
	err := <-resp
	return err
}

type getOauth2ProvidersMessage struct {
	resp chan []OAuth2Provider
}

func (s *JsonStorage) GetOAuth2Providers() ([]OAuth2Provider, error) {
	ch := make(chan []OAuth2Provider)
	s.message_chan <- getOauth2ProvidersMessage{
		resp: ch,
	}
	return <-ch, nil
}

type setOauth2ProviderMessage struct {
	provider OAuth2Provider
	resp     chan error
}

type getSmtpConfigMessage struct {
	resp chan *SmtpConfig
}

func (s *JsonStorage) SetOauth2Provider(provider OAuth2Provider) error {
	resp := make(chan error)
	s.message_chan <- setOauth2ProviderMessage{
		provider,
		resp,
	}
	err := <-resp
	return err
}

func (s *JsonStorage) GetSmtpConfig() (SmtpConfig, error) {
	ch := make(chan *SmtpConfig)
	s.message_chan <- getSmtpConfigMessage{
		resp: ch,
	}
	smtp := <-ch

	if smtp == nil {
		return SmtpConfig{}, errors.New("No SMTP config set")
	} else {
		return *smtp, nil
	}
}

func (s *JsonStorage) Persist() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	saveJson(s, s.path)
}

func (s *JsonStorage) persist() {
	saveJson(s, s.path)
}
