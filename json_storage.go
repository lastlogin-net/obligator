package obligator

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JsonStorage struct {
	DisplayName            string           `json:"display_name"`
	Prefix                 string           `json:"prefix"`
	OAuth2Providers        []OAuth2Provider `json:"oauth2_providers"`
	Smtp                   *SmtpConfig      `json:"smtp"`
	Jwks                   jwk.Set          `json:"jwks"`
	FedCmEnabled           bool             `json:"fedcm_enabled"`
	ForwardAuthPassthrough bool             `json:"forward_auth_passthrough"`
	mutex                  *sync.Mutex
	path                   string
	message_chan           chan interface{}
}

func NewJsonStorage(path string) (*JsonStorage, error) {
	s := &JsonStorage{
		DisplayName:     "obligator",
		OAuth2Providers: []OAuth2Provider{},
		Jwks:            jwk.NewSet(),
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
			case getPrefixMessage:
				msg.resp <- s.Prefix
			case setPrefixMessage:
				s.Prefix = msg.prefix
				msg.resp <- nil
				s.Persist()
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
			case getDisplayNameMessage:
				msg.resp <- s.DisplayName
			case setDisplayNameMessage:
				s.DisplayName = msg.value
				msg.resp <- nil
				s.Persist()
			}
		}
	}()

	s.persist()

	return s, nil
}

type getPrefixMessage struct {
	resp chan string
}

func (s *JsonStorage) GetPrefix() string {
	ch := make(chan string)
	s.message_chan <- getPrefixMessage{
		resp: ch,
	}
	result := <-ch
	return result
}

type setPrefixMessage struct {
	prefix string
	resp   chan error
}

func (s *JsonStorage) SetPrefix(prefix string) {
	resp := make(chan error)
	s.message_chan <- setPrefixMessage{
		prefix,
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

func (s *JsonStorage) SetOauth2Provider(provider OAuth2Provider) error {
	resp := make(chan error)
	s.message_chan <- setOauth2ProviderMessage{
		provider,
		resp,
	}
	err := <-resp
	return err
}

type getSmtpConfigMessage struct {
	resp chan *SmtpConfig
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

type getDisplayNameMessage struct {
	resp chan string
}

func (s *JsonStorage) GetDisplayName() string {
	ch := make(chan string)
	s.message_chan <- getDisplayNameMessage{
		resp: ch,
	}
	return <-ch
}

type setDisplayNameMessage struct {
	value string
	resp  chan error
}

func (s *JsonStorage) SetDisplayName(value string) {
	resp := make(chan error)
	s.message_chan <- setDisplayNameMessage{
		value,
		resp,
	}
	<-resp
}

func (s *JsonStorage) Persist() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	saveJson(s, s.path)
}

func (s *JsonStorage) persist() {
	saveJson(s, s.path)
}

func (s *JsonStorage) SetFedCmEnable(enable bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.FedCmEnabled = enable
	s.persist()
}
func (s *JsonStorage) GetFedCmEnabled() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.FedCmEnabled
}

func (s *JsonStorage) SetForwardAuthPassthrough(enable bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.ForwardAuthPassthrough = enable
	s.persist()
}
func (s *JsonStorage) GetForwardAuthPassthrough() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.ForwardAuthPassthrough
}
