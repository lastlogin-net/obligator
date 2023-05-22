package main

import (
	"errors"
	"sync"
)

type Storage struct {
	Users         map[string]*User
	Identities    []*Identity
	requests      map[string]*OAuth2AuthRequest
	pendingTokens map[string]string
	mutex         *sync.Mutex
}

type User struct {
}

type Identity struct {
	Id         string `json:"id"`
	ProviderId string `json:"provider_id"`
	OwnerId    string `json:"owner"`
}

func NewFileStorage() *Storage {
	s := &Storage{
		Users:         make(map[string]*User),
		Identities:    []*Identity{},
		requests:      make(map[string]*OAuth2AuthRequest),
		pendingTokens: make(map[string]string),
		mutex:         &sync.Mutex{},
	}

	return s
}

func (s *Storage) AddIdentity(ownerId, providerId string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	id, err := genRandomKey()
	if err != nil {
		return "", err
	}

	identity := &Identity{
		Id:         id,
		ProviderId: providerId,
		OwnerId:    ownerId,
	}

	s.Identities = append(s.Identities, identity)

	return id, nil
}

func (s *Storage) AddRequest(req OAuth2AuthRequest) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	requestId, err := genRandomKey()
	if err != nil {
		return "", err
	}

	s.requests[requestId] = &req

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
}

func (s *Storage) AddPendingToken(token string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	code, err := genRandomKey()
	if err != nil {
		return "", err
	}

	s.pendingTokens[code] = token

	return code, nil
}
func (s *Storage) GetPendingToken(code string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, ok := s.pendingTokens[code]
	if !ok {
		return token, errors.New("No token for code")
	}

	return token, nil
}
