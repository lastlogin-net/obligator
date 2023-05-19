package main

import (
	"errors"
	"sync"
)

type Storage struct {
	requests      map[string]*OAuth2AuthRequest
	pendingTokens map[string]string
	mutex         *sync.Mutex
}

func NewStorage() *Storage {
	s := &Storage{
		requests:      make(map[string]*OAuth2AuthRequest),
		pendingTokens: make(map[string]string),
		mutex:         &sync.Mutex{},
	}

	return s
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
