package main

import (
	"errors"
	"sync"
)

type Storage struct {
	requests map[string]*OAuth2AuthRequest
	mutex    *sync.Mutex
}

func NewStorage() *Storage {
	s := &Storage{
		requests: make(map[string]*OAuth2AuthRequest),
		mutex:    &sync.Mutex{},
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
