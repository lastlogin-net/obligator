package main

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type Storage struct {
	Users         map[string]*User      `json:"users"`
	Identities    []*Identity           `json:"identities"`
	LoginData     map[string]*LoginData `json:"login_data"`
	requests      map[string]*OAuth2AuthRequest
	pendingTokens map[string]string
	mutex         *sync.Mutex
	path          string
}

type User struct {
}

type Identity struct {
	Id         string `json:"id"`
	ProviderId string `json:"provider_id"`
	OwnerId    string `json:"owner_id"`
	Email      string `json:"email"`
}

type LoginData struct {
	OwnerId string `json:"owner_id"`
}

func NewFileStorage(path string) (*Storage, error) {
	s := &Storage{
		Users:         make(map[string]*User),
		Identities:    []*Identity{},
		LoginData:     make(map[string]*LoginData),
		requests:      make(map[string]*OAuth2AuthRequest),
		pendingTokens: make(map[string]string),
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

func (s *Storage) AddIdentity(ownerId, providerId, email string) (string, error) {
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
		Id:         id,
		ProviderId: providerId,
		OwnerId:    ownerId,
		Email:      email,
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

func (s *Storage) AddPendingToken(token string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	code, err := genRandomKey()
	if err != nil {
		return "", err
	}

	s.pendingTokens[code] = token

	s.persist()

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
