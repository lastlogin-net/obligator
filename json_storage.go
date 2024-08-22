package obligator

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type Config JsonStorage

type JsonStorage struct {
	Smtp         *SmtpConfig `json:"smtp"`
	mutex        *sync.Mutex
	path         string
	message_chan chan interface{}
}

func NewJsonStorage(path string) (*JsonStorage, error) {
	s := &JsonStorage{
		mutex:        &sync.Mutex{},
		path:         path,
		message_chan: make(chan interface{}),
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

func (s *JsonStorage) Persist() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	saveJson(s, s.path)
}

func (s *JsonStorage) persist() {
	saveJson(s, s.path)
}
