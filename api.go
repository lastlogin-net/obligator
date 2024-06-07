package obligator

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
)

type Api struct {
	storage       Storage
	oauth2MetaMan *OAuth2MetadataManager
}

func NewApi(storage Storage, dir string, oauth2MetaMan *OAuth2MetadataManager) (*Api, error) {

	mux := http.NewServeMux()

	a := &Api{
		storage,
		oauth2MetaMan,
	}

	mux.HandleFunc("/oauth2-providers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			providers, err := storage.GetOAuth2Providers()
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}
			json.NewEncoder(w).Encode(providers)
		}
	})

	mux.HandleFunc("/oauth2-providers/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			pathParts := strings.Split(r.URL.Path, "/")

			if len(pathParts) > 3 {
				w.WriteHeader(400)
				io.WriteString(w, "Too many path segments")
				return
			}

			providerId := pathParts[2]

			if providerId == "" {
				w.WriteHeader(400)
				io.WriteString(w, "Missing provider ID")
				return
			}

			var prov OAuth2Provider

			err := json.NewDecoder(r.Body).Decode(&prov)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}

			err = a.SetOAuth2Provider(prov)
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}

		}
	})

	//mux.HandleFunc("/root-uri", func(w http.ResponseWriter, r *http.Request) {
	//	switch r.Method {
	//	case "PUT":
	//		r.ParseForm()
	//		rootUri := r.Form.Get("root_uri")
	//		if rootUri == "" {
	//			w.WriteHeader(400)
	//			io.WriteString(w, "Missing root_uri")
	//			return
	//		}

	//		err := storage.SetRootUri(rootUri)
	//		if err != nil {
	//			w.WriteHeader(400)
	//			io.WriteString(w, err.Error())
	//			return
	//		}
	//	}
	//})

	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			users, err := a.GetUsers()
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}

			json.NewEncoder(w).Encode(users)
		case "POST":
			var user User
			err := json.NewDecoder(r.Body).Decode(&user)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}

			err = a.AddUser(user)
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}
		}
	})

	server := http.Server{
		Handler: mux,
	}

	sockPath := filepath.Join(dir, storage.GetPrefix()+"api.sock")

	os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	go func() {
		server.Serve(listener)
	}()

	return a, nil
}

func (a *Api) SetOAuth2Provider(prov OAuth2Provider) error {
	if prov.ID == "" {
		return errors.New("Missing ID")
	}

	if prov.Name == "" {
		return errors.New("Missing name")
	}

	if prov.URI == "" {
		return errors.New("Missing URI")
	}

	if prov.ClientID == "" {
		return errors.New("Missing client_id")
	}

	err := a.storage.SetOauth2Provider(prov)
	if err != nil {
		return err
	}

	err = a.oauth2MetaMan.Update()
	if err != nil {
		return err
	}

	return nil
}

func (a *Api) AddUser(user User) error {
	_, err := mail.ParseAddress(user.Email)
	if err != nil {
		return err
	}

	err = a.storage.CreateUser(user)
	if err != nil {
		return err
	}
	return nil
}

func (a *Api) GetUsers() ([]User, error) {

	users, err := a.storage.GetUsers()
	if err != nil {
		return nil, err
	}

	return users, nil
}
