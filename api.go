package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
)

type Api struct {
}

func NewApi(storage Storage, dir string) (*Api, error) {

	mux := http.NewServeMux()

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

			if prov.ID == "" {
				w.WriteHeader(400)
				io.WriteString(w, "Missing ID")
				return
			}

			if prov.Name == "" {
				w.WriteHeader(400)
				io.WriteString(w, "Missing name")
				return
			}

			if prov.URI == "" {
				w.WriteHeader(400)
				io.WriteString(w, "Missing URI")
				return
			}

			if prov.ClientID == "" {
				w.WriteHeader(400)
				io.WriteString(w, "Missing client_id")
				return
			}

			err = storage.SetOauth2Provider(prov)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}

			updateOidcConfigs(storage)
		}
	})

	mux.HandleFunc("/root-uri", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			r.ParseForm()
			rootUri := r.Form.Get("root_uri")
			if rootUri == "" {
				w.WriteHeader(400)
				io.WriteString(w, "Missing root_uri")
				return
			}

			err := storage.SetRootUri(rootUri)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}
		}
	})

	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			users, err := storage.GetUsers()
			if err != nil {
				w.WriteHeader(400)
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

			_, err = mail.ParseAddress(user.Email)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}

			err = storage.CreateUser(user)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}
		}
	})

	server := http.Server{
		Handler: mux,
	}

	sockPath := filepath.Join(dir, "obligator_api.sock")

	os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	go func() {
		server.Serve(listener)
	}()

	a := &Api{}
	return a, nil
}
