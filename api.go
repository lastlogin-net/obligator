package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/mail"
	"os"
)

type Api struct {
}

func NewApi(storage *Storage) (*Api, error) {

	mux := http.NewServeMux()

	mux.HandleFunc("/root_uri", func(w http.ResponseWriter, r *http.Request) {
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
			users := storage.GetUsers()
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

	sockPath := "./obligator.sock"

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
