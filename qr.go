package main

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/skip2/go-qrcode"
)

type QrHandler struct {
	mux *http.ServeMux
}

type PendingShare struct {
	Identities []*Identity `json:"identities"`
}

func (h *QrHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

const checkboxPrefix = "checkbox_"

func NewQrHandler(storage Storage, cluster *Cluster, tmpl *template.Template) *QrHandler {

	pendingShares := make(map[string]PendingShare)
	mut := &sync.Mutex{}

	mux := http.NewServeMux()

	h := &QrHandler{
		mux,
	}

	publicJwks, err := jwk.PublicSetOf(storage.GetJWKSet())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	mux.HandleFunc("/login-qr", func(w http.ResponseWriter, r *http.Request) {

		qrKey, err := genRandomKey()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		qrUrl := fmt.Sprintf("%s/qr/%s", storage.GetRootUri(), qrKey)

		qrCode, err := qrcode.Encode(qrUrl, qrcode.Medium, 256)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		qrPng := base64.StdEncoding.EncodeToString(qrCode)
		qrDataUri := template.URL("data:image/png;base64," + qrPng)

		templateData := struct {
			DisplayName  string
			RootUri      string
			QrDataUri    template.URL
			QrKey        string
			ErrorMessage string
		}{
			DisplayName:  storage.GetDisplayName(),
			RootUri:      storage.GetRootUri(),
			QrDataUri:    qrDataUri,
			QrKey:        qrKey,
			ErrorMessage: "",
		}

		err = tmpl.ExecuteTemplate(w, "login-qr.html", templateData)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/qr/", func(w http.ResponseWriter, r *http.Request) {

		pathParts := strings.Split(r.URL.Path, "/")
		qrKey := pathParts[len(pathParts)-1]

		identities := []*Identity{}

		loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
		if err == nil && loginKeyCookie.Value != "" {
			parsed, err := jwt.Parse([]byte(loginKeyCookie.Value), jwt.WithKeySet(publicJwks))
			if err != nil {
				w.WriteHeader(401)
				io.WriteString(w, err.Error())
				return
			} else {
				tokIdentsInterface, exists := parsed.Get("identities")
				if exists {
					if tokIdents, ok := tokIdentsInterface.([]*Identity); ok {
						identities = tokIdents
					}
				}
			}

		}

		templateData := struct {
			DisplayName  string
			RootUri      string
			Identities   []*Identity
			QrKey        string
			ErrorMessage string
		}{
			DisplayName:  storage.GetDisplayName(),
			RootUri:      storage.GetRootUri(),
			Identities:   identities,
			QrKey:        qrKey,
			ErrorMessage: "",
		}

		err = tmpl.ExecuteTemplate(w, "qr.html", templateData)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		qrKey := r.Form.Get("qr_key")

		identities := []*Identity{}

		loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
		if err == nil && loginKeyCookie.Value != "" {
			parsed, err := jwt.Parse([]byte(loginKeyCookie.Value), jwt.WithKeySet(publicJwks))
			if err != nil {
				w.WriteHeader(401)
				io.WriteString(w, err.Error())
				return
			} else {
				tokIdentsInterface, exists := parsed.Get("identities")
				if exists {
					if tokIdents, ok := tokIdentsInterface.([]*Identity); ok {
						identities = tokIdents
					}
				}
			}

		}

		share := PendingShare{
			Identities: []*Identity{},
		}

		for key, value := range r.Form {
			if strings.HasPrefix(key, checkboxPrefix) && len(value) > 0 && value[0] == "on" {
				id := key[len(checkboxPrefix):]
				for _, ident := range identities {
					if ident.Id == id {
						share.Identities = append(share.Identities, &(*ident))
					}
				}
			}
		}

		if len(share.Identities) == 0 {

			w.WriteHeader(400)

			templateData := struct {
				DisplayName  string
				RootUri      string
				Identities   []*Identity
				QrKey        string
				ErrorMessage string
			}{
				DisplayName:  storage.GetDisplayName(),
				RootUri:      storage.GetRootUri(),
				Identities:   identities,
				QrKey:        qrKey,
				ErrorMessage: "You must select at least one identity",
			}

			err = tmpl.ExecuteTemplate(w, "qr.html", templateData)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}

			return
		}

		mut.Lock()
		defer mut.Unlock()
		pendingShares[qrKey] = share

		templateData := struct {
			DisplayName string
			RootUri     string
		}{
			DisplayName: storage.GetDisplayName(),
			RootUri:     storage.GetRootUri(),
		}

		err = tmpl.ExecuteTemplate(w, "send-success.html", templateData)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/receive", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		qrKey := r.Form.Get("qr_key")

		mut.Lock()
		share, exists := pendingShares[qrKey]
		mut.Unlock()
		if !exists {
			w.WriteHeader(400)

			qrUrl := fmt.Sprintf("%s/qr/%s", storage.GetRootUri(), qrKey)

			qrCode, err := qrcode.Encode(qrUrl, qrcode.Medium, 256)
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}

			qrPng := base64.StdEncoding.EncodeToString(qrCode)
			qrDataUri := template.URL("data:image/png;base64," + qrPng)

			templateData := struct {
				DisplayName  string
				RootUri      string
				QrKey        string
				QrDataUri    template.URL
				ErrorMessage string
			}{
				DisplayName:  storage.GetDisplayName(),
				RootUri:      storage.GetRootUri(),
				QrKey:        qrKey,
				QrDataUri:    qrDataUri,
				ErrorMessage: "No share found. Make sure you've scanned the QR code on the sharing device and confirmed",
			}

			err = tmpl.ExecuteTemplate(w, "login-qr.html", templateData)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}

			return
		}

		cookie := &http.Cookie{}
		loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
		if err == nil {
			cookie = loginKeyCookie
		}

		for _, ident := range share.Identities {
			cookie, err = addIdentToCookie(storage, cookie.Value, ident)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}
		}

		http.SetCookie(w, cookie)

		authRequest, err := getJwtFromCookie("obligator_auth_request", storage, w, r)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		redirUrl := fmt.Sprintf("%s/auth?%s", storage.GetRootUri(), claimFromToken("raw_query", authRequest))

		http.Redirect(w, r, redirUrl, http.StatusSeeOther)
	})

	return h
}
