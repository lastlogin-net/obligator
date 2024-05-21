package obligator

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/skip2/go-qrcode"
)

type QrHandler struct {
	mux *http.ServeMux
}

type PendingShare struct {
	Identities []*Identity         `json:"identities"`
	Logins     map[string][]*Login `json:"logins"`
	ExpiresAt  time.Time
}

type QrTemplateData struct {
	DisplayName  string
	RootUri      string
	Identities   []*Identity
	QrKey        string
	InstanceId   string
	ErrorMessage string
	ReturnUri    string
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

	const ShareTimeout = 2 * time.Minute

	prefix := storage.GetPrefix()
	loginKeyName := prefix + "login_key"

	// Periodically clean up expired shares
	go func() {
		for {
			newMap := make(map[string]PendingShare)
			mut.Lock()
			for k, v := range pendingShares {
				newMap[k] = v
			}
			mut.Unlock()

			for key, pending := range newMap {
				if time.Now().UTC().After(pending.ExpiresAt) {
					mut.Lock()
					delete(pendingShares, key)
					mut.Unlock()
				}
			}
			time.Sleep(ShareTimeout)
		}
	}()

	mux.HandleFunc("/login-qr", func(w http.ResponseWriter, r *http.Request) {

		qrKey, err := genRandomKey()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		qrUrl := fmt.Sprintf("%s/qr?key=%s&instance_id=%s", storage.GetRootUri(), qrKey, cluster.GetLocalId())

		qrCode, err := qrcode.Encode(qrUrl, qrcode.Medium, 256)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		qrPng := base64.StdEncoding.EncodeToString(qrCode)
		qrDataUri := template.URL("data:image/png;base64," + qrPng)

		idents, _ := getIdentities(storage, r, publicJwks)

		templateData := struct {
			DisplayName  string
			RootUri      string
			QrDataUri    template.URL
			QrKey        string
			ErrorMessage string
			Identities   []*Identity
		}{
			DisplayName:  storage.GetDisplayName(),
			RootUri:      storage.GetRootUri(),
			QrDataUri:    qrDataUri,
			QrKey:        qrKey,
			ErrorMessage: "",
			Identities:   idents,
		}

		err = tmpl.ExecuteTemplate(w, "login-qr.html", templateData)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/qr", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		qrKey := r.Form.Get("key")
		instanceId := r.Form.Get("instance_id")

		identities := []*Identity{}

		loginKeyCookie, err := r.Cookie(loginKeyName)
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

		templateData := QrTemplateData{
			DisplayName:  storage.GetDisplayName(),
			RootUri:      storage.GetRootUri(),
			Identities:   identities,
			QrKey:        qrKey,
			InstanceId:   instanceId,
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
		ogInstanceId := r.Form.Get("instance_id")

		if ogInstanceId != cluster.GetLocalId() {
			cluster.RedirectOrForward(ogInstanceId, w, r)
			return
		}

		identities := []*Identity{}
		logins := make(map[string][]*Login)

		loginKeyCookie, err := r.Cookie(loginKeyName)
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

				tokLoginsInterface, exists := parsed.Get("logins")
				if exists {
					if tokLogins, ok := tokLoginsInterface.(map[string][]*Login); ok {
						logins = tokLogins
					}
				}
			}

		}

		share := PendingShare{
			Identities: []*Identity{},
			Logins:     map[string][]*Login{},
			ExpiresAt:  time.Now().UTC().Add(ShareTimeout),
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

		copyLogins := r.Form.Get("checkbox_share_logins") == "on"

		if copyLogins {
			for _, ident := range share.Identities {
				for clientId, clientLogins := range logins {
					for _, clientLogin := range clientLogins {
						if clientLogin.Id == ident.Id {
							share.Logins[clientId] = append(share.Logins[clientId], &(*clientLogin))
						}
					}
				}
			}
		}

		if len(share.Identities) == 0 {

			w.WriteHeader(400)

			templateData := QrTemplateData{
				DisplayName:  storage.GetDisplayName(),
				RootUri:      storage.GetRootUri(),
				Identities:   identities,
				QrKey:        qrKey,
				InstanceId:   ogInstanceId,
				ErrorMessage: "You must select at least one identity",
			}

			err = tmpl.ExecuteTemplate(w, "qr.html", templateData)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				fmt.Println(err)
				return
			}

			return
		}

		mut.Lock()
		defer mut.Unlock()
		pendingShares[qrKey] = share

		idents, _ := getIdentities(storage, r, publicJwks)

		templateData := struct {
			DisplayName string
			RootUri     string
			Identities  []*Identity
			ReturnUri   string
		}{
			DisplayName: storage.GetDisplayName(),
			RootUri:     storage.GetRootUri(),
			Identities:  idents,
		}

		returnUri := r.Form.Get("return_uri")
		setReturnUriCookie(storage, returnUri, w)

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
		loginKeyCookie, err := r.Cookie(loginKeyName)
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

		for clientId, clientLogins := range share.Logins {
			for _, login := range clientLogins {
				cookie, err = addLoginToCookie(storage, cookie.Value, clientId, login)
				if err != nil {
					w.WriteHeader(500)
					fmt.Fprintf(os.Stderr, err.Error())
					return
				}
			}
		}

		http.SetCookie(w, cookie)

		returnUri, err := getReturnUriCookie(storage, r)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}
		deleteReturnUriCookie(storage, w)

		redirUrl := fmt.Sprintf("%s", returnUri)

		http.Redirect(w, r, redirUrl, http.StatusSeeOther)
	})

	return h
}
