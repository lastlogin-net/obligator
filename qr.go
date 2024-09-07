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
	*commonData
	QrKey        string
	InstanceId   string
	ErrorMessage string
}

func (h *QrHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

const checkboxPrefix = "checkbox_"

func NewQrHandler(db Database, cluster *Cluster, tmpl *template.Template, jose *JOSE) *QrHandler {

	pendingShares := make(map[string]PendingShare)
	mut := &sync.Mutex{}

	mux := http.NewServeMux()

	h := &QrHandler{
		mux,
	}

	const ShareTimeout = 2 * time.Minute

	prefix, err := db.GetPrefix()
	checkErr(err)

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

		rootUri := domainToUri(r.Host)
		qrUrl := fmt.Sprintf("%s/qr?key=%s&instance_id=%s", rootUri, qrKey, cluster.GetLocalId())

		qrCode, err := qrcode.Encode(qrUrl, qrcode.Medium, 256)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		qrPng := base64.StdEncoding.EncodeToString(qrCode)
		qrDataUri := template.URL("data:image/png;base64," + qrPng)

		templateData := struct {
			*commonData
			QrDataUri    template.URL
			QrKey        string
			ErrorMessage string
		}{
			commonData:   newCommonData(nil, db, r),
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

	mux.HandleFunc("/qr", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		qrKey := r.Form.Get("key")
		instanceId := r.Form.Get("instance_id")

		templateData := QrTemplateData{
			commonData:   newCommonData(nil, db, r),
			QrKey:        qrKey,
			InstanceId:   instanceId,
			ErrorMessage: "",
		}

		err := tmpl.ExecuteTemplate(w, "qr.html", templateData)
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

		identities, _ := getIdentities(db, r)

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

		logins, loginsErr := getLogins(db, r)
		copyLogins := r.Form.Get("checkbox_share_logins") == "on"

		if loginsErr == nil && copyLogins {
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
				commonData:   newCommonData(nil, db, r),
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

		templateData := struct {
			*commonData
		}{
			commonData: newCommonData(nil, db, r),
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

		serverUri := domainToUri(r.Host)

		mut.Lock()
		share, exists := pendingShares[qrKey]
		mut.Unlock()
		if !exists {
			w.WriteHeader(400)

			qrUrl := fmt.Sprintf("%s/qr/%s", serverUri, qrKey)

			qrCode, err := qrcode.Encode(qrUrl, qrcode.Medium, 256)
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}

			qrPng := base64.StdEncoding.EncodeToString(qrCode)
			qrDataUri := template.URL("data:image/png;base64," + qrPng)

			templateData := struct {
				*commonData
				QrKey        string
				QrDataUri    template.URL
				ErrorMessage string
			}{
				commonData:   newCommonData(nil, db, r),
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
			cookie, err = addIdentToCookie(r.Host, db, cookie.Value, ident, jose)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(os.Stderr, err.Error())
				return
			}
		}

		for clientId, clientLogins := range share.Logins {
			for _, login := range clientLogins {
				cookie, err = addLoginToCookie(r.Host, db, cookie.Value, clientId, login, jose)
				if err != nil {
					w.WriteHeader(500)
					fmt.Fprintf(os.Stderr, err.Error())
					return
				}
			}
		}

		http.SetCookie(w, cookie)

		returnUri, err := getReturnUriCookie(db, r)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}
		deleteReturnUriCookie(r.Host, db, w)

		redirUrl := fmt.Sprintf("%s", returnUri)

		http.Redirect(w, r, redirUrl, http.StatusSeeOther)
	})

	return h
}
