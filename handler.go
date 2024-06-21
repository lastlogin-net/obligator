package obligator

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
)

type Handler struct {
	mux *http.ServeMux
}

func NewHandler(db *Database, storage Storage, conf ServerConfig, tmpl *template.Template) *Handler {

	mux := http.NewServeMux()

	h := &Handler{
		mux: mux,
	}

	var err error

	fsHandler := http.FileServer(http.Dir("static"))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		domain, err := db.GetDomain(r.Host)
		if err != nil {
			fsHandler.ServeHTTP(w, r)
			return
		}

		if domain.HashedOwnerId == Hash("root") {
			fsHandler.ServeHTTP(w, r)
			return
		}

		uri := fmt.Sprintf("%s/.well-known/oauth-authorization-server", domainToUri(r.Host))
		link := fmt.Sprintf("<%s>; rel=\"indieauth-metadata\"", uri)
		w.Header().Set("Link", link)

		tmplData := newCommonData(nil, storage, r)

		err = tmpl.ExecuteTemplate(w, "user.html", tmplData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

	})

	mux.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		if conf.LogoPng != nil {
			w.Header()["Content-Type"] = []string{"image/png"}
			w.Header()["Cache-Control"] = []string{"max-age=86400"}
			w.Write(conf.LogoPng)
			return
		} else {
			fsHandler.ServeHTTP(w, r)
		}
	})

	mux.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
		remoteIp, err := getRemoteIp(r, conf.BehindProxy)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		data := struct {
			*commonData
			RemoteIp string
		}{
			commonData: newCommonData(nil, storage, r),
			RemoteIp:   remoteIp,
		}

		err = tmpl.ExecuteTemplate(w, "ip.html", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	// TODO: probably needs to be combined with the API somehow, but the
	// API currently only works over a unix socket for security.
	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		authServer := r.Form.Get("auth_server")

		redirectUri := r.Form.Get("redirect_uri")
		url := fmt.Sprintf("%s/auth?client_id=%s&redirect_uri=%s&response_type=code&state=&scope=",
			domainToUri(authServer), redirectUri, redirectUri)

		validation, err := validate(storage, r)
		if err != nil {
			fmt.Println(err)
			http.Redirect(w, r, url, 307)
			return
		}

		if validation != nil {
			w.Header().Set("Remote-Id-Type", validation.IdType)
			w.Header().Set("Remote-Id", validation.Id)
		} else {
			w.Header().Set("Remote-Id-Type", "")
			w.Header().Set("Remote-Id", "")
		}
	})

	loginFunc := func(w http.ResponseWriter, r *http.Request, fedCm bool) {

		r.ParseForm()

		canEmail := true
		if _, err := storage.GetSmtpConfig(); err != nil {
			canEmail = false
		}

		providers, err := storage.GetOAuth2Providers()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		returnUri := r.Form.Get("return_uri")

		if returnUri == "" {
			returnUri = "/login"

			if fedCm {
				returnUri = "/login-fedcm-auto"
			}
		} else {
			parsedUrl, err := url.Parse(returnUri)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}

			// Prevent open redirect by verifying the return
			// domain is in our database.
			_, err = db.GetDomain(parsedUrl.Host)
			if err != nil {
				w.WriteHeader(403)
				io.WriteString(w, err.Error())
				return
			}
		}

		setReturnUriCookie(r.Host, storage, returnUri, w)

		data := struct {
			*commonData
			CanEmail        bool
			OAuth2Providers []OAuth2Provider
			LogoMap         map[string]template.HTML
			FedCm           bool
		}{
			commonData: newCommonData(&commonData{
				ReturnUri: returnUri,
			}, storage, r),
			CanEmail:        canEmail,
			OAuth2Providers: providers,
			LogoMap:         providerLogoMap,
			FedCm:           fedCm,
		}

		err = tmpl.ExecuteTemplate(w, "login.html", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	}

	mux.HandleFunc("/login-fedcm-auto", func(w http.ResponseWriter, r *http.Request) {
		loginFunc(w, r, true)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginFunc(w, r, false)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		redirect := r.Form.Get("prev_page")

		err = deleteLoginKeyCookie(r.Host, storage, w)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
		}

		w.Header().Add("Set-Login", "logged-out")
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	})

	mux.HandleFunc("/no-account", func(w http.ResponseWriter, r *http.Request) {

		data := struct {
			*commonData
		}{
			commonData: newCommonData(nil, storage, r),
		}

		err = tmpl.ExecuteTemplate(w, "no-account.html", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		printJson(r.Header)
	})

	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}
