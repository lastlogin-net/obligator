package obligator

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
)

type footerData struct {
	RootUri string
}

type IndieAuthHandler struct {
	mux *http.ServeMux
}

type IndieAuthProfile struct {
	MeUri string `json:"me"`
}

func NewIndieAuthHandler(storage Storage, tmpl *template.Template, prefix string) *IndieAuthHandler {

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("catchall: " + r.URL.Path)
	})

	handleToken := func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/token")

		r.ParseForm()

		code := r.Form.Get("code")

		if code != "dummy-code" {
			w.WriteHeader(400)
			io.WriteString(w, "Invalid code")
			return
		}

		profile := IndieAuthProfile{
			MeUri: fmt.Sprintf("%s/users/dummy-user", storage.GetRootUri()),
		}

		err := json.NewEncoder(w).Encode(profile)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

	}

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/auth")

		if r.Method == "POST" {
			handleToken(w, r)
			return
		}

		ar, err := ParseAuthRequest(w, r)
		if err != nil {
			return
		}

		uri := fmt.Sprintf("%s?code=%s&state=%s",
			ar.RedirectUri,
			"dummy-code",
			ar.State)

		http.Redirect(w, r, uri, 302)
	})

	mux.HandleFunc("/token", handleToken)

	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/users/")

		uri := fmt.Sprintf("%s/.well-known/oauth-authorization-server", storage.GetRootUri())
		link := fmt.Sprintf("<%s>; rel=\"indieauth-metadata\"", uri)
		w.Header().Set("Link", link)
		w.Header().Set("Content-Type", "text/html")

		data := struct {
			RootUri string
		}{
			RootUri: storage.GetRootUri(),
		}

		err := tmpl.ExecuteTemplate(w, "user.html", data)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/.well-known/oauth-authorization-server")

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		rootUri := storage.GetRootUri()

		meta := OAuth2ServerMetadata{
			Issuer:                        rootUri,
			AuthorizationEndpoint:         fmt.Sprintf("%s%s/auth", rootUri, prefix),
			TokenEndpoint:                 fmt.Sprintf("%s%s/token", rootUri, prefix),
			IntrospectionEndpoint:         fmt.Sprintf("%s%s/introspect", rootUri, prefix),
			CodeChallengeMethodsSupported: []string{"S256"},
		}

		err := json.NewEncoder(w).Encode(meta)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	h := &IndieAuthHandler{
		mux: mux,
	}

	return h
}

func (h *IndieAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}
