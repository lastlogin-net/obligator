package obligator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type IndieAuthHandler struct {
	mux *http.ServeMux
}

func NewIndieAuthHandler(storage Storage, prefix string) *IndieAuthHandler {

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL.Path)
	})

	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/users/")

		uri := fmt.Sprintf("%s/.well-known/oauth-authorization-server", storage.GetRootUri())
		link := fmt.Sprintf("<%s>; rel=\"indieauth-metadata\"", uri)
		w.Header().Set("Link", link)
		w.Header().Set("Content-Type", "text/html")

		tmpl := `
                <!DOCTYPE html>
                <html>
                  <head>
                    <link rel="indieauth-metadata" href="%s">
                  </head>
                  <body>
                  </body>
                </html>
                `

		html := fmt.Sprintf(tmpl, uri)
		io.WriteString(w, html)
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
