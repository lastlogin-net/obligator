package obligator

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type IndieAuthHandler struct {
	mux *http.ServeMux
}

type IndieAuthProfile struct {
	MeUri string `json:"me"`
}

func NewIndieAuthHandler(db *Database, storage Storage, tmpl *template.Template, prefix string) *IndieAuthHandler {

	mux := http.NewServeMux()

	publicJwks, err := jwk.PublicSetOf(storage.GetJWKSet())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cookiePrefix := storage.GetPrefix()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("catchall: " + r.URL.Path)
	})

	handleToken := func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/token")

		r.ParseForm()

		codeJwt := r.Form.Get("code")

		parsedCodeJwt, err := jwt.Parse([]byte(codeJwt), jwt.WithKeySet(publicJwks))
		if err != nil {
			fmt.Println(err.Error())
			w.WriteHeader(401)
			io.WriteString(w, err.Error())
			return
		}

		printJson(parsedCodeJwt)

		domain := claimFromToken("domain", parsedCodeJwt)
		if domain != r.Host {
			w.WriteHeader(400)
			io.WriteString(w, "Invalid domain")
			return
		}

		pkceCodeChallenge, exists := parsedCodeJwt.Get("pkce_code_challenge")
		if !exists {
			w.WriteHeader(401)
			io.WriteString(w, "Invalid pkce_code_challenge in code")
			return
		}

		// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.8.2
		// draft-ietf-oauth-security-topics-24 2.1.1
		pkceCodeVerifier := r.Form.Get("code_verifier")
		if pkceCodeChallenge != "" {
			challenge := GeneratePKCECodeChallenge(pkceCodeVerifier)
			if challenge != pkceCodeChallenge {
				w.WriteHeader(401)
				io.WriteString(w, "Invalid code_verifier")
				return
			}
		} else {
			if pkceCodeVerifier != "" {
				w.WriteHeader(401)
				io.WriteString(w, "code_verifier provided for request that did not include code_challenge")
				return
			}
		}

		profile := IndieAuthProfile{
			MeUri: domainToUri(r.Host),
		}

		printJson(profile)

		w.Header().Set("Content-Type", "application/json")

		err = json.NewEncoder(w).Encode(profile)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	}

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {

		if r.Method == "POST" {
			handleToken(w, r)
			return
		}

		ar, err := ParseAuthRequest(w, r)
		if err != nil {
			return
		}

		domain, err := db.GetDomain(r.Host)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		idents, _ := getIdentities(storage, r, publicJwks)

		var matchIdent *Identity = nil
		for _, ident := range idents {
			if domain.HashedOwnerId == Hash(ident.Id) {
				matchIdent = ident
				break
			}
		}

		if matchIdent == nil {
			w.WriteHeader(401)
			msg := fmt.Sprintf("You don't have permission to log in as %s", r.Host)
			io.WriteString(w, msg)
			return
		}

		maxAge := 8 * time.Minute
		issuedAt := time.Now().UTC()
		authRequestJwt, err := jwt.NewBuilder().
			IssuedAt(issuedAt).
			Expiration(issuedAt.Add(maxAge)).
			Claim("client_id", ar.ClientId).
			Claim("redirect_uri", ar.RedirectUri).
			Claim("state", ar.State).
			Claim("scope", r.Form.Get("scope")).
			Claim("nonce", r.Form.Get("nonce")).
			Claim("pkce_code_challenge", r.Form.Get("code_challenge")).
			Claim("response_type", ar.ResponseType).
			Build()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		setJwtCookie(r.Host, storage, authRequestJwt, cookiePrefix+"auth_request", maxAge, w, r)

		data := struct {
			*commonData
			ClientId string
		}{
			commonData: newCommonData(&commonData{
				Identities: idents,
			}, storage, r),
			ClientId: ar.ClientId,
		}

		err = tmpl.ExecuteTemplate(w, "indieauth.html", data)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

	})

	mux.HandleFunc("/confirm", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/indieauth/confirm")

		clearCookie(r.Host, storage, cookiePrefix+"auth_request", w)

		parsedAuthReq, err := getJwtFromCookie(cookiePrefix+"auth_request", storage, w, r)
		if err != nil {
			w.WriteHeader(401)
			io.WriteString(w, err.Error())
			return
		}

		printJson(parsedAuthReq)

		issuedAt := time.Now().UTC()
		codeJwt, err := jwt.NewBuilder().
			IssuedAt(issuedAt).
			Expiration(issuedAt.Add(16*time.Second)).
			//Subject(idToken.Email()).
			Claim("domain", r.Host).
			Claim("pkce_code_challenge", claimFromToken("pkce_code_challenge", parsedAuthReq)).
			Build()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		key, exists := storage.GetJWKSet().Key(0)
		if !exists {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, "No keys available")
			return
		}

		signedCode, err := jwt.Sign(codeJwt, jwt.WithKey(jwa.RS256, key))
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		uri := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&code=%s&state=%s&scope=%s",
			claimFromToken("redirect_uri", parsedAuthReq),
			claimFromToken("client_id", parsedAuthReq),
			claimFromToken("redirect_uri", parsedAuthReq),
			string(signedCode),
			claimFromToken("state", parsedAuthReq),
			claimFromToken("scope", parsedAuthReq))

		http.Redirect(w, r, uri, 302)
	})

	mux.HandleFunc("/token", handleToken)

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("/.well-known/oauth-authorization-server")

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")

		rootUri := domainToUri(r.Host)

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
