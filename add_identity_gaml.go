package obligator

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

type AddIdentityGamlHandler struct {
	mux *http.ServeMux
}

func NewAddIdentityGamlHandler(db Database, cluster *Cluster, tmpl *template.Template, jose *JOSE) *AddIdentityGamlHandler {
	mux := http.NewServeMux()

	h := &AddIdentityGamlHandler{
		mux: mux,
	}

	httpClient := &http.Client{}
	// TODO: clean up old codes
	pendingCodes := make(map[string]string)
	mut := &sync.Mutex{}

	prefix, err := db.GetPrefix()
	checkErr(err)

	mux.HandleFunc("/login-gaml", func(w http.ResponseWriter, r *http.Request) {

		templateData := struct {
			*commonData
		}{
			commonData: newCommonData(nil, db, r),
		}

		err := tmpl.ExecuteTemplate(w, "login-gaml.html", templateData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/gaml-code", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		urlParam := r.Form.Get("url")
		if urlParam == "" {
			w.WriteHeader(400)
			io.WriteString(w, "url param missing")
			return
		}

		parsedUrl, err := url.Parse(urlParam)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		urlId := fmt.Sprintf("%s%s", parsedUrl.Host, parsedUrl.Path)

		// It's important to retrieve the value of the previous code
		// and verify that it changes during this process. Otherwise
		// an attacker could read the old code and use it to log it.
		oldCode, err := retrieveCode(urlId, httpClient, w)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		gamlCode := oldCode

		i := 0
		maxIter := 1024
		for {
			gamlCode, err = genRandomCode()
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}

			if gamlCode != oldCode {
				break
			}

			i += 1
			if i > maxIter {
				w.WriteHeader(500)
				io.WriteString(w, "Failed to generate a new code")
				return
			}
		}

		issuedAt := time.Now().UTC()
		maxAge := 2 * time.Minute
		reqJwt, err := NewJWTBuilder().
			IssuedAt(issuedAt).
			Expiration(issuedAt.Add(maxAge)).
			Claim("url", urlId).
			Claim("instance_id", cluster.GetLocalId()).
			Build()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		setJwtCookie(db, r.Host, reqJwt, prefix+"_gaml_login_state", maxAge, w, r)

		templateData := struct {
			*commonData
			GamlCode string
		}{
			commonData: newCommonData(nil, db, r),
			GamlCode:   gamlCode,
		}

		err = tmpl.ExecuteTemplate(w, "gaml-code.html", templateData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		mut.Lock()
		pendingCodes[Hash(urlId)] = gamlCode
		defer mut.Unlock()
	})

	mux.HandleFunc("/complete-gaml-login", func(w http.ResponseWriter, r *http.Request) {

		upstreamAuthReqCookie, err := r.Cookie(prefix + "_gaml_login_state")
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		parsedUpstreamAuthReq, err := ParseJWT(db, upstreamAuthReqCookie.Value)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		ogInstanceId := claimFromToken("instance_id", parsedUpstreamAuthReq)

		if ogInstanceId != cluster.GetLocalId() {
			done := cluster.RedirectOrForward(ogInstanceId, w, r)
			if done {
				return
			}
		}

		urlId := claimFromToken("url", parsedUpstreamAuthReq)

		code, err := retrieveCode(urlId, httpClient, w)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		hashedUrl := Hash(urlId)
		mut.Lock()
		pendingCode := pendingCodes[hashedUrl]
		delete(pendingCodes, hashedUrl)
		defer mut.Unlock()

		if code != pendingCode {
			w.WriteHeader(401)
			io.WriteString(w, "Invalid code")
			return
		}

		request, err := getJwtFromCookie(prefix+"auth_request", w, r, jose)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		cookieValue := ""
		loginKeyCookie, err := getLoginCookie(db, r)
		if err == nil {
			cookieValue = loginKeyCookie.Value
		}

		newIdent := &Identity{
			IdType:       "url",
			Id:           urlId,
			ProviderName: "URL",
		}

		cookie, err := addIdentToCookie(r.Host, db, cookieValue, newIdent, jose)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		http.SetCookie(w, cookie)

		redirUrl := fmt.Sprintf("%s/auth?%s", domainToUri(r.Host), claimFromToken("raw_query", request))

		http.Redirect(w, r, redirUrl, http.StatusSeeOther)
	})

	return h
}

func (h *AddIdentityGamlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func retrieveCode(urlId string, httpClient *http.Client, w http.ResponseWriter) (string, error) {
	codeUrl := fmt.Sprintf("https://%s/%s", urlId, "gaml_code.txt")

	req, err := http.NewRequest(http.MethodGet, codeUrl, nil)
	if err != nil {
		return "", err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", errors.New("Invalid response status")
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	code := string(b)

	return code, nil
}
