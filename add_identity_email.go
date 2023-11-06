package main

import (
	"crypto/rand"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"net/smtp"
	"os"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AddIdentityEmailHandler struct {
	mux           *http.ServeMux
	storage       Storage
	db            *Database
	revokedTokens map[string]uint8
	mut           *sync.Mutex
}

func (h *AddIdentityEmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func NewAddIdentityEmailHandler(storage Storage, db *Database, cluster *Cluster, tmpl *template.Template) *AddIdentityEmailHandler {
	mux := http.NewServeMux()
	h := &AddIdentityEmailHandler{
		mux:           mux,
		storage:       storage,
		db:            db,
		mut:           &sync.Mutex{},
		revokedTokens: make(map[string]uint8),
	}

	privateJwks := storage.GetJWKSet()

	publicJwks, err := jwk.PublicSetOf(privateJwks)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	privKey, exists := privateJwks.Key(0)
	if !exists {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	pubKey, exists := publicJwks.Key(0)
	if !exists {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	const EmailTimeout = 2 * time.Minute

	go func() {
		for {
			newMap := make(map[string]uint8)
			h.mut.Lock()
			for k, v := range h.revokedTokens {
				newMap[k] = v
			}
			h.mut.Unlock()

			for tok, _ := range newMap {
				decryptedJwt, err := jwe.Decrypt([]byte(tok), jwe.WithKey(jwa.RSA_OAEP_256, privKey))
				_, err = jwt.Parse(decryptedJwt, jwt.WithKeySet(publicJwks))
				if err != nil {
					h.mut.Lock()
					delete(h.revokedTokens, tok)
					h.mut.Unlock()
				}
			}
			time.Sleep(EmailTimeout)
		}
	}()

	mux.HandleFunc("/login-email", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		if r.Method != "POST" {
			w.WriteHeader(405)
			io.WriteString(w, "Invalid method")
			return
		}

		templateData := struct {
			DisplayName string
			RootUri     string
		}{
			DisplayName: storage.GetDisplayName(),
			RootUri:     storage.GetRootUri(),
		}

		err := tmpl.ExecuteTemplate(w, "login-email.html", templateData)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/email-code", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		if r.Method != "POST" {
			w.WriteHeader(405)
			io.WriteString(w, "Invalid method")
			return
		}

		email := r.Form.Get("email")
		if email == "" {
			w.WriteHeader(400)
			io.WriteString(w, "email param missing")
			return
		}

		users, err := storage.GetUsers()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		code, err := genCode()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, "Key doesn't exist")
			return
		}

		issuedAt := time.Now().UTC()
		emailCodeJwt, err := jwt.NewBuilder().
			IssuedAt(issuedAt).
			Expiration(issuedAt.Add(EmailTimeout)).
			Subject(email).
			Claim("code", code).
			Claim("instance_id", cluster.GetLocalId()).
			Build()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		encryptedJwt, err := jwt.NewSerializer().
			Sign(jwt.WithKey(jwa.RS256, privKey)).
			Encrypt(jwt.WithKey(jwa.RSA_OAEP_256, pubKey)).
			Serialize(emailCodeJwt)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		cookieDomain, err := buildCookieDomain(storage.GetRootUri())
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
		cookie := &http.Cookie{
			Domain:   cookieDomain,
			Name:     "obligator_email_code",
			Value:    string(encryptedJwt),
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			Secure:   true,
			HttpOnly: true,
			MaxAge:   2 * 60,
		}
		http.SetCookie(w, cookie)

		// TODO: this is duplicated. make a function
		identities := []*Identity{}
		loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
		if err == nil && loginKeyCookie.Value != "" {
			parsed, err := jwt.Parse([]byte(loginKeyCookie.Value), jwt.WithKeySet(publicJwks))
			if err != nil {
				// Only add identities from current cookie if it's valid
			} else {
				tokIdentsInterface, exists := parsed.Get("identities")
				if exists {
					if tokIdents, ok := tokIdentsInterface.([]*Identity); ok {
						identities = tokIdents
					}
				}
			}
		}

		since := time.Now().UTC().Add(-RateLimitTime)
		counts, err := db.GetEmailValidationCounts(since)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			w.WriteHeader(400)
			return
		}

		for _, ident := range identities {
			hashedId := Hash(ident.Id)
			for _, count := range counts {
				if hashedId == count.HashedRequesterId && count.Count >= EmailValidationsPerTimeLimit {
					w.WriteHeader(429)
					io.WriteString(w, "Too many email validation attempts")
					return
				}
			}
		}

		primaryHost, err := cluster.PrimaryHost()
		if err != nil {
			// I *am* the primary
		} else {
			done := cluster.RedirectOrForward(primaryHost, w, r)
			if done {
				return
			}
		}

		if storage.GetPublic() || validUser(email, users) {
			// run in goroutine so the user can't use timing to determine whether the account exists
			go func() {
				err := h.StartEmailValidation(email, code, identities)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to send email: %s\n", err.Error())
				}
			}()
		}

		data := struct {
			DisplayName string
			RootUri     string
		}{
			DisplayName: storage.GetDisplayName(),
			RootUri:     storage.GetRootUri(),
		}

		err = tmpl.ExecuteTemplate(w, "email-code.html", data)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/complete-email-login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			io.WriteString(w, "Invalid method")
			return
		}

		r.ParseForm()

		emailCodeJwtCookie, err := r.Cookie("obligator_email_code")
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		h.mut.Lock()
		_, exists := h.revokedTokens[emailCodeJwtCookie.Value]
		h.mut.Unlock()
		if exists {
			w.WriteHeader(401)
			io.WriteString(w, "This token has been revoked")
			return
		}

		encryptedJwt := []byte(emailCodeJwtCookie.Value)
		decryptedJwt, err := jwe.Decrypt(encryptedJwt, jwe.WithKey(jwa.RSA_OAEP_256, privKey))
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		parsedJwt, err := jwt.Parse(decryptedJwt, jwt.WithKeySet(publicJwks))
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		ogInstanceId := claimFromToken("instance_id", parsedJwt)

		if ogInstanceId != cluster.GetLocalId() {
			done := cluster.RedirectOrForward(ogInstanceId, w, r)
			if done {
				return
			}
		}

		jwtCode := claimFromToken("code", parsedJwt)

		email := parsedJwt.Subject()

		request, err := getJwtFromCookie("obligator_auth_request", storage, w, r)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		code := r.Form.Get("code")
		if code == "" {
			w.WriteHeader(400)
			io.WriteString(w, "code param missing")
			return
		}

		if code != jwtCode {

			h.mut.Lock()
			h.revokedTokens[emailCodeJwtCookie.Value] = 1
			h.mut.Unlock()

			w.WriteHeader(401)
			io.WriteString(w, "Bad code")
			return
		}

		cookieValue := ""
		loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
		if err == nil {
			cookieValue = loginKeyCookie.Value
		}

		cookie, err := addIdentityToCookie(storage, "Email", email, cookieValue)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		http.SetCookie(w, cookie)

		redirUrl := fmt.Sprintf("%s/auth?%s", storage.GetRootUri(), claimFromToken("raw_query", request))

		http.Redirect(w, r, redirUrl, http.StatusSeeOther)
	})

	return h
}

func (h *AddIdentityEmailHandler) StartEmailValidation(email, code string, identities []*Identity) error {

	for _, ident := range identities {
		err := h.db.AddEmailValidationRequest(ident.Id, email)
		if err != nil {
			return err
		}
	}

	bodyTemplate := "From: %s <%s>\r\n" +
		"To: %s\r\n" +
		"Subject: Email Validation\r\n" +
		"\r\n" +
		"This is an email validation request from %s. Use the following code to prove you have access to %s:\r\n" +
		"\r\n" +
		"%s\r\n"

	smtpConfig, err := h.storage.GetSmtpConfig()
	if err != nil {
		return err
	}

	fromText := fmt.Sprintf("%s email validator", smtpConfig.SenderName)
	fromEmail := smtpConfig.Sender
	emailBody := fmt.Sprintf(bodyTemplate, fromText, fromEmail, email, smtpConfig.SenderName, email, code)

	emailAuth := smtp.PlainAuth("", smtpConfig.Username, smtpConfig.Password, smtpConfig.Server)
	srv := fmt.Sprintf("%s:%d", smtpConfig.Server, smtpConfig.Port)
	msg := []byte(emailBody)
	err = smtp.SendMail(srv, emailAuth, fromEmail, []string{email}, msg)
	if err != nil {
		return err
	}

	return nil
}

func genCode() (string, error) {
	const chars string = "0123456789"
	id := ""
	for i := 0; i < 6; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}
