package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"net/smtp"
	"os"
	"sync"
	"time"
)

type Auth struct {
	storage             Storage
	pendingAuthRequests map[string]*PendingAuthRequest
	mut                 *sync.Mutex
}

type AuthRequest struct {
	Type  string `json:"type"`
	Email string `json:"email"`
}

type PendingAuthRequest struct {
	email string
	code  string
}

func (h *EmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func NewEmailAuth(storage Storage) *Auth {

	pendingAuthRequests := make(map[string]*PendingAuthRequest)
	mut := &sync.Mutex{}

	return &Auth{
		storage,
		pendingAuthRequests,
		mut,
	}
}

type EmailHandler struct {
	mux *http.ServeMux
}

func NewEmailHander(storage Storage) *EmailHandler {
	mux := http.NewServeMux()
	h := &EmailHandler{
		mux: mux,
	}

	tmpl, err := template.ParseFS(fs, "templates/*.tmpl")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	emailAuth := NewEmailAuth(storage)

	mux.HandleFunc("/login-email", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		if r.Method != "POST" {
			w.WriteHeader(405)
			io.WriteString(w, "Invalid method")
			return
		}

		requestId := r.Form.Get("request_id")

		templateData := struct {
			RequestId string
		}{
			RequestId: requestId,
		}

		err := tmpl.ExecuteTemplate(w, "login-email.tmpl", templateData)
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

		requestId := r.Form.Get("request_id")

		emailRequestId, err := genRandomKey()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		users, err := storage.GetUsers()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		if storage.GetPublic() || validUser(email, users) {
			// run in goroutine so the user can't use timing to determine whether the account exists
			go func() {
				_ = emailAuth.StartEmailValidation(email, emailRequestId)
			}()
		}

		data := struct {
			RequestId      string
			EmailRequestId string
		}{
			RequestId:      requestId,
			EmailRequestId: emailRequestId,
		}

		err = tmpl.ExecuteTemplate(w, "email-code.tmpl", data)
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

		requestId := r.Form.Get("request_id")
		request, err := storage.GetRequest(requestId)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		emailRequestId := r.Form.Get("email_request_id")
		if emailRequestId == "" {
			w.WriteHeader(400)
			io.WriteString(w, "email_request_id param missing")
			return
		}

		code := r.Form.Get("code")
		if code == "" {
			w.WriteHeader(400)
			io.WriteString(w, "code param missing")
			return
		}

		_, email, err := emailAuth.CompleteEmailValidation(emailRequestId, code)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		cookieValue := ""
		loginKeyCookie, err := r.Cookie("login_key")
		if err == nil {
			cookieValue = loginKeyCookie.Value
		}

		cookie, err := generateCookie(storage, email, "Email", email, cookieValue)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		http.SetCookie(w, cookie)

		redirUrl := fmt.Sprintf("%s/auth?%s", storage.GetRootUri(), request.RawQuery)

		http.Redirect(w, r, redirUrl, http.StatusSeeOther)
	})

	return h
}

func (a *Auth) StartEmailValidation(email, requestId string) error {

	code, err := genCode()
	if err != nil {
		return err
	}

	bodyTemplate := "From: %s <%s>\r\n" +
		"To: %s\r\n" +
		"Subject: Email Validation\r\n" +
		"\r\n" +
		"This is an email validation request from %s. Use the following code to prove you control %s:\r\n" +
		"\r\n" +
		"%s\r\n"

	smtpConfig, err := a.storage.GetSmtpConfig()
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

	a.mut.Lock()
	a.pendingAuthRequests[requestId] = &PendingAuthRequest{
		email: email,
		code:  code,
	}
	a.mut.Unlock()

	// Requests expire after a certain time
	go func() {
		time.Sleep(60 * time.Second)
		a.mut.Lock()
		delete(a.pendingAuthRequests, requestId)
		a.mut.Unlock()
	}()

	return nil
}

func (a *Auth) CompleteEmailValidation(requestId, code string) (string, string, error) {

	a.mut.Lock()
	req, exists := a.pendingAuthRequests[requestId]
	delete(a.pendingAuthRequests, requestId)
	a.mut.Unlock()

	if exists && req.code == code {
		token, err := genRandomKey()
		if err != nil {
			return "", "", err
		}
		//a.db.SetKeyring(token, req.keyring)
		return token, req.email, nil
	}

	return "", "", errors.New("Failed email validation")
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
