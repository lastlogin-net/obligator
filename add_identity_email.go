package obligator

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/smtp"
	"os"
	"sync"
	"time"

	"github.com/ip2location/ip2location-go/v9"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AddIdentityEmailHandler struct {
	mux           *http.ServeMux
	db            Database
	pendingLogins map[string]*PendingLogin
	mut           *sync.Mutex
}

type PendingLogin struct {
	Email     string
	ExpiresAt time.Time
	RemoteIp  string
}

func (h *AddIdentityEmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func NewAddIdentityEmailHandler(db Database, cluster *Cluster, tmpl *template.Template, behindProxy bool, geoDb *ip2location.DB, jose *JOSE) *AddIdentityEmailHandler {
	mux := http.NewServeMux()
	h := &AddIdentityEmailHandler{
		mux:           mux,
		db:            db,
		mut:           &sync.Mutex{},
		pendingLogins: make(map[string]*PendingLogin),
	}

	privateJwks, err := GetJWKS(db)
	checkErr(err)

	publicJwks, err := jwk.PublicSetOf(privateJwks)
	checkErr(err)

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

	const EmailTimeout = 5 * time.Minute
	prefix, err := db.GetPrefix()
	checkErr(err)

	loginKeyName := prefix + "login_key"

	// Periodically clean up expired shares
	go func() {
		for {
			newMap := make(map[string]PendingLogin)
			h.mut.Lock()
			for k, v := range h.pendingLogins {
				newMap[k] = *v
			}
			h.mut.Unlock()

			for key, pending := range newMap {
				if time.Now().UTC().After(pending.ExpiresAt) {
					h.mut.Lock()
					delete(h.pendingLogins, key)
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

		templateData := newCommonData(nil, db, r)

		err := tmpl.ExecuteTemplate(w, "login-email.html", templateData)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/email-sent", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		serverUri := domainToUri(r.Host)

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

		users, err := db.GetUsers()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		magicLinkKey, err := genRandomKey()
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintln(os.Stderr, err.Error())
			return
		}

		magicLink := fmt.Sprintf("%s/magic?key=%s&instance_id=%s", serverUri, magicLinkKey, cluster.GetLocalId())

		remoteIp, err := getRemoteIp(r, behindProxy)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		h.mut.Lock()
		h.pendingLogins[magicLinkKey] = &PendingLogin{
			Email:     email,
			ExpiresAt: time.Now().UTC().Add(EmailTimeout),
			RemoteIp:  remoteIp,
		}
		h.mut.Unlock()

		issuedAt := time.Now().UTC()

		emailCodeJwt, err := NewJWTBuilder().
			IssuedAt(issuedAt).
			Expiration(issuedAt.Add(EmailTimeout)).
			Subject(email).
			Claim("magic_link_key", magicLinkKey).
			Claim("instance_id", cluster.GetLocalId()).
			Build()
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		// TODO: now that we're using magic links instead of codes,
		// does it still add value for this to be encrypted?
		encryptedJwt, err := NewJWTSerializer().
			Sign(jwt.WithKey(jwa.RS256, privKey)).
			Encrypt(jwt.WithKey(jwa.RSA_OAEP_256, pubKey)).
			Serialize(emailCodeJwt)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		cookieDomain, err := buildCookieDomain(serverUri)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
		// TODO: delete this cookie eventually
		cookie := &http.Cookie{
			Domain:   cookieDomain,
			Name:     prefix + "email_login",
			Value:    string(encryptedJwt),
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			Secure:   true,
			HttpOnly: true,
			MaxAge:   2 * 60,
		}
		http.SetCookie(w, cookie)

		identities, _ := getIdentities(db, r)

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

		config, err := db.GetConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			w.WriteHeader(500)
			return
		}

		if config.Public || validUser(email, users) {
			// run in goroutine so the user can't use timing to determine whether the account exists
			go func() {
				err := h.StartEmailValidation(email, serverUri, magicLink, identities)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to send email: %s\n", err.Error())
				}
			}()
		} else {
			fmt.Fprintf(os.Stderr, "Email validation attempted for non-existing user: %s\n", email)
		}

		data := newCommonData(nil, db, r)

		err = tmpl.ExecuteTemplate(w, "email-sent.html", data)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/magic", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		ogInstanceId := r.Form.Get("instance_id")

		if ogInstanceId != cluster.GetLocalId() {
			done := cluster.RedirectOrForward(ogInstanceId, w, r)
			if done {
				return
			}
		}

		key := r.Form.Get("key")

		h.mut.Lock()
		defer h.mut.Unlock()
		pendingLogin, exists := h.pendingLogins[key]
		if !exists {
			w.WriteHeader(500)
			io.WriteString(w, "Invalid magic link")
			return
		}

		remoteIp, err := getRemoteIp(r, behindProxy)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		differentIps := false
		if pendingLogin.RemoteIp != remoteIp {
			differentIps = true
		}

		useGeoDb := false
		var ogIpGeo ip2location.IP2Locationrecord
		var magicIpGeo ip2location.IP2Locationrecord
		if geoDb != nil {
			useGeoDb = true

			ogIpGeo, err = geoDb.Get_all(pendingLogin.RemoteIp)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(w, err.Error())
				return
			}

			magicIpGeo, err = geoDb.Get_all(remoteIp)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(w, err.Error())
				return
			}
		}

		differentBrowsers := true

		emailCodeJwtCookie, err := r.Cookie(prefix + "email_login")
		if err == nil {
			encryptedJwt := []byte(emailCodeJwtCookie.Value)
			decryptedJwt, err := jwe.Decrypt(encryptedJwt, jwe.WithKey(jwa.RSA_OAEP_256, privKey))
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}

			parsedJwt, err := ParseJWT(db, string(decryptedJwt))
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}

			ogMagicLinkKey := claimFromToken("magic_link_key", parsedJwt)

			if key == ogMagicLinkKey {
				differentBrowsers = false
			}
		}

		templateData := struct {
			*commonData
			Key               string
			DifferentIps      bool
			DifferentBrowsers bool
			UseGeoDb          bool
			OgIp              string
			OgIpGeo           ip2location.IP2Locationrecord
			MagicIp           string
			MagicIpGeo        ip2location.IP2Locationrecord
			InstanceId        string
		}{
			commonData:        newCommonData(nil, db, r),
			Key:               key,
			DifferentIps:      differentIps,
			DifferentBrowsers: differentBrowsers,
			UseGeoDb:          useGeoDb,
			OgIp:              pendingLogin.RemoteIp,
			OgIpGeo:           ogIpGeo,
			MagicIp:           remoteIp,
			MagicIpGeo:        magicIpGeo,
			InstanceId:        ogInstanceId,
		}

		err = tmpl.ExecuteTemplate(w, "email-magic.html", templateData)
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

		magicLinkKey := r.Form.Get("magic_link_key")
		ogInstanceId := r.Form.Get("instance_id")

		if ogInstanceId != cluster.GetLocalId() {
			done := cluster.RedirectOrForward(ogInstanceId, w, r)
			if done {
				return
			}
		}

		h.mut.Lock()
		defer h.mut.Unlock()
		pendingLogin, exists := h.pendingLogins[magicLinkKey]
		if !exists {
			w.WriteHeader(500)
			io.WriteString(w, "Not a valid session")
			return
		}

		delete(h.pendingLogins, magicLinkKey)

		email := pendingLogin.Email

		cookieValue := ""
		loginKeyCookie, err := r.Cookie(loginKeyName)
		if err == nil {
			cookieValue = loginKeyCookie.Value
		}

		newIdent := &Identity{
			IdType:        "email",
			Id:            email,
			ProviderName:  "Email",
			Name:          r.Form.Get("name"),
			Email:         email,
			EmailVerified: true,
		}

		cookie, err := addIdentToCookie(r.Host, db, cookieValue, newIdent, jose)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		w.Header().Add("Set-Login", "logged-in")
		http.SetCookie(w, cookie)

		returnUri, err := getReturnUriCookie(db, r)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(os.Stderr, err.Error())
			return
		}

		if err == nil {
			deleteReturnUriCookie(r.Host, db, w)

			redirUrl := fmt.Sprintf("%s", returnUri)
			http.Redirect(w, r, redirUrl, http.StatusSeeOther)
			return
		} else {
			templateData := newCommonData(nil, db, r)

			err := tmpl.ExecuteTemplate(w, "confirm-magic.html", templateData)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, err.Error())
				return
			}
		}
	})

	return h
}

func (h *AddIdentityEmailHandler) StartEmailValidation(email, rootUri, magicLink string, identities []*Identity) error {

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
		"This is an email validation request from %s. Use the link below to prove you have access to %s." +
		"\r\n\r\n%s"

	smtpConfig, err := h.db.GetSmtpConfig()
	if err != nil {
		return err
	}

	fromText := fmt.Sprintf("%s email validator", smtpConfig.SenderName)
	fromEmail := smtpConfig.Sender
	emailBody := fmt.Sprintf(bodyTemplate, fromText, fromEmail, email, smtpConfig.SenderName, email, magicLink)

	emailAuth := smtp.Auth(nil)
	if smtpConfig.Username != "" && smtpConfig.Password != "" {
		emailAuth = smtp.PlainAuth("", smtpConfig.Username, smtpConfig.Password, smtpConfig.Server)
	}
	srv := fmt.Sprintf("%s:%d", smtpConfig.Server, smtpConfig.Port)
	msg := []byte(emailBody)
	err = smtp.SendMail(srv, emailAuth, fromEmail, []string{email}, msg)
	if err != nil {
		return err
	}

	return nil
}
