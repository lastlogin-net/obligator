package obligator

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func Hash(input string) string {
	sha2 := sha256.New()
	io.WriteString(sha2, input)
	return fmt.Sprintf("%x", sha2.Sum(nil))
}

func saveJson(data interface{}, filePath string) error {
	jsonStr, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errors.New("Error serializing JSON")
	} else {
		err := os.WriteFile(filePath, jsonStr, 0644)
		if err != nil {
			return errors.New("Error saving JSON")
		}
	}
	return nil
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}

func genRandomKey() (string, error) {
	const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	id := ""
	for i := 0; i < 32; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}

func genRandomCode() (string, error) {
	const chars string = "0123456789"
	id := ""
	for i := 0; i < 4; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}

func buildCookieDomain(fullUrl string) (string, error) {
	rootUrlParsed, err := url.Parse(fullUrl)
	if err != nil {
		return "", err
	}
	hostParts := strings.Split(rootUrlParsed.Host, ".")

	// TODO: This should probably be using the public suffix list. It's
	// currently hardcoded for only certain domains
	if len(hostParts) < 3 {
		// apex domain
		return rootUrlParsed.Host, nil
	} else {
		cookieDomain := strings.Join(hostParts[1:], ".")
		return cookieDomain, nil
	}
}

func validUser(email string, users []User) bool {
	for _, user := range users {
		if email == user.Email {
			return true
		}
	}
	return false
}

func addIdentityToCookie(storage Storage, providerName, id, email, cookieValue string, emailVerified bool) (*http.Cookie, error) {

	idType := "email"
	if providerName == "URL" {
		idType = "url"
	}

	newIdent := &Identity{
		IdType:        idType,
		Id:            id,
		ProviderName:  providerName,
		Email:         email,
		EmailVerified: emailVerified,
	}

	return addIdentToCookie(storage, cookieValue, newIdent)
}

func addIdentToCookie(storage Storage, cookieValue string, newIdent *Identity) (*http.Cookie, error) {

	key, exists := storage.GetJWKSet().Key(0)
	if !exists {
		return nil, errors.New("No keys available")
	}

	idents := []*Identity{newIdent}

	keyJwt := jwt.New()

	if cookieValue != "" {
		publicJwks, err := jwk.PublicSetOf(storage.GetJWKSet())
		if err != nil {
			return nil, err
		}

		parsed, err := jwt.Parse([]byte(cookieValue), jwt.WithKeySet(publicJwks))
		if err != nil {
			// Only add identities from current cookie if it's valid
		} else {
			keyJwt = parsed
			tokIdentsInterface, exists := parsed.Get("identities")
			if exists {
				if tokIdents, ok := tokIdentsInterface.([]*Identity); ok {
					for _, ident := range tokIdents {
						if ident.Id != newIdent.Id {
							idents = append(idents, ident)
						}
					}
				}
			}
		}
	}

	issuedAt := time.Now().UTC()

	err := keyJwt.Set("iat", issuedAt)
	if err != nil {
		return nil, err
	}

	nonce, err := genRandomKey()
	if err != nil {
		return nil, err
	}
	err = keyJwt.Set("nonce", nonce)
	if err != nil {
		return nil, err
	}

	err = keyJwt.Set("identities", idents)
	if err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(keyJwt, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return nil, err
	}

	unhashedLoginKey := string(signed)

	cookieDomain, err := buildCookieDomain(storage.GetRootUri())
	if err != nil {
		return nil, err
	}

	loginKeyName := storage.GetPrefix() + "login_key"

	sameSiteMode := http.SameSiteLaxMode

	if storage.GetFedCmEnabled() {
		sameSiteMode = http.SameSiteNoneMode
	}

	cookie := &http.Cookie{
		Domain:   cookieDomain,
		Name:     loginKeyName,
		Value:    unhashedLoginKey,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   86400 * 365,
		Path:     "/",
		SameSite: sameSiteMode,
		//SameSite: http.SameSiteLaxMode,
		//SameSite: http.SameSiteStrictMode,
	}

	return cookie, nil
}

func addLoginToCookie(storage Storage, currentCookieValue, clientId string, newLogin *Login) (*http.Cookie, error) {
	key, exists := storage.GetJWKSet().Key(0)
	if !exists {
		return nil, errors.New("No keys available")
	}

	issuedAt := time.Now().UTC()

	newLogin.Timestamp = issuedAt.Format(time.RFC3339)

	logins := make(map[string][]*Login)

	keyJwt := jwt.New()

	if currentCookieValue != "" {
		publicJwks, err := jwk.PublicSetOf(storage.GetJWKSet())
		if err != nil {
			return nil, err
		}

		parsed, err := jwt.Parse([]byte(currentCookieValue), jwt.WithKeySet(publicJwks))
		if err != nil {
			// Only add identities from current cookie if it's valid
		} else {
			keyJwt = parsed
			loginsInterface, exists := parsed.Get("logins")
			if exists {
				if tokLogins, ok := loginsInterface.(map[string][]*Login); ok {
					logins = tokLogins
				}
			}
		}
	}

	_, exists = logins[clientId]
	if exists {
		// Search for and update existing login, otherwise add a new entry
		found := false
		for _, login := range logins[clientId] {
			if login.Id == newLogin.Id && login.ProviderName == newLogin.ProviderName {
				login.Timestamp = newLogin.Timestamp
				found = true
			}
		}
		if !found {
			logins[clientId] = append(logins[clientId], newLogin)
		}
	} else {
		logins[clientId] = []*Login{newLogin}
	}

	err := keyJwt.Set("iat", issuedAt)
	if err != nil {
		return nil, err
	}

	nonce, err := genRandomKey()
	if err != nil {
		return nil, err
	}
	err = keyJwt.Set("nonce", nonce)
	if err != nil {
		return nil, err
	}

	err = keyJwt.Set("logins", logins)
	if err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(keyJwt, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return nil, err
	}

	loginKey := string(signed)

	cookieDomain, err := buildCookieDomain(storage.GetRootUri())
	if err != nil {
		return nil, err
	}

	loginKeyName := storage.GetPrefix() + "login_key"

	cookie := &http.Cookie{
		Domain:   cookieDomain,
		Name:     loginKeyName,
		Value:    loginKey,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   86400 * 365,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		//SameSite: http.SameSiteStrictMode,
	}

	return cookie, nil
}

func deleteLoginKeyCookie(storage Storage, w http.ResponseWriter) error {
	cookieDomain, err := buildCookieDomain(storage.GetRootUri())
	if err != nil {
		return err
	}

	loginKeyName := storage.GetPrefix() + "login_key"

	cookie := &http.Cookie{
		Domain:   cookieDomain,
		Name:     loginKeyName,
		Value:    "",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	return nil
}

func claimFromToken(claim string, token jwt.Token) string {
	valIface, exists := token.Get(claim)
	if !exists {
		return ""
	}

	val, ok := valIface.(string)
	if !ok {
		return ""
	}

	return val
}

func getJwtFromCookie(cookieKey string, storage Storage, w http.ResponseWriter, r *http.Request) (jwt.Token, error) {
	// TODO: would tying to login key increase security?
	//loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
	//if err != nil {
	//	return nil, err
	//}

	publicJwks, err := jwk.PublicSetOf(storage.GetJWKSet())
	if err != nil {
		return nil, err
	}

	//hashedLoginKey := Hash(loginKeyCookie.Value)

	authReqCookie, err := r.Cookie(cookieKey)
	if err != nil {
		return nil, err
	}

	parsedAuthReq, err := jwt.Parse([]byte(authReqCookie.Value), jwt.WithKeySet(publicJwks))
	if err != nil {
		return nil, err
	}

	//reqLoginKey := claimFromToken("login_key_hash", parsedAuthReq)

	//if reqLoginKey != hashedLoginKey {
	//	return nil, errors.New("Not your request")
	//}

	return parsedAuthReq, nil
}

func setJwtCookie(storage Storage, jot jwt.Token, cookieKey string, maxAge time.Duration, w http.ResponseWriter, r *http.Request) {
	key, exists := storage.GetJWKSet().Key(0)
	if !exists {
		w.WriteHeader(500)
		fmt.Fprintf(os.Stderr, "No keys available")
		return
	}

	signedReqJwt, err := jwt.Sign(jot, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		w.WriteHeader(400)
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
		Name:     cookieKey,
		Value:    string(signedReqJwt),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   int(maxAge.Seconds()),
	}
	http.SetCookie(w, cookie)
}

func clearCookie(storage Storage, cookieKey string, w http.ResponseWriter) {
	cookieDomain, err := buildCookieDomain(storage.GetRootUri())
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	cookie := &http.Cookie{
		Domain: cookieDomain,
		Name:   cookieKey,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)
}

func getRemoteIp(r *http.Request, behindProxy bool) (string, error) {
	remoteIp, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}

	if behindProxy {
		xffHeader := r.Header.Get("X-Forwarded-For")
		if xffHeader != "" {
			parts := strings.Split(xffHeader, ",")
			remoteIp = parts[0]
		}
	}

	return remoteIp, nil
}

func getIdentities(storage Storage, r *http.Request, publicJwks jwk.Set) ([]*Identity, error) {

	identities := []*Identity{}

	prefix := storage.GetPrefix()
	loginKeyName := prefix + "login_key"

	loginKeyCookie, err := r.Cookie(loginKeyName)
	if err != nil {
		return identities, err
	}

	jwtStr := loginKeyCookie.Value

	if jwtStr == "" {
		return identities, errors.New("Blank jwt")
	}

	parsed, err := jwt.Parse([]byte(jwtStr), jwt.WithKeySet(publicJwks))
	if err != nil {
		return identities, errors.New("Invalid jwt")
	}

	tokIdentsInterface, exists := parsed.Get("identities")
	if !exists {
		return identities, errors.New("No identities")
	}

	if tokIdents, ok := tokIdentsInterface.([]*Identity); ok {
		identities = tokIdents
	}

	return identities, nil
}

func getReturnUriCookie(storage Storage, r *http.Request) (string, error) {
	name := storage.GetPrefix() + "return_uri"

	cookie, err := r.Cookie(name)
	if err != nil {
		return "", errors.New("Missing return URI cookie")
	}

	return cookie.Value, nil
}
func setReturnUriCookie(storage Storage, uri string, w http.ResponseWriter) error {

	cookieDomain, err := buildCookieDomain(storage.GetRootUri())
	if err != nil {
		return err
	}

	name := storage.GetPrefix() + "return_uri"

	cookie := &http.Cookie{
		Domain:   cookieDomain,
		Name:     name,
		Value:    uri,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	return nil
}

func deleteReturnUriCookie(storage Storage, w http.ResponseWriter) {

	name := storage.GetPrefix() + "return_uri"

	clearCookie(storage, name, w)
}
