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
	"os"
	"strings"
	"time"
)

type commonData struct {
	RootUri              string
	DisplayName          string
	Identities           []*Identity
	ReturnUri            string
	DisableHeaderButtons bool
}

func newCommonData(overrides *commonData, db Database, r *http.Request) *commonData {
	d := &commonData{}

	if overrides != nil {
		d.DisableHeaderButtons = overrides.DisableHeaderButtons
	}

	if overrides == nil || overrides.RootUri == "" {
		d.RootUri = domainToUri(r.Host)
	} else {
		d.RootUri = overrides.RootUri
	}

	if overrides == nil || overrides.DisplayName == "" {
		displayName, err := db.GetDisplayName()
		if err != nil {
			displayName = "Invalid display name"
		}
		d.DisplayName = displayName
	} else {
		d.DisplayName = overrides.DisplayName
	}

	if overrides == nil || overrides.Identities == nil {
		idents, _ := getIdentities(db, r)
		d.Identities = idents
	}

	if overrides == nil || overrides.ReturnUri == "" {
		var err error
		d.ReturnUri, err = getReturnUriCookie(db, r)
		if err != nil {
			d.ReturnUri = "/"
		}
	} else {
		d.ReturnUri = overrides.ReturnUri
	}

	return d
}

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

func buildCookieDomain(domain string) (string, error) {

	hostParts := strings.Split(domain, ".")

	// TODO: This should probably be using the public suffix list. It's
	// currently hardcoded for only certain domains
	if len(hostParts) < 3 {
		// apex domain
		return domain, nil
	} else {
		cookieDomain := strings.Join(hostParts[1:], ".")
		return cookieDomain, nil
	}
}

func validUser(id string, users []*User) bool {
	for _, user := range users {
		if id == user.Id {
			return true
		}
	}
	return false
}

func getLoginCookie(db Database, r *http.Request) (*http.Cookie, error) {

	prefix, err := db.GetPrefix()
	if err != nil {
		return nil, err
	}

	loginKeyName := prefix + "login_key"

	loginKeyCookie, err := r.Cookie(loginKeyName)
	if err != nil {
		return nil, err
	}

	// This cookie unlocks the main one. This is necessary for FedCM
	crossSiteDetectorCookieName := "obligator_not_cross_site"
	_, err = r.Cookie(crossSiteDetectorCookieName)
	if err != nil {
		return nil, err
	}

	return loginKeyCookie, nil
}

func setLoginCookie(w http.ResponseWriter, cookie *http.Cookie) error {

	w.Header().Add("Set-Login", "logged-in")
	http.SetCookie(w, cookie)

	return nil
}

func addIdentToCookie(domain string, db Database, cookieValue string, newIdent *Identity, jose *JOSE) (*http.Cookie, error) {

	idents := []*Identity{newIdent}

	keyJwt := NewJWT()

	if cookieValue != "" {
		parsed, err := jose.Parse(cookieValue)
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

	signed, err := jose.Sign(keyJwt)
	if err != nil {
		return nil, err
	}

	unhashedLoginKey := string(signed)

	cookieDomain, err := buildCookieDomain(domain)
	if err != nil {
		return nil, err
	}

	prefix, err := db.GetPrefix()
	if err != nil {
		return nil, err
	}

	loginKeyName := prefix + "login_key"

	cookie := &http.Cookie{
		Domain:   cookieDomain,
		Name:     loginKeyName,
		Value:    unhashedLoginKey,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   86400 * 365,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
	}

	return cookie, nil
}

func addLoginToCookie(db Database, r *http.Request, clientId string, newLogin *Login) (*http.Cookie, error) {

	domain := r.Host

	prefix, err := db.GetPrefix()
	if err != nil {
		return nil, err
	}

	loginKeyName := prefix + "login_key"

	loginKeyCookie, err := getLoginCookie(db, r)
	if err != nil {
		return nil, errors.New("Only logged-in users can access this endpoint")
	}

	issuedAt := time.Now().UTC()

	newLogin.Timestamp = issuedAt.Format(time.RFC3339)

	logins := make(map[string][]*Login)

	keyJwt := NewJWT()

	currentCookieValue := loginKeyCookie.Value

	if currentCookieValue != "" {
		parsed, err := ParseJWT(db, currentCookieValue)
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

	_, exists := logins[clientId]
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

	err = keyJwt.Set("iat", issuedAt)
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

	signed, err := SignJWT(db, keyJwt)
	if err != nil {
		return nil, err
	}

	loginKey := string(signed)

	cookieDomain, err := buildCookieDomain(domain)
	if err != nil {
		return nil, err
	}

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

func deleteLoginKeyCookie(domain string, db Database, w http.ResponseWriter) error {
	cookieDomain, err := buildCookieDomain(domain)
	if err != nil {
		return err
	}

	prefix, err := db.GetPrefix()
	if err != nil {
		return err
	}

	loginKeyName := prefix + "login_key"

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

func claimFromToken(claim string, token JWTToken) string {
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

func getJwtFromCookie(cookieKey string, w http.ResponseWriter, r *http.Request, jose *JOSE) (JWTToken, error) {
	// TODO: would tying to login key increase security?
	//loginKeyCookie, err := r.Cookie(storage.GetLoginKeyName())
	//if err != nil {
	//	return nil, err
	//}

	//hashedLoginKey := Hash(loginKeyCookie.Value)

	authReqCookie, err := r.Cookie(cookieKey)
	if err != nil {
		return nil, err
	}

	parsedAuthReq, err := jose.Parse(authReqCookie.Value)
	if err != nil {
		return nil, err
	}

	//reqLoginKey := claimFromToken("login_key_hash", parsedAuthReq)

	//if reqLoginKey != hashedLoginKey {
	//	return nil, errors.New("Not your request")
	//}

	return parsedAuthReq, nil
}

func setJwtCookie(db Database, domain string, jot JWTToken, cookieKey string, maxAge time.Duration, w http.ResponseWriter, r *http.Request) {

	signedReqJwt, err := SignJWT(db, jot)
	if err != nil {
		w.WriteHeader(400)
		io.WriteString(w, err.Error())
		return
	}

	cookieDomain, err := buildCookieDomain(domain)
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

func clearCookie(domain string, cookieKey string, w http.ResponseWriter) {
	cookieDomain, err := buildCookieDomain(domain)
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

// This function doesn't check against cross site requests as compared to
// the normal version
func getIdentitiesFedCm(db Database, r *http.Request) ([]*Identity, error) {

	prefix, err := db.GetPrefix()
	if err != nil {
		return nil, err
	}

	loginKeyName := prefix + "login_key"

	loginKeyCookie, err := r.Cookie(loginKeyName)
	if err != nil {
		return nil, err
	}

	return getIdentitiesCommon(db, r, loginKeyCookie)
}

func getIdentities(db Database, r *http.Request) ([]*Identity, error) {

	loginKeyCookie, err := getLoginCookie(db, r)
	if err != nil {
		return []*Identity{}, err
	}

	return getIdentitiesCommon(db, r, loginKeyCookie)
}

func getIdentitiesCommon(db Database, r *http.Request, loginKeyCookie *http.Cookie) ([]*Identity, error) {

	identities := []*Identity{}

	jwtStr := loginKeyCookie.Value

	if jwtStr == "" {
		return identities, errors.New("Blank jwt")
	}

	parsed, err := ParseJWT(db, jwtStr)
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

func getLogins(db Database, r *http.Request) (map[string][]*Login, error) {

	loginKeyCookie, err := getLoginCookie(db, r)
	if err != nil {
		return nil, err
	}

	jwtStr := loginKeyCookie.Value

	if jwtStr == "" {
		return nil, errors.New("Blank jwt")
	}

	parsed, err := ParseJWT(db, jwtStr)
	if err != nil {
		return nil, errors.New("Invalid jwt")
	}

	tokLoginsInterface, exists := parsed.Get("logins")
	if !exists {
		return nil, errors.New("No logins")
	}

	logins, ok := tokLoginsInterface.(map[string][]*Login)
	if !ok {
		return nil, errors.New("getLogins: Failed to assert type")
	}

	return logins, nil
}

func getReturnUriCookie(db Database, r *http.Request) (string, error) {

	prefix, err := db.GetPrefix()
	if err != nil {
		return "", err
	}

	name := prefix + "return_uri"

	cookie, err := r.Cookie(name)
	if err != nil {
		return "", errors.New("Missing return URI cookie")
	}

	return cookie.Value, nil
}
func setReturnUriCookie(domain string, db Database, uri string, w http.ResponseWriter) error {

	cookieDomain, err := buildCookieDomain(domain)
	if err != nil {
		return err
	}

	prefix, err := db.GetPrefix()
	if err != nil {
		return err
	}

	name := prefix + "return_uri"

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

func deleteReturnUriCookie(domain string, db Database, w http.ResponseWriter) {

	prefix, err := db.GetPrefix()
	if err != nil {
		fmt.Println("deleteReturnUriCookie: failed to get prefix")
		return
	}

	name := prefix + "return_uri"

	clearCookie(domain, name, w)
}

func domainToUri(host string) string {
	return fmt.Sprintf("https://%s", host)
}
