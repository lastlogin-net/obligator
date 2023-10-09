package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
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

func tokenExpired(tokenData *Token) (bool, error) {
	timeNow := time.Now().UTC()
	createdAt, err := time.Parse("2006-01-02T15:04:05Z", tokenData.CreatedAt)
	if err != nil {
		return false, err
	}

	expiresAt := createdAt.Add(time.Duration(tokenData.ExpiresIn) * time.Second)

	return timeNow.After(expiresAt), nil
}

func buildCookieDomain(fullUrl string) (string, error) {
	rootUrlParsed, err := url.Parse(fullUrl)
	if err != nil {
		return "", err
	}
	hostParts := strings.Split(rootUrlParsed.Host, ".")

	if len(hostParts) < 3 {
		// apex domain
		return fullUrl, nil
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

func generateCookie(storage Storage, providerIdentityId, providerName, email, cookieValue string) (*http.Cookie, error) {
	key, exists := storage.GetJWKSet().Key(0)
	if !exists {
		return nil, errors.New("No keys available")
	}

	newIdentId, err := genRandomKey()
	if err != nil {
		return nil, err
	}

	newIdent := &Identity{
		Id:           newIdentId,
		ProviderId:   providerIdentityId,
		ProviderName: providerName,
		Email:        email,
	}

	idents := []*Identity{newIdent}

	if err == nil && cookieValue != "" {
		publicJwks, err := jwk.PublicSetOf(storage.GetJWKSet())
		if err != nil {
			return nil, err
		}

		parsed, err := jwt.Parse([]byte(cookieValue), jwt.WithKeySet(publicJwks))
		if err != nil {
			return nil, err
		}

		tokIdentsInterface, exists := parsed.Get("identities")
		if exists {
			if tokIdents, ok := tokIdentsInterface.([]*Identity); ok {
				for _, ident := range tokIdents {
					if ident.Email != newIdent.Email {
						idents = append(idents, ident)
					}
				}
			}
		}
	}

	nonce, err := genRandomKey()
	if err != nil {
		return nil, err
	}

	issuedAt := time.Now().UTC()
	jot, err := jwt.NewBuilder().
		IssuedAt(issuedAt).
		Claim("nonce", nonce).
		Claim("identities", idents).
		Build()
	if err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(jot, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return nil, err
	}

	unhashedLoginKey := string(signed)

	err = storage.AddLoginData(unhashedLoginKey)
	if err != nil {
		return nil, err
	}

	cookieDomain, err := buildCookieDomain(storage.GetRootUri())
	if err != nil {
		return nil, err
	}

	cookie := &http.Cookie{
		Domain:   cookieDomain,
		Name:     "login_key",
		Value:    unhashedLoginKey,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   86400 * 365,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		//SameSite: http.SameSiteStrictMode,
	}

	return cookie, nil
}
