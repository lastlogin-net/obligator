package obligator

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

func NewOIDCTokenBuilder() *openid.Builder {
	return openid.NewBuilder()
}

func NewJWTBuilder() *jwt.Builder {
	return jwt.NewBuilder()
}

type JOSE struct {
	db   *Database
	jwks jwk.Set
}

func NewJOSE(db *Database) (*JOSE, error) {

	jwksJson, err := db.GetJwksJson()
	if err != nil {
		return nil, err
	}

	if jwksJson == "" {
		jwks, err := GenerateJWKS()
		if err != nil {
			return nil, err
		}

		jwksJson, err := json.Marshal(jwks)
		if err != nil {
			return nil, err
		}

		err = db.SetJwksJson(string(jwksJson))
		if err != nil {
			return nil, err
		}

	}

	j := &JOSE{
		db: db,
	}

	return j, nil
}

func (j *JOSE) getJwks() (jwk.Set, error) {

	jwksJson, err := j.db.GetJwksJson()
	if err != nil {
		return nil, err
	}

	jwks, err := jwk.Parse([]byte(jwksJson))
	if err != nil {
		return nil, err
	}

	return jwks, nil
}

func (j *JOSE) GetPublicJwks() (jwk.Set, error) {

	jwks, err := j.getJwks()
	if err != nil {
		return nil, err
	}

	publicJwks, err := jwk.PublicSetOf(jwks)
	if err != nil {
		return nil, err
	}

	return publicJwks, nil
}

func (j *JOSE) Sign(jwt_ jwt.Token) (string, error) {

	jwks, err := j.getJwks()
	if err != nil {
		return "", err
	}

	key, exists := jwks.Key(0)
	if !exists {
		return "", errors.New("JOSE.sign(): No keys available for signing")
	}

	signed, err := jwt.Sign(jwt_, jwt.WithKey(jwa.RS256, key))

	return string(signed), nil
}

func (j *JOSE) Parse(jwtStr string) (jwt.Token, error) {

	publicJwks, err := j.GetPublicJwks()
	if err != nil {
		return nil, err
	}

	parsed, err := jwt.Parse([]byte(jwtStr), jwt.WithKeySet(publicJwks))
	if err != nil {
		return nil, err
	}

	return parsed, nil
}

func GenerateJWKS() (jwk.Set, error) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	key, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, err
	}

	if _, ok := key.(jwk.RSAPrivateKey); !ok {
		return nil, err
	}

	err = jwk.AssignKeyID(key)
	if err != nil {
		return nil, err
	}

	key.Set("alg", "RS256")

	keyset := jwk.NewSet()
	keyset.AddKey(key)
	return keyset, nil
}
