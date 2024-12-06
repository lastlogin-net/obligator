package obligator

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

type JWTToken jwt.Token

func NewOIDCTokenBuilder() *openid.Builder {
	return openid.NewBuilder()
}

func NewJWTBuilder() *jwt.Builder {
	return jwt.NewBuilder()
}

func NewJWTSerializer() *jwt.Serializer {
	return jwt.NewSerializer()
}

func NewJWT() jwt.Token {
	return jwt.New()
}

type JOSE struct {
	db   Database
	jwks jwk.Set
}

func NewJOSE(db Database, cluster *Cluster) (*JOSE, error) {

	var identsType []*Identity
	jwt.RegisterCustomField("identities", identsType)
	var loginsType map[string][]*Login
	jwt.RegisterCustomField("logins", loginsType)
	var idTokenType string
	jwt.RegisterCustomField("id_token", idTokenType)

	jwksJson, err := db.GetJwksJson()
	if err != nil {
		return nil, err
	}

	if jwksJson == "" && cluster.IAmThePrimary() {
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

func (j *JOSE) GetJWKS() (jwk.Set, error) {
	return GetJWKS(j.db)
}
func GetJWKS(db Database) (jwk.Set, error) {

	jwksJson, err := db.GetJwksJson()
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
	return getPublicJwks(j.db)
}
func getPublicJwks(db Database) (jwk.Set, error) {

	jwks, err := GetJWKS(db)
	if err != nil {
		return nil, err
	}

	publicJwks, err := jwk.PublicSetOf(jwks)
	if err != nil {
		return nil, err
	}

	return publicJwks, nil
}

func (j *JOSE) SignAndEncrypt(jwt_ jwt.Token) (string, error) {
	return SignAndEncryptJWT(j.db, jwt_)
}

func (j *JOSE) Sign(jwt_ jwt.Token) (string, error) {
	return SignJWT(j.db, jwt_)
}

func (j *JOSE) Decrypt(encryptedJwt string) (string, error) {
	return DecryptJWT(j.db, encryptedJwt)
}

func DecryptJWT(db Database, encryptedJwt string) (string, error) {
	jwks, err := GetJWKS(db)
	if err != nil {
		return "", err
	}

	privKey, exists := jwks.Key(0)
	if !exists {
		return "", errors.New("JOSE.sign(): No keys available for signing")
	}

	encryptedJwtBytes := []byte(encryptedJwt)
	decryptedJwt, err := jwe.Decrypt(encryptedJwtBytes, jwe.WithKey(jwa.RSA_OAEP_256, privKey))
	if err != nil {
		return "", err
	}

	return string(decryptedJwt), nil
}

func SignAndEncryptJWT(db Database, jwt_ jwt.Token) (string, error) {

	jwks, err := GetJWKS(db)
	if err != nil {
		return "", err
	}

	privKey, exists := jwks.Key(0)
	if !exists {
		return "", errors.New("JOSE.sign(): No keys available for signing")
	}

	publicJwks, err := jwk.PublicSetOf(jwks)
	if err != nil {
		return "", err
	}

	pubKey, exists := publicJwks.Key(0)
	if !exists {
		return "", errors.New("JOSE.sign(): no pubkey")
	}

	encryptedJwt, err := NewJWTSerializer().
		Sign(jwt.WithKey(jwa.RS256, privKey)).
		Encrypt(jwt.WithKey(jwa.RSA_OAEP_256, pubKey)).
		Serialize(jwt_)
	if err != nil {
		return "", err
	}

	return string(encryptedJwt), nil
}

func SignJWT(db Database, jwt_ jwt.Token) (string, error) {

	jwks, err := GetJWKS(db)
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
	return ParseJWT(j.db, jwtStr)
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

func ParseJWT(db Database, jwtStr string) (jwt.Token, error) {

	publicJwks, err := getPublicJwks(db)
	if err != nil {
		return nil, err
	}

	parsed, err := jwt.Parse([]byte(jwtStr), jwt.WithKeySet(publicJwks))
	if err != nil {
		return nil, err
	}

	return parsed, nil
}
