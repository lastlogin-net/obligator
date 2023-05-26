package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"math/big"
)

// Modified from https://chrisguitarguy.com/2022/12/07/oauth-pkce-with-go/
func GeneratePKCEData() (string, string, error) {
	const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~"
	verifier := ""
	for i := 0; i < 64; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", "", err
		}
		verifier += string(chars[randIndex.Int64()])
	}

	sha2 := sha256.New()
	io.WriteString(sha2, verifier)
	challenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))

	return challenge, verifier, nil
}
