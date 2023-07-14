package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"
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
	cookieDomain := strings.Join(hostParts[1:], ".")

	return cookieDomain, nil
}

func validUser(email string, users []User) bool {
	for _, user := range users {
		if email == user.Email {
			return true
		}
	}
	return false
}
