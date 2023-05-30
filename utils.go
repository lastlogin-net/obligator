package main

import (
	"crypto/sha256"
	"fmt"
	"io"
)

func Hash(input string) string {
	sha2 := sha256.New()
	io.WriteString(sha2, input)
	return fmt.Sprintf("%x", sha2.Sum(nil))
}
