package security

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func GenerateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateOTPCode vraća 6-cifreni OTP u string formatu (sa vodećim nulama).
func GenerateOTPCode() (string, error) {
	var n uint32
	if err := binaryRead(&n); err != nil {
		return "", err
	}
	code := n % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// binaryRead čita 4 bajta kriptografski sigurnog entropije u uint32.
func binaryRead(out *uint32) error {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	*out = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return nil
}
