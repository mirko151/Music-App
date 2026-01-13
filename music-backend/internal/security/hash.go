package security

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// HashSHA256Hex vraća hex(SHA-256(value)).
// Koristi se za zaštitu osetljivih jednokratnih vrednosti (OTP, reset/magic/verification tokeni)
// kada se čuvaju u memoriji ili bazi, tako da se original ne čuva u plain tekstu.
func HashSHA256Hex(value string) string {
	value = strings.TrimSpace(value)
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
