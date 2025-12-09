package validation

import (
	"errors"
	"regexp"
	"strings"

	"music-backend/internal/models"
)

var (
	lowercaseRe = regexp.MustCompile(`[a-z]`)
	uppercaseRe = regexp.MustCompile(`[A-Z]`)
	digitRe     = regexp.MustCompile(`[0-9]`)
	specialRe   = regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-\[\]\{\}\\|;:'",.<>\/\?]`)
	usernameRe  = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,50}$`)
)

func NormalizeInputs(first, last, username, email string) (string, string, string, string) {
	return strings.TrimSpace(first),
		strings.TrimSpace(last),
		strings.ToLower(strings.TrimSpace(username)),
		strings.ToLower(strings.TrimSpace(email))
}

func ValidateUsername(u string) error {
	if !usernameRe.MatchString(u) {
		return errors.New("korisničko ime mora imati 3-50 karaktera i sme da sadrži slova, brojeve, ., _ ili -")
	}
	return nil
}

func ValidatePassword(pw string) error {
	if len(pw) < models.PasswordMinLength {
		return errors.New("lozinka mora imati najmanje 8 karaktera")
	}
	if !lowercaseRe.MatchString(pw) {
		return errors.New("lozinka mora sadržati bar jedno malo slovo")
	}
	if !uppercaseRe.MatchString(pw) {
		return errors.New("lozinka mora sadržati bar jedno veliko slovo")
	}
	if !digitRe.MatchString(pw) {
		return errors.New("lozinka mora sadržati bar jednu cifru")
	}
	if !specialRe.MatchString(pw) {
		return errors.New("lozinka mora sadržati bar jedan specijalni znak")
	}
	return nil
}
