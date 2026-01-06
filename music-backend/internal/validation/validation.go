package validation

import (
	"errors"
	"html"
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"music-backend/internal/models"
)

var (
	lowercaseRe = regexp.MustCompile(`[a-z]`)
	uppercaseRe = regexp.MustCompile(`[A-Z]`)
	digitRe     = regexp.MustCompile(`[0-9]`)
	specialRe   = regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-\[\]\{\}\\|;:'",.<>\/\?]`)
	usernameRe  = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,50}$`)
	otpRe       = regexp.MustCompile(`^[0-9]{6}$`)
	hexTokenRe  = regexp.MustCompile(`^[a-f0-9]{32}$`)
	nameRe      = regexp.MustCompile(`^[\p{L}][\p{L} \-']{1,49}$`)
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

func ValidateEmail(email string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return errors.New("email je obavezan")
	}
	// Koristimo net/mail parser kao robustan validator.
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("neispravan email")
	}
	return nil
}

func ValidateHumanName(name string, fieldLabel string) error {
	name = NormalizeHumanText(name)
	if name == "" {
		return errors.New(fieldLabel + " je obavezno")
	}
	if !nameRe.MatchString(name) {
		return errors.New(fieldLabel + " nije validno (2-50 karaktera, samo slova/razmak/-/')")
	}
	return nil
}

func ValidateOTP(code string) error {
	code = strings.TrimSpace(code)
	if !otpRe.MatchString(code) {
		return errors.New("otp mora imati tačno 6 cifara")
	}
	return nil
}

func ValidateHexToken(token string) error {
	token = strings.TrimSpace(strings.ToLower(token))
	if !hexTokenRe.MatchString(token) {
		return errors.New("token nije validan")
	}
	return nil
}

// NormalizeHumanText radi basic character escaping/sanitization za user-unos.
// Ne oslanja se na ovo kao jedinu zaštitu; služi kao demonstracija 2.18.
func NormalizeHumanText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Ukloni kontrolne karaktere
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	// HTML escape (output encoding) - bezbedno za prikaz u HTML kontekstu
	return html.EscapeString(b.String())
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

