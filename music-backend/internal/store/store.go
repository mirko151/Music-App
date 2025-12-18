package store

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"music-backend/internal/models"
	"music-backend/internal/security"
)

var (
	ErrUsernameExists  = errors.New("korisničko ime već postoji")
	ErrEmailExists     = errors.New("email već postoji")
	ErrTokenInvalid    = errors.New("token je nevažeći ili istekao")
	ErrUserNotFound    = errors.New("korisnik ne postoji")
	ErrInvalidCreds    = errors.New("neispravni kredencijali")
	ErrPasswordExpired = errors.New("lozinka je istekla; zatraži reset")
	ErrPasswordTooNew  = errors.New("lozinka mora biti stara bar 24h pre izmene")
	ErrOTPInvalid      = errors.New("otp je nevažeći ili istekao")
	ErrResetInvalid    = errors.New("reset token je nevažeći ili istekao")
)

type UserStore interface {
	Register(u models.User) (string, error)
	Confirm(token string) error
	Authenticate(username, password string) (string, error)
	VerifyOTP(code string) (string, error)
	Logout(session string)
	ChangePassword(username, currentPassword, newPassword string) error
	RequestPasswordReset(email string) (string, error)
	ResetPassword(token, newPassword string) error
}

type MemoryUserStore struct {
	mu              sync.Mutex
	users           map[string]models.User
	verificationMap map[string]string // token -> username
	otpMap          map[string]otpEntry
	resetMap        map[string]resetEntry
	sessions        map[string]string // sessionToken -> username
}

type otpEntry struct {
	Username  string
	ExpiresAt time.Time
}

type resetEntry struct {
	Username  string
	ExpiresAt time.Time
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users:           make(map[string]models.User),
		verificationMap: make(map[string]string),
		otpMap:          make(map[string]otpEntry),
		resetMap:        make(map[string]resetEntry),
		sessions:        make(map[string]string),
	}
}

func (s *MemoryUserStore) Register(u models.User) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[u.Username]; exists {
		return "", ErrUsernameExists
	}
	for _, existing := range s.users {
		if existing.Email == u.Email {
			return "", ErrEmailExists
		}
	}

	token, err := security.GenerateToken()
	if err != nil {
		return "", err
	}

	u.Verified = false
	u.RegistrationStatus = models.RegistrationPending
	u.PasswordChangedAt = time.Now()
	u.PasswordExpiresAt = time.Now().Add(models.PasswordMaxAge)

	s.users[u.Username] = u
	s.verificationMap[token] = u.Username
	return token, nil
}

func (s *MemoryUserStore) Confirm(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, ok := s.verificationMap[token]
	if !ok {
		return ErrTokenInvalid
	}

	u := s.users[username]
	u.Verified = true
	u.RegistrationStatus = models.RegistrationActive
	s.users[username] = u
	delete(s.verificationMap, token)
	return nil
}

func (s *MemoryUserStore) Authenticate(username, password string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return "", ErrUserNotFound
	}
	if time.Now().After(u.PasswordExpiresAt) {
		return "", ErrPasswordExpired
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return "", ErrInvalidCreds
	}
	if !u.Verified {
		return "", ErrTokenInvalid // nedovršena registracija
	}

	code, err := security.GenerateOTPCode()
	if err != nil {
		return "", err
	}
	s.otpMap[code] = otpEntry{
		Username:  username,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	return code, nil
}

func (s *MemoryUserStore) VerifyOTP(code string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.otpMap[code]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return "", ErrOTPInvalid
	}
	delete(s.otpMap, code)

	session, err := security.GenerateToken()
	if err != nil {
		return "", err
	}
	s.sessions[session] = entry.Username
	return session, nil
}

func (s *MemoryUserStore) Logout(session string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, session)
}

func (s *MemoryUserStore) ChangePassword(username, currentPassword, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return ErrUserNotFound
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(currentPassword)); err != nil {
		return ErrInvalidCreds
	}
	if time.Since(u.PasswordChangedAt) < models.PasswordMinAgeForChange {
		return ErrPasswordTooNew
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	u.PasswordChangedAt = time.Now()
	u.PasswordExpiresAt = time.Now().Add(models.PasswordMaxAge)
	s.users[username] = u
	return nil
}

func (s *MemoryUserStore) RequestPasswordReset(email string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var username string
	for _, u := range s.users {
		if u.Email == email {
			username = u.Username
			break
		}
	}
	if username == "" {
		return "", ErrUserNotFound
	}
	token, err := security.GenerateToken()
	if err != nil {
		return "", err
	}
	s.resetMap[token] = resetEntry{
		Username:  username,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	return token, nil
}

func (s *MemoryUserStore) ResetPassword(token, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.resetMap[token]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return ErrResetInvalid
	}
	delete(s.resetMap, token)

	u := s.users[entry.Username]
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	u.PasswordChangedAt = time.Now()
	u.PasswordExpiresAt = time.Now().Add(models.PasswordMaxAge)
	s.users[entry.Username] = u
	return nil
}
