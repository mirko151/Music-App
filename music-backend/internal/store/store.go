package store

import (
	"errors"
	"sync"
	"time"

	"music-backend/internal/models"
	"music-backend/internal/security"
)

var (
	ErrUsernameExists = errors.New("korisničko ime već postoji")
	ErrEmailExists    = errors.New("email već postoji")
	ErrTokenInvalid   = errors.New("token je nevažeći ili istekao")
)

type UserStore interface {
	Register(u models.User) (string, error)
	Confirm(token string) error
}

type MemoryUserStore struct {
	mu              sync.Mutex
	users           map[string]models.User
	verificationMap map[string]string // token -> username
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users:           make(map[string]models.User),
		verificationMap: make(map[string]string),
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
