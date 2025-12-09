package models

import "time"

const (
	RegistrationPending = "pending_confirmation"
	RegistrationActive  = "active"
	PasswordMinLength   = 8
	PasswordMaxAge      = time.Hour
)

// User minimalni model za registraciju (zahtev 1.1).
type User struct {
	Username           string    `json:"username"`
	FirstName          string    `json:"firstName"`
	LastName           string    `json:"lastName"`
	Email              string    `json:"email"`
	PasswordHash       string    `json:"-"`
	Verified           bool      `json:"verified"`
	PasswordChangedAt  time.Time `json:"passwordChangedAt"`
	PasswordExpiresAt  time.Time `json:"passwordExpiresAt"`
	RegistrationStatus string    `json:"registrationStatus"`
}
