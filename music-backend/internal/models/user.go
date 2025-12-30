package models

import "time"

const (
	RegistrationPending     = "pending_confirmation"
	RegistrationActive      = "active"
	PasswordMinLength       = 8
	PasswordMaxAge          = 60 * 24 * time.Hour  // 60 dana
	PasswordMinAgeForChange = 24 * time.Hour
	MaxFailedLoginAttempts  = 5
	AccountLockoutDuration  = 30 * time.Minute
)

// User predstavlja korisnika u sistemu
type User struct {
	ID                 string    `bson:"_id,omitempty" json:"id"`
	Username           string    `bson:"username" json:"username"`
	FirstName          string    `bson:"first_name" json:"firstName"`
	LastName           string    `bson:"last_name" json:"lastName"`
	Email              string    `bson:"email" json:"email"`
	PasswordHash       string    `bson:"password_hash" json:"-"`
	Role               string    `bson:"role" json:"role"` // "NK", "A", "RK"
	Verified           bool      `bson:"verified" json:"verified"`
	PasswordChangedAt  time.Time `bson:"password_changed_at" json:"passwordChangedAt"`
	PasswordExpiresAt  time.Time `bson:"password_expires_at" json:"passwordExpiresAt"`
	RegistrationStatus string    `bson:"registration_status" json:"registrationStatus"`
	CreatedAt          time.Time `bson:"created_at" json:"createdAt"`
	UpdatedAt          time.Time `bson:"updated_at" json:"updatedAt"`
	FailedLoginAttempts int      `bson:"failed_login_attempts" json:"failedLoginAttempts"`
	LockedUntil        *time.Time `bson:"locked_until" json:"lockedUntil"`
}
