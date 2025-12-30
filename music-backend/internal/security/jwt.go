package security

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

// Claims predstavlja JWT claims sa podacima korisnika
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}

// TokenManager upravlja JWT tokenima
type TokenManager struct {
	secretKey      string
	expiryDuration time.Duration
}

// NewTokenManager kreira novi TokenManager
func NewTokenManager(secretKey string, expiryHours int) *TokenManager {
	return &TokenManager{
		secretKey:      secretKey,
		expiryDuration: time.Duration(expiryHours) * time.Hour,
	}
}

// GenerateToken generiše JWT token
func (tm *TokenManager) GenerateToken(userID, username, email, role string) (string, error) {
	claims := Claims{
		UserID:   userID,
		Username: username,
		Email:    email,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tm.expiryDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tm.secretKey))
}

// ValidateToken validira JWT token i vraća claims
func (tm *TokenManager) ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(tm.secretKey), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

// RefreshToken generiše novi token
func (tm *TokenManager) RefreshToken(oldToken string) (string, error) {
	claims, err := tm.ValidateToken(oldToken)
	if err != nil && err != ErrExpiredToken {
		return "", err
	}

	return tm.GenerateToken(claims.UserID, claims.Username, claims.Email, claims.Role)
}
