package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"music-backend/internal/models"
	"music-backend/internal/store"
	"music-backend/internal/validation"
)

type RegisterRequest struct {
	Username        string `json:"username" binding:"required,min=3,max=50"`
	FirstName       string `json:"firstName" binding:"required,min=2,max=50"`
	LastName        string `json:"lastName" binding:"required,min=2,max=50"`
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required"`
	ConfirmPassword string `json:"confirmPassword" binding:"required"`
}

type ConfirmRequest struct {
	Token string `json:"token" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type OTPVerifyRequest struct {
	OTP string `json:"otp" binding:"required"`
}

type LogoutRequest struct {
	Session string `json:"session" binding:"required"`
}

type ChangePasswordRequest struct {
	Username        string `json:"username" binding:"required"`
	CurrentPassword string `json:"currentPassword" binding:"required"`
	NewPassword     string `json:"newPassword" binding:"required"`
	ConfirmPassword string `json:"confirmPassword" binding:"required"`
}

type ResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetConfirmRequest struct {
	Token           string `json:"token" binding:"required"`
	NewPassword     string `json:"newPassword" binding:"required"`
	ConfirmPassword string `json:"confirmPassword" binding:"required"`
}

type AuthHandler struct {
	users store.UserStore
}

func NewAuthHandler(users store.UserStore) *AuthHandler {
	return &AuthHandler{users: users}
}

func (h *AuthHandler) RegisterRoutes(r *gin.Engine) {
	r.POST("/register", h.Register)
	r.POST("/register/confirm", h.Confirm)
	r.POST("/login", h.Login)
	r.POST("/login/verify", h.VerifyOTP)
	r.POST("/logout", h.Logout)
	r.POST("/password/change", h.ChangePassword)
	r.POST("/password/reset/request", h.RequestReset)
	r.POST("/password/reset/confirm", h.ResetPassword)
}

// Register implementira 1.1: unos podataka, jaka lozinka, provera jedinstvenosti, kreira verifikacioni token.
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}

	first, last, username, email := validation.NormalizeInputs(req.FirstName, req.LastName, req.Username, req.Email)
	if err := validation.ValidateUsername(username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Password != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "lozinke se ne poklapaju"})
		return
	}
	if err := validation.ValidatePassword(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "greška pri čuvanju lozinke"})
		return
	}

	u := models.User{
		Username:          username,
		FirstName:         first,
		LastName:          last,
		Email:             email,
		PasswordHash:      string(hash),
		PasswordChangedAt: time.Now(),
	}

	token, err := h.users.Register(u)
	if err != nil {
		status := http.StatusBadRequest
		if err == store.ErrUsernameExists || err == store.ErrEmailExists {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	// U produkciji bi token išao emailom; ovde ga vraćamo radi demonstracije.
	c.JSON(http.StatusCreated, gin.H{
		"message":            "registracija kreirana; potvrdi nalog verifikacionim tokenom",
		"verificationToken":  token,
		"registrationStatus": models.RegistrationPending,
	})
}

func (h *AuthHandler) Confirm(c *gin.Context) {
	var req ConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}

	if err := h.users.Confirm(req.Token); err != nil {
		status := http.StatusBadRequest
		if err == store.ErrTokenInvalid {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "registracija potvrđena"})
}

// Login: korak 1, proverava lozinku, generiše OTP (vraća ga radi demo-a; u praksi bi se slao emailom/SMS).
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}
	otp, err := h.users.Authenticate(req.Username, req.Password)
	if err != nil {
		status := http.StatusUnauthorized
		switch err {
		case store.ErrUserNotFound:
			status = http.StatusNotFound
		case store.ErrPasswordExpired:
			status = http.StatusForbidden
		case store.ErrTokenInvalid:
			status = http.StatusForbidden
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "otp generisan (u realnom sistemu šalje se na email)",
		"otp":     otp,
	})
}

// VerifyOTP: korak 2, potvrđuje OTP i vraća session token.
func (h *AuthHandler) VerifyOTP(c *gin.Context) {
	var req OTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}
	session, err := h.users.VerifyOTP(req.OTP)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "prijava uspešna",
		"session": session,
	})
}

// Logout: uklanja session token (radi demo-a prihvatamo kroz telo).
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}
	h.users.Logout(req.Session)
	c.JSON(http.StatusOK, gin.H{"message": "odjava uspešna"})
}

// ChangePassword: zahteva staru lozinku, nova mora biti validna i stara lozinka mora biti starija od 24h.
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}
	if req.NewPassword != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "lozinke se ne poklapaju"})
		return
	}
	if err := validation.ValidatePassword(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.users.ChangePassword(req.Username, req.CurrentPassword, req.NewPassword); err != nil {
		status := http.StatusBadRequest
		switch err {
		case store.ErrUserNotFound:
			status = http.StatusNotFound
		case store.ErrInvalidCreds:
			status = http.StatusUnauthorized
		case store.ErrPasswordTooNew:
			status = http.StatusForbidden
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "lozinka promenjena"})
}

// RequestReset: generiše reset token (demo: vraća se u odgovoru; inače bi bio poslat emailom).
func (h *AuthHandler) RequestReset(c *gin.Context) {
	var req ResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}
	token, err := h.users.RequestPasswordReset(req.Email)
	if err != nil {
		status := http.StatusNotFound
		if err != store.ErrUserNotFound {
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":    "reset token generisan (u realnom sistemu šalje se emailom)",
		"resetToken": token,
	})
}

// ResetPassword: potvrda reset tokena i postavljanje nove lozinke.
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req ResetConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}
	if req.NewPassword != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "lozinke se ne poklapaju"})
		return
	}
	if err := validation.ValidatePassword(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.users.ResetPassword(req.Token, req.NewPassword); err != nil {
		status := http.StatusBadRequest
		if err == store.ErrResetInvalid {
			status = http.StatusUnauthorized
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "lozinka resetovana"})
}
