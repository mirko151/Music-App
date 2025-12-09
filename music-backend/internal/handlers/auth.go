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

type AuthHandler struct {
	users store.UserStore
}

func NewAuthHandler(users store.UserStore) *AuthHandler {
	return &AuthHandler{users: users}
}

func (h *AuthHandler) RegisterRoutes(r *gin.Engine) {
	r.POST("/register", h.Register)
	r.POST("/register/confirm", h.Confirm)
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
