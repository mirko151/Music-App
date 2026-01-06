package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"music-backend/internal/middleware"
	"music-backend/internal/models"
	"music-backend/internal/security"
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

type MagicLinkRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type MagicLinkConfirm struct {
	Token string `json:"token" binding:"required"`
}

type AuthHandler struct {
	users        store.UserStore
	tokenManager *security.TokenManager
}

func NewAuthHandler(users store.UserStore, tokenManager *security.TokenManager) *AuthHandler {
	return &AuthHandler{
		users:        users,
		tokenManager: tokenManager,
	}
}

func (h *AuthHandler) RegisterRoutes(r *gin.Engine) {
	// 2.18: validacija ulaza + boundary checking (JSON only + limit)
	json := r.Group("/", middleware.RequireJSONGin(), middleware.LimitBodyGin(1<<20))
	json.POST("/register", h.Register)
	json.POST("/register/confirm", h.Confirm)
	json.POST("/login", h.Login)
	json.POST("/login/verify", h.VerifyOTP)
	json.POST("/password/reset/request", h.RequestReset)
	json.POST("/password/reset/confirm", h.ResetPassword)
	json.POST("/magic/request", h.RequestMagicLink)
	json.POST("/magic/confirm", h.ConfirmMagicLink)

	// JWT-zaštićene JSON rute
	protected := r.Group("/", middleware.RequireJSONGin(), middleware.LimitBodyGin(1<<20), middleware.AuthMiddleware(h.tokenManager))
	protected.POST("/logout", h.Logout)
	protected.POST("/password/change", h.ChangePassword)
	
	// Admin rutas
	adminRoutes := r.Group("/admin", middleware.AuthMiddleware(h.tokenManager), middleware.RequireRole(security.RoleAdmin))
	adminRoutes.POST("/users/:id/role", h.UpdateUserRole)
	adminRoutes.POST("/file/verify", h.VerifyFileUpload)
}

// Register implementira 1.1: unos podataka, jaka lozinka, provera jedinstvenosti, kreira verifikacioni token.
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}

	first, last, username, email := validation.NormalizeInputs(req.FirstName, req.LastName, req.Username, req.Email)
	first = validation.NormalizeHumanText(first)
	last = validation.NormalizeHumanText(last)
	username = strings.TrimSpace(strings.ToLower(username))
	email = strings.TrimSpace(strings.ToLower(email))

	if err := validation.ValidateHumanName(first, "ime"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validation.ValidateHumanName(last, "prezime"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validation.ValidateEmail(email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
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
		ID:                strconv.FormatInt(time.Now().Unix(), 10),
		Username:          username,
		FirstName:         first,
		LastName:          last,
		Email:             email,
		PasswordHash:      string(hash),
		Role:              security.RoleRegularUser,
		PasswordChangedAt: time.Now(),
		PasswordExpiresAt: time.Now().Add(models.PasswordMaxAge),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
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
	if err := validation.ValidateHexToken(req.Token); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

// VerifyOTP: korak 2, potvrđuje OTP i vraća JWT token
func (h *AuthHandler) VerifyOTP(c *gin.Context) {
	var req OTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}
	if err := validation.ValidateOTP(req.OTP); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user, err := h.users.VerifyOTPAndGetUser(req.OTP)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Generisanje JWT tokena
	token, err := h.tokenManager.GenerateToken(user.ID, user.Username, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "greška pri generisanju tokena"})
		return
	}

	// Ažuriranje LastLoginAt
	h.users.UpdateLastLogin(user.ID)

	c.JSON(http.StatusOK, gin.H{
		"message":   "prijava uspešna",
		"token":     token,
		"user_id":   user.ID,
		"email":     user.Email,
		"role":      user.Role,
		"username":  user.Username,
		"expiresAt": time.Now().Add(time.Duration(24) * time.Hour).Unix(),
	})
}

// Logout: odjava (invalidira token na klijentskoj strani)
func (h *AuthHandler) Logout(c *gin.Context) {
	userID := middleware.ExtractUserID(c)
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "odjava uspešna",
	})
}

// ChangePassword: promenjena lozinka sa autentifikacijom
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}

	userID := middleware.ExtractUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
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
		if err := validation.ValidateEmail(req.Email); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
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
		if err := validation.ValidateHexToken(req.Token); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
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

// RequestMagicLink: generiše magic link (demo: vraća ga u odgovoru, inače bi se slao emailom).
func (h *AuthHandler) RequestMagicLink(c *gin.Context) {
	var req MagicLinkRequest
		if err := validation.ValidateEmail(req.Email); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}
	token, err := h.users.RequestMagicLink(req.Email)
	if err != nil {
		status := http.StatusNotFound
		if err != store.ErrUserNotFound {
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":    "magic link generisan (demo: token vraćen ovde, inače bi bio poslat emailom)",
		"magicToken": token,
	})
}

// ConfirmMagicLink: potvrđuje magic link i vraća JWT token
func (h *AuthHandler) ConfirmMagicLink(c *gin.Context) {
	var req MagicLinkConfirm
		if err := validation.ValidateHexToken(req.Token); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}
	user, err := h.users.ConsumeMagicLinkAndGetUser(req.Token)
	if err != nil {
		status := http.StatusUnauthorized
		if err == store.ErrMagicInvalid {
			status = http.StatusUnauthorized
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	// Generisanje JWT tokena
	token, err := h.tokenManager.GenerateToken(user.ID, user.Username, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "greška pri generisanju tokena"})
		return
	}

	// Ažuriranje LastLoginAt
	h.users.UpdateLastLogin(user.ID)

	c.JSON(http.StatusOK, gin.H{
		"message":   "magic link potvrđen, prijava uspešna",
		"token":     token,
		"user_id":   user.ID,
		"email":     user.Email,
		"role":      user.Role,
		"username":  user.Username,
		"expiresAt": time.Now().Add(time.Duration(24) * time.Hour).Unix(),
	})
}

// VerifyFileUpload: 2.18 demo bezbednog upravljanja datotekama (whitelist + integritet)
// Očekuje multipart/form-data sa field "file".
// Opcionalno: expectedSha256 u form polju za proveru integriteta.
func (h *AuthHandler) VerifyFileUpload(c *gin.Context) {
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing file"})
		return
	}
	expected := strings.TrimSpace(strings.ToLower(c.PostForm("expectedSha256")))

	mimeType, sha, err := validation.ValidateUploadedFile(fileHeader, validation.DefaultMaxUploadBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if expected != "" && expected != sha {
		c.JSON(http.StatusBadRequest, gin.H{"error": "integrity check failed", "sha256": sha})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "file ok",
		"filename": fileHeader.Filename,
		"mime":     mimeType,
		"size":     fileHeader.Size,
		"sha256":   sha,
	})
}

// UpdateUserRole: Admin akcija za promenu uloge korisnika (2.17)
func (h *AuthHandler) UpdateUserRole(c *gin.Context) {
	userID := c.Param("id")
	
	var req struct {
		Role string `json:"role" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "neispravan unos", "details": err.Error()})
		return
	}

	// Validacija uloge
	if req.Role != security.RoleAdmin && req.Role != security.RoleRegularUser {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nevalidna uloga"})
		return
	}

	if err := h.users.UpdateUserRole(userID, req.Role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "uloga korisnika ažurirana",
		"user_id": userID,
		"role":    req.Role,
	})
}
