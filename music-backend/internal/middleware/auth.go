package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"music-backend/internal/security"
)

// AuthMiddleware validira JWT token iz Authorization headera
func AuthMiddleware(tokenManager *security.TokenManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		token := parts[1]
		claims, err := tokenManager.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Čuvanje claims u context-u
		c.Set("user_id", claims.UserID)
		c.Set("user_role", claims.Role)
		c.Set("user_email", claims.Email)
		c.Set("username", claims.Username)

		c.Next()
	}
}

// RequireRole middleware proverava da li korisnik ima potrebnu ulogu
func RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user role not found"})
			c.Abort()
			return
		}

		userRoleStr, ok := userRole.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user role"})
			c.Abort()
			return
		}

		// Proverava da li korisnik ima bilo koju od potrebnih uloga
		hasRole := false
		for _, role := range requiredRoles {
			if security.HasPermission(userRoleStr, role) {
				hasRole = true
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// OptionalAuth middleware proverava token ako postoji
func OptionalAuth(tokenManager *security.TokenManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Set("user_id", "")
			c.Set("user_role", security.RoleUnauthenticated)
			c.Set("user_email", "")
			c.Set("username", "")
			c.Next()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Set("user_id", "")
			c.Set("user_role", security.RoleUnauthenticated)
			c.Set("user_email", "")
			c.Set("username", "")
			c.Next()
			return
		}

		token := parts[1]
		claims, err := tokenManager.ValidateToken(token)
		if err != nil {
			c.Set("user_id", "")
			c.Set("user_role", security.RoleUnauthenticated)
			c.Set("user_email", "")
			c.Set("username", "")
			c.Next()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("user_role", claims.Role)
		c.Set("user_email", claims.Email)
		c.Set("username", claims.Username)
		c.Next()
	}
}

// ExtractUserID vraća user ID iz context-a
func ExtractUserID(c *gin.Context) string {
	userID, exists := c.Get("user_id")
	if !exists {
		return ""
	}
	return userID.(string)
}

// ExtractUserRole vraća user role iz context-a
func ExtractUserRole(c *gin.Context) string {
	userRole, exists := c.Get("user_role")
	if !exists {
		return security.RoleUnauthenticated
	}
	return userRole.(string)
}

// ExtractUserEmail vraća user email iz context-a
func ExtractUserEmail(c *gin.Context) string {
	userEmail, exists := c.Get("user_email")
	if !exists {
		return ""
	}
	return userEmail.(string)
}

// ExtractUsername vraća username iz context-a
func ExtractUsername(c *gin.Context) string {
	username, exists := c.Get("username")
	if !exists {
		return ""
	}
	return username.(string)
}
