package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// LimitBodyGin ograničava veličinu request body-ja (boundary checking).
// Primeni na JSON rute; za upload rute postavi veći limit ili ne koristi.
func LimitBodyGin(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

// RequireJSONGin odbija zahteve koji nisu application/json (whitelisting Content-Type).
// Ne koristiti za multipart/form-data upload rute.
func RequireJSONGin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut || c.Request.Method == http.MethodPatch {
			ct := c.GetHeader("Content-Type")
			if ct == "" {
				c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "missing Content-Type"})
				c.Abort()
				return
			}
			if !strings.HasPrefix(strings.ToLower(ct), "application/json") {
				c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "Content-Type must be application/json"})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
