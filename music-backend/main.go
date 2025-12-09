package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"music-backend/internal/handlers"
	"music-backend/internal/middleware"
	"music-backend/internal/store"
)

func main() {
	r := gin.Default()
	r.Use(middleware.CORS())

	userStore := store.NewMemoryUserStore()
	authHandler := handlers.NewAuthHandler(userStore)

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"app":    "music-backend",
		})
	})

	authHandler.RegisterRoutes(r)

	if err := r.Run(":8080"); err != nil {
		panic(err)
	}
}
