package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"music-backend/internal/handlers"
	"music-backend/internal/middleware"
	"music-backend/internal/store"
)

func main() {
	r := gin.Default()
	r.Use(middleware.CORS())

	var userStore store.UserStore = store.NewMemoryUserStore()
	if uri := os.Getenv("MONGO_URI"); uri != "" {
		if mongoStore, err := store.NewMongoUserStore(defaultContext(), uri, envOr("MONGO_DB", "music"), envOr("MONGO_USERS_COLLECTION", "users")); err == nil {
			userStore = mongoStore
		} else {
			// Fallback na memoriju ako konekcija padne.
			log.Printf("Mongo konekcija nije uspela, koristi se memorijski store: %v\n", err)
		}
	}
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultContext() context.Context {
	return context.Background()
}
