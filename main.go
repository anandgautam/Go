package main

import (
	"os"

	routes "github.com/anandgautam/Go/go-jwt-project/routes"
	"github.com/gin-gonic/gin"
)

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8080" // Default port if not specified
	}

	router := gin.New()
	router.Use(gin.Logger())

	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	routes.GET("/api-1ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"success": "Access Granted for API 1",
		})
	})

	routes.GET("/api-2", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"success": "Access Granted for API 2",
		})
	})

	router.Run(":" + port)

}
