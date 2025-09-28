package middleware

import (
	"net/http"

	helper "github.com/anandgautam/Go/go-jwt-project/helper"
	"github.com/gin-gonic/gin"
)

func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("Authorization")
		if clientToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No Authorization header provided"})
			c.Abort()
			return
		}

		claims, err := helper.VerifyToken(clientToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("uid", claims.Uid)
		c.Set("email", claims.Email)
		c.set("first_name", claims.First_name)
		c.set("last_name", claims.Last_name)
		c.Set("user_type", claims.User_type)
		c.Next()
	}
}
