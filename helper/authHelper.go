package helper

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func CheckUserType(c *gin.Context, role string) error {

	userType := c.GetString("user_type")
	var err error = nil
	if userType != role {
		return errors.New("unauthorized user type")
	}
	return err
}

func MatchUserTypeToUID(c *gin.Context, userID string) error {
	userType := c.GetString("user_type")
	uid := c.GetString("uid")

	if userType != "USER" && uid != userID {
		return errors.New("unauthorized to access this resource")
	}

	err := CheckUserType(c, userType)
	return err
}

func VerifyToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		c.Abort()
		return
	}

	tokenString := strings.TrimSpace(strings.Replace(authHeader, "Bearer", "", 1))
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Secret key not set in environment"})
		c.Abort()
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		c.Abort()
		return
	}

	if uid, ok := claims["uid"].(string); ok {
		c.Set("uid", uid)
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UID not found in token"})
		c.Abort()
		return
	}

	if userType, ok := claims["user_type"].(string); ok {
		c.Set("user_type", userType)
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User type not found in token"})
		c.Abort()
		return
	}

	c.Next()
}
