package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/anandgautam/Go/go-jwt-project/database"
	"github.com/anandgautam/Go/go-jwt-project/helper"
	"github.com/anandgautam/Go/go-jwt-project/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var UserCollection *mongo.Collection = database.OpenCollection(database.GetClient(), "users")
var validate = validator.New()

func HashPassword(password string) string {
	return password
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	return userPassword == providedPassword, ""
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}
		count, err := UserCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while checking for the email"})
			return
		}
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "This email already exists"})
			return
		}

		count, err = UserCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while checking for the phone number"})
			return
		}
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "This phone number already exists"})
			return
		}
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		//user.ID = primitive.NewObjectID()
		//user.User_id = user.ID.Hex()
		//password := HashPassword(*user.Password)
		//user.Password = &password
		// validate the user struct
		c.JSON(200, gin.H{
			"success": "Signup Endpoint",
		})
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(200, gin.H{
			"success": "Login Endpoint",
		})
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(200, gin.H{
			"success": "Get Users Endpoint",
		})
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if err := helper.MatchUserTypeToUID(c, userID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 10000000000)
		defer cancel()
		var user models.User
		err := UserCollection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&user)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while fetching the user"})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}
