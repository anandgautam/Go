package routes

import (
	controllers "github.com/anandgautam/Go/go-jwt-project/controllers"

	"github.com/anandgautam/Go/go-jwt-project/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authentication())
	incomingRoutes.GET("/users/:user_id", controllers.GetUser())
	incomingRoutes.GET("/users", controllers.GetUsers())
}
