package main

import (
	"github.com/Chirniy/massager/internal/authorization"
	"github.com/gin-gonic/gin"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	r := gin.Default()
	r.POST("/register", authorization.Register)
	r.POST("/login", authorization.Login)

	r.Run(":8080")
}
