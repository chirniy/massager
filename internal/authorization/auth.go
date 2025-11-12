package authorization

import (
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/Chirniy/massager/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	usersMu sync.Mutex
	users   = make(map[string]string)
	jwtKey  = []byte("super_secret_key_123")
)

func generateToken(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(), // токен живёт 24ч
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func parseToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if email, ok := claims["email"].(string); ok {
			return email, nil
		}
	}
	return "", err
}

func isValidGmail(email string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._%+\-]+@gmail\.com$`, email)
	return matched
}

func Register(c *gin.Context) {
	var req models.User
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if !isValidGmail(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email must be a gmail.com address"})
		return
	}

	usersMu.Lock()
	defer usersMu.Unlock()

	if _, exists := users[req.Email]; exists {
		c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
		return
	}

	users[req.Email] = req.Password
	c.JSON(http.StatusOK, gin.H{"message": "registration successful"})
}

func Login(c *gin.Context) {
	var req models.User
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	usersMu.Lock()
	defer usersMu.Unlock()

	pass, exists := users[req.Email]
	if !exists || pass != req.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := generateToken(req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
	c.JSON(http.StatusOK, gin.H{"message": "login successful"})
}

func DeleteUser(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return
	}

	tokenStr := authHeader
	email, err := parseToken(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	usersMu.Lock()
	defer usersMu.Unlock()

	if _, exists := users[email]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	delete(users, email)
	c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
}
