package authorization

import (
	"net/http"
	"regexp"
	"sync"

	"github.com/Chirniy/massager/internal/models"
	"github.com/gin-gonic/gin"
)

var (
	usersMu sync.Mutex
	users   = make(map[string]string)
)

// простая проверка: почта на gmail
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

	c.JSON(http.StatusOK, gin.H{"message": "login successful"})
}
