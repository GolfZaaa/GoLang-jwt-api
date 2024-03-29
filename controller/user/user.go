package user

import (
	"melivecode/jwt-api/orm"
	"net/http"

	"github.com/gin-gonic/gin"
)

func ReadAll(c *gin.Context) {
	var users []orm.User
	orm.Db.Find(&users)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "User Read Success", "users": users})
}

func Profile(c *gin.Context) {
	userid := c.MustGet("userId").(float64)
	var user orm.User
	orm.Db.First(&user, userid)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "User Read Success", "users": user})
}
