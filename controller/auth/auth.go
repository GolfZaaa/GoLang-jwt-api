package auth

import (
	"melivecode/jwt-api/orm"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type RegisterBody struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Fullname string `json:"fullname" binding:"required"`
	Avatar   string `json:"avatar" binding:"required"`
}

func Register(c *gin.Context) {
	var json RegisterBody
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check user Exists ผู้ใช้มีอยู่แล้ว
	var userExits orm.User
	orm.Db.Where("username = ?", json.Username).First(&userExits)
	if userExits.ID > 0 {
		c.JSON(http.StatusOK, gin.H{
			"status":  "Error",
			"message": "มีชื่อผู้ใช้งานนี้อยู่ในระบบแล้ว",
		})
		return
	}

	// Create User
	encrypetedPassword, _ := bcrypt.GenerateFromPassword([]byte(json.Password), 10)
	user := orm.User{Username: json.Username, Password: string(encrypetedPassword), Fullname: json.Fullname, Avatar: json.Avatar}
	orm.Db.Create(&user)
	if user.ID > 0 {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": "สมัครผู้ใช้เสร็จสิ้น",
			"userId":  user.ID,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"status":  "fail",
			"message": "สมัครผู้ใช้ล้มเหลว",
		})
	}
}
