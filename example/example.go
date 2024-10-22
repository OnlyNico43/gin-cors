package example

import (
	"net/http"
	"time"

	"github.com/onlynico43/gin-cors"
	"github.com/gin-gonic/gin"
)

func main() {
  r := gin.Default()

  r.Use(cors.CorsMiddleware(cors.Config{
		AllowedOrigins:   []string{"https://foo.bar"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Length", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

  r.GET("/ping", func(c *gin.Context) {
    c.String(http.StatusOK, "pong")
  })

  r.Run(":8080")
}