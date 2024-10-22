package cors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestCorsMiddleware_DefaultConfig(t *testing.T) {
	router := gin.New()
	router.Use(CorsMiddleware(DefaultConfig()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://example.com")

	router.ServeHTTP(w, req)

	// Assert that the correct headers are set
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "false", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "Content-Length", w.Header().Get("Access-Control-Expose-Headers"))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCorsMiddleware_PreflightRequest(t *testing.T) {
	config := Config{
		AllowedOrigins:   []string{"http://example.com"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           10 * time.Minute,
	}

	router := gin.New()
	router.Use(CorsMiddleware(config))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	router.ServeHTTP(w, req)

	// Assert that the preflight response headers are correctly set
	assert.Equal(t, "http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Authorization, Content-Type", w.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "600", w.Header().Get("Access-Control-Max-Age"))
	assert.Equal(t, http.StatusNoContent, w.Code) // 204 for preflight requests
}

func TestCorsMiddleware_DisallowedOrigin(t *testing.T) {
	config := Config{
		AllowedOrigins:   []string{"http://example.com"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           10 * time.Minute,
	}

	router := gin.New()
	router.Use(CorsMiddleware(config))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://notallowed.com")

	router.ServeHTTP(w, req)

	// Assert that the request is forbidden due to disallowed origin
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCorsMiddleware_DisallowedMethod(t *testing.T) {
	config := Config{
		AllowedOrigins:   []string{"http://example.com"},
		AllowedMethods:   []string{"GET"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           10 * time.Minute,
	}

	router := gin.New()
	router.Use(CorsMiddleware(config))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "http://example.com")

	router.ServeHTTP(w, req)

	// Assert that the request is forbidden due to disallowed method
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCorsMiddleware_AllowCredentials(t *testing.T) {
	config := Config{
		AllowedOrigins:   []string{"http://example.com"},
		AllowedMethods:   []string{"GET"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           10 * time.Minute,
	}

	router := gin.New()
	router.Use(CorsMiddleware(config))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://example.com")

	router.ServeHTTP(w, req)

	// Assert that the Allow-Credentials header is set to true
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCorsMiddleware_NoOrigin(t *testing.T) {
	config := DefaultConfig()

	router := gin.New()
	router.Use(CorsMiddleware(config))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	router.ServeHTTP(w, req)

	// Assert that the request is forbidden when no Origin is present
	assert.Equal(t, http.StatusForbidden, w.Code)
}
