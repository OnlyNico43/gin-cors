package cors

import (
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCases holds the test configuration and expected results
type TestCase struct {
	name            string
	config          Config
	method          string
	requestHeaders  map[string]string
	expectedCode    int
	expectedHeaders map[string]string
}

func setupRouter(config Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(CorsMiddleware(config))
	router.Any("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	return router
}

func runTestCase(t *testing.T, tc TestCase) {
	router := setupRouter(tc.config)
	w := httptest.NewRecorder()
	req, err := http.NewRequest(tc.method, "/test", nil)
	require.NoError(t, err)

	// Set request headers
	for key, value := range tc.requestHeaders {
		req.Header.Set(key, value)
	}

	router.ServeHTTP(w, req)

	// Check status code
	assert.Equal(t, tc.expectedCode, w.Code, "Status code mismatch for test: %s", tc.name)

	// Check response headers
	for key, expectedValue := range tc.expectedHeaders {
		assert.Equal(t, expectedValue, w.Header().Get(key),
			"Header %s mismatch for test: %s", key, tc.name)
	}
}

func TestCorsMiddleware_DefaultConfig(t *testing.T) {
	tc := TestCase{
		name:   "Default configuration",
		config: DefaultConfig(),
		method: "GET",
		requestHeaders: map[string]string{
			"Origin": "http://example.com",
		},
		expectedCode: http.StatusOK,
		expectedHeaders: map[string]string{
			"Access-Control-Allow-Origin":      "*",
			"Access-Control-Allow-Credentials": "false",
			"Access-Control-Expose-Headers":    "Content-Length",
			"Vary":                             "Origin",
		},
	}
	runTestCase(t, tc)
}

func TestCorsMiddleware_MultipleOrigins(t *testing.T) {
	config := Config{
		AllowedOrigins:   []string{"http://example1.com", "http://example2.com"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           10 * time.Minute,
	}

	testCases := []TestCase{
		{
			name:   "Allowed origin 1",
			config: config,
			method: "GET",
			requestHeaders: map[string]string{
				"Origin": "http://example1.com",
			},
			expectedCode: http.StatusOK,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://example1.com, http://example2.com",
				"Access-Control-Allow-Credentials": "true",
			},
		},
		{
			name:   "Allowed origin 2",
			config: config,
			method: "GET",
			requestHeaders: map[string]string{
				"Origin": "http://example2.com",
			},
			expectedCode: http.StatusOK,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://example1.com, http://example2.com",
				"Access-Control-Allow-Credentials": "true",
			},
		},
		{
			name:   "Disallowed origin",
			config: config,
			method: "GET",
			requestHeaders: map[string]string{
				"Origin": "http://example3.com",
			},
			expectedCode: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runTestCase(t, tc)
		})
	}
}

func TestCorsMiddleware_PreflightRequests(t *testing.T) {
	config := Config{
		AllowedOrigins:   []string{"http://example.com"},
		AllowedMethods:   []string{"GET", "POST", "PUT"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           10 * time.Minute,
	}

	testCases := []TestCase{
		{
			name:   "Valid preflight request",
			config: config,
			method: "OPTIONS",
			requestHeaders: map[string]string{
				"Origin":                         "http://example.com",
				"Access-Control-Request-Method":  "POST",
				"Access-Control-Request-Headers": "Authorization",
			},
			expectedCode: http.StatusNoContent,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://example.com",
				"Access-Control-Allow-Methods":     "GET, POST, PUT",
				"Access-Control-Allow-Headers":     "Authorization, Content-Type",
				"Access-Control-Allow-Credentials": "true",
				"Access-Control-Max-Age":           "600",
			},
		},
		{
			name:   "Preflight with disallowed origin",
			config: config,
			method: "OPTIONS",
			requestHeaders: map[string]string{
				"Origin":                        "http://unauthorized.com",
				"Access-Control-Request-Method": "POST",
			},
			expectedCode: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runTestCase(t, tc)
		})
	}
}

func TestCorsMiddleware_WildcardValidation(t *testing.T) {
	assert.Panics(t, func() {
		config := Config{
			AllowedOrigins:   []string{"*"},
			AllowCredentials: true,
		}
		config.validate()
	}, "Should panic when using wildcard with credentials")

	assert.NotPanics(t, func() {
		config := Config{
			AllowedOrigins:   []string{"http://example.com"},
			AllowedMethods:   []string{"GET", "POST"},
			AllowedHeaders:   []string{"ContentType", "ContentLength"},
			ExposeHeaders:    []string{"ContentType"},
			AllowCredentials: true,
		}
		config.validate()
	}, "Should not panic with specific origin and credentials")
}

func TestCorsMiddleware_HeaderValidation(t *testing.T) {
	testCases := []struct {
		name           string
		config         Config
		shouldPanic    bool
		expectedConfig Config
	}{
		{
			name: "Default values with no credentials",
			config: Config{
				AllowCredentials: false,
			},
			shouldPanic: false,
			expectedConfig: Config{
				AllowedOrigins:   []string{"*"},
				AllowedMethods:   []string{"*"},
				AllowedHeaders:   []string{"*"},
				ExposeHeaders:    []string{"*"},
				AllowCredentials: false,
				MaxAge:           24 * time.Hour,
			},
		},
		{
			name: "Custom values with credentials",
			config: Config{
				AllowedOrigins:   []string{"http://example.com"},
				AllowedMethods:   []string{"GET", "POST"},
				AllowedHeaders:   []string{"Authorization"},
				ExposeHeaders:    []string{"Content-Length"},
				AllowCredentials: true,
				MaxAge:           10 * time.Minute,
			},
			shouldPanic: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shouldPanic {
				assert.Panics(t, func() {
					tc.config.validate()
				})
			} else {
				assert.NotPanics(t, func() {
					validatedConfig := tc.config.validate()
					if tc.expectedConfig.AllowedOrigins != nil {
						assert.Equal(t, tc.expectedConfig.AllowedOrigins, validatedConfig.AllowedOrigins)
					}
				})
			}
		})
	}
}
