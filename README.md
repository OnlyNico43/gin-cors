# Gin Cors Middleware

The gin-cors package can be used in every [Gin](https://github.com/gin-gonic/gin) project and configure the cors behaviour of your application.

## Getting started
After installing and setting up Go you can create yor first project with gin.

In your main go file create a basic gin http server with the gin-cors middleware package
```go
package main

import (
  "net/http"

  "github.com/gin-gonic/gin"
  cors "github.com/OnlyNico43/gin-cors"
)

func main() {
  r := gin.Default()

  r.Use(cors.CorsMiddleware(cors.DefaultConfig()))

  r.GET("/ping", func(c *gin.Context) {
    c.String(http.StatusOK, "pong")
  })

  r.Run(":8080")
}
```

Done, now your application is equipped with a basic cors configuration


## How to configure
You can either use the default configuration or decide to use your own values in the Config object.

For more details please see the [documentation](https://pkg.go.dev/github.com/OnlyNico43/gin-cors)