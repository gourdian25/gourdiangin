# Gourdiangin Package Documentation

The `gourdiangin` package is a production-ready HTTP server built on top of the popular Gin framework. It provides a robust, configurable, and easy-to-use server implementation with features like TLS support, CORS configuration, graceful shutdown, and structured logging using the `gourdianlogger` package.

---

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Configuration](#configuration)
4. [Examples](#examples)
   - [Basic Example](#basic-example)
   - [With TLS Example](#with-tls-example)
   - [With CORS Example](#with-cors-example)
   - [Custom Middleware Example](#custom-middleware-example)
   - [Graceful Shutdown Example](#graceful-shutdown-example)
5. [Using Gourdian Logger](#using-gourdian-logger)
6. [API Reference](#api-reference)

---

## Installation

To install the `gourdiangin` package, use the following command:

```bash
go get github.com/gourdian25/gourdiangin
```

---

## Basic Usage

Here’s a simple example to get started with the `gourdiangin` package:

```go
package main

import (
	"github.com/gourdian25/gourdiangin"
	"github.com/gourdian25/gourdianlogger"
)

func main() {
	// Create a new logger with default configuration
	logger, err := gourdianlogger.NewGourdianLogger(gourdianlogger.LoggerConfig{
		Filename:    "myapp.log",
		MaxBytes:    10 * 1024 * 1024, // 10MB
		BackupCount: 5,
		LogLevel:    gourdianlogger.INFO,
	})
	if err != nil {
		panic(err)
	}
	defer logger.Close()

	config := gourdiangin.ServerConfig{
		Port:            8080,
		UseTLS:          false,
		UseCORS:         false,
		Logger:          logger,
		ShutdownTimeout: 30 * time.Second,
	}

	setup := &gourdiangin.ServerSetupImpl{}
	server := gourdiangin.NewGourdianGinServer(setup, config)

	router := server.GetRouter()
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello, World!",
		})
	})

	if err := server.Start(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
```

---

## Configuration

The `ServerConfig` struct encapsulates all configuration options for the Gin server setup:

```go
type ServerConfig struct {
	Port            int
	UseTLS          bool
	UseCORS         bool
	TLSKeyFile      string
	TLSCertFile     string
	CORSConfig      cors.Config
	Logger          *gourdianlogger.Logger
	ShutdownTimeout time.Duration
}
```

### Example Configuration

```go
config := ServerConfig{
    Port:            8443,
    UseTLS:          true,
    TLSCertFile:     "/path/to/cert.pem",
    TLSKeyFile:      "/path/to/key.pem",
    UseCORS:         true,
    CORSConfig:      corsConfig,
    Logger:          logger,
    ShutdownTimeout: 30 * time.Second,
}
```

---

## Examples

### Basic Example

This example demonstrates the most basic usage of the `gourdiangin` package.

```go
package main

import (
	"github.com/gourdian25/gourdiangin"
	"github.com/gourdian25/gourdianlogger"
)

func main() {
	// Create a new logger with default configuration
	logger, err := gourdianlogger.NewGourdianLogger(gourdianlogger.LoggerConfig{
		Filename:    "myapp.log",
		MaxBytes:    10 * 1024 * 1024, // 10MB
		BackupCount: 5,
		LogLevel:    gourdianlogger.INFO,
	})
	if err != nil {
		panic(err)
	}
	defer logger.Close()

	config := gourdiangin.ServerConfig{
		Port:            8080,
		UseTLS:          false,
		UseCORS:         false,
		Logger:          logger,
		ShutdownTimeout: 30 * time.Second,
	}

	setup := &gourdiangin.ServerSetupImpl{}
	server := gourdiangin.NewGourdianGinServer(setup, config)

	router := server.GetRouter()
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello, World!",
		})
	})

	if err := server.Start(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
```

---

### With TLS Example

This example demonstrates how to set up the server with TLS.

```go
package main

import (
	"github.com/gourdian25/gourdiangin"
	"github.com/gourdian25/gourdianlogger"
)

func main() {
	// Create a new logger with default configuration
	logger, err := gourdianlogger.NewGourdianLogger(gourdianlogger.LoggerConfig{
		Filename:    "myapp.log",
		MaxBytes:    10 * 1024 * 1024, // 10MB
		BackupCount: 5,
		LogLevel:    gourdianlogger.INFO,
	})
	if err != nil {
		panic(err)
	}
	defer logger.Close()

	config := gourdiangin.ServerConfig{
		Port:            8443,
		UseTLS:          true,
		TLSCertFile:     "cert.pem",
		TLSKeyFile:      "key.pem",
		Logger:          logger,
		ShutdownTimeout: 30 * time.Second,
	}

	setup := &gourdiangin.ServerSetupImpl{}
	server := gourdiangin.NewGourdianGinServer(setup, config)

	router := server.GetRouter()
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Secure Hello, World!",
		})
	})

	if err := server.Start(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
```

---

### With CORS Example

This example demonstrates how to enable and configure CORS.

```go
package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gourdian25/gourdiangin"
	"github.com/gourdian25/gourdianlogger"
)

func main() {
	// Create a new logger with default configuration
	logger, err := gourdianlogger.NewGourdianLogger(gourdianlogger.LoggerConfig{
		Filename:    "myapp.log",
		MaxBytes:    10 * 1024 * 1024, // 10MB
		BackupCount: 5,
		LogLevel:    gourdianlogger.INFO,
	})
	if err != nil {
		panic(err)
	}
	defer logger.Close()

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"https://trusted-site.com"}
	corsConfig.AllowCredentials = true

	config := gourdiangin.ServerConfig{
		Port:            8080,
		UseTLS:          false,
		UseCORS:         true,
		CORSConfig:      corsConfig,
		Logger:          logger,
		ShutdownTimeout: 30 * time.Second,
	}

	setup := &gourdiangin.ServerSetupImpl{}
	server := gourdiangin.NewGourdianGinServer(setup, config)

	router := server.GetRouter()
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "CORS Enabled!",
		})
	})

	if err := server.Start(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
```

---

### Custom Middleware Example

This example demonstrates how to add custom middleware to the Gin router.

```go
package main

import (
	"github.com/gourdian25/gourdiangin"
	"github.com/gourdian25/gourdianlogger"
	"github.com/gin-gonic/gin"
)

func customMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

func main() {
	// Create a new logger with default configuration
	logger, err := gourdianlogger.NewGourdianLogger(gourdianlogger.LoggerConfig{
		Filename:    "myapp.log",
		MaxBytes:    10 * 1024 * 1024, // 10MB
		BackupCount: 5,
		LogLevel:    gourdianlogger.INFO,
	})
	if err != nil {
		panic(err)
	}
	defer logger.Close()

	config := gourdiangin.ServerConfig{
		Port:            8080,
		UseTLS:          false,
		UseCORS:         false,
		Logger:          logger,
		ShutdownTimeout: 30 * time.Second,
	}

	setup := &gourdiangin.ServerSetupImpl{}
	server := gourdiangin.NewGourdianGinServer(setup, config)

	router := server.GetRouter()
	router.Use(customMiddleware())
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Custom Middleware!",
		})
	})

	if err := server.Start(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
```

---

### Graceful Shutdown Example

This example demonstrates how to handle graceful shutdown.

```go
package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/gourdian25/gourdiangin"
	"github.com/gourdian25/gourdianlogger"
)

func main() {
	// Create a new logger with default configuration
	logger, err := gourdianlogger.NewGourdianLogger(gourdianlogger.LoggerConfig{
		Filename:    "myapp.log",
		MaxBytes:    10 * 1024 * 1024, // 10MB
		BackupCount: 5,
		LogLevel:    gourdianlogger.INFO,
	})
	if err != nil {
		panic(err)
	}
	defer logger.Close()

	config := gourdiangin.ServerConfig{
		Port:            8080,
		UseTLS:          false,
		UseCORS:         false,
		Logger:          logger,
		ShutdownTimeout: 30 * time.Second,
	}

	setup := &gourdiangin.ServerSetupImpl{}
	server := gourdiangin.NewGourdianGinServer(setup, config)

	router := server.GetRouter()
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Graceful Shutdown!",
		})
	})

	// Start server in a separate goroutine
	go func() {
		if err := server.Start(); err != nil {
			logger.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	server.GracefulShutdown()
	logger.Info("Server exited")
}
```

---

## Using Gourdian Logger

The `gourdianlogger` package is used for structured logging. It provides configurable log levels, file rotation, and more. Refer to the [gourdianlogger documentation](https://github.com/gourdian25/gourdianlogger) for detailed usage.

---

## API Reference

### ServerConfig

```go
type ServerConfig struct {
	Port            int
	UseTLS          bool
	UseCORS         bool
	TLSKeyFile      string
	TLSCertFile     string
	CORSConfig      cors.Config
	Logger          *gourdianlogger.Logger
	ShutdownTimeout time.Duration
}
```

### Server Interface

```go
type Server interface {
	Start() error
	GracefulShutdown()
	GetRouter() *gin.Engine
}
```

### ServerSetup Interface

```go
type ServerSetup interface {
	SetUpRouter(config ServerConfig) *gin.Engine
	SetUpTLS(config ServerConfig) (*tls.Config, error)
	SetUpCORS(router *gin.Engine, config ServerConfig)
	CheckPortAvailability(config ServerConfig) error
}
```

### GourdianGinServer

```go
type GourdianGinServer struct {
	router      *gin.Engine
	server      *http.Server
	serverSetup ServerSetup
	config      ServerConfig
	shutdownWg  sync.WaitGroup
	stopChan    chan os.Signal
}
```

### Methods

- `NewGourdianGinServer(setup ServerSetup, config ServerConfig) Server`
- `Start() error`
- `GracefulShutdown()`
- `GetRouter() *gin.Engine`
- `shutdown() error`

---

## Contributing

Contributions to `gourdiangin` are welcome! If you'd like to contribute, please follow these steps:

1. Fork the repository: [https://github.com/gourdian25/gourdiangin](https://github.com/gourdian25/gourdiangin).
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a detailed description of your changes.

---

## License

`gourdiangin` is open-source and licensed under the **MIT License**. See the [LICENSE](https://github.com/gourdian25/gourdiangin/blob/master/LICENSE) file for more details.

---

## Support

If you encounter any issues or have questions, please open an issue on the [GitHub repository](https://github.com/gourdian25/gourdiangin/issues).

---

## Author

`gourdiangin` is developed and maintained by [gourdian25](https://github.com/gourdian25) and [lordofthemind](https://github.com/lordofthemind).

---

Thank you for using `gourdiangin`! 🚀