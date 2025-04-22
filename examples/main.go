package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gourdian25/gourdiangin"
	"github.com/gourdian25/gourdianlogger"
)

var startTime = time.Now()

func main() {
	// Create a logger
	logger, err := gourdianlogger.NewGourdianLoggerWithDefault()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Configure the server
	config := gourdiangin.ServerConfig{
		Port:            8080,
		PIDFile:         "tmp/myapp.pid",
		UseTLS:          false, // Set to true for HTTPS
		UseCORS:         true,
		Logger:          logger,
		RequestTimeout:  15 * time.Second,
		ShutdownTimeout: 20 * time.Second,
		CORSConfig: cors.Config{
			AllowOrigins:     []string{"*"},
			AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
			ExposeHeaders:    []string{"Content-Length"},
			AllowCredentials: true,
			MaxAge:           12 * time.Hour,
		},
		// If using TLS:
		// TLSCertFile: "cert.pem",
		// TLSKeyFile:  "key.pem",
	}

	// Create the server
	server := gourdiangin.NewGourdianGinServer(&gourdiangin.ServerSetupImpl{}, config)

	// Add some routes
	router := server.GetRouter()
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome to the Gourdian Gin Server!",
		})
	})

	// Enhanced health check with more information
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":   "healthy",
			"version":  "1.0.0",
			"uptime":   time.Since(startTime).String(),
			"services": []string{"database", "cache", "storage"},
		})
	})

	router.GET("/api/data", func(c *gin.Context) {
		// Simulate a long-running request to test timeout
		// time.Sleep(20 * time.Second) // Uncomment to test timeout
		c.JSON(200, gin.H{
			"data": "Some important data",
		})
	})

	// Handle graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			logger.Errorf("Server error: %v", err)
			serverErr <- err
		}
	}()

	select {
	case <-signalChan:
		logger.Info("Shutdown signal received")
		server.GracefulShutdown()
	case err := <-serverErr:
		logger.Errorf("Server error: %v", err)
	}

}

// package main

// import (
// 	"time"
// 	"github.com/gin-gonic/gin"
// 	"github.com/gourdian25/gourdianlogger"
// 	"path/to/gourdiangin"
// )

// func main() {
// 	// Create a logger
// 	logger, _ := gourdianlogger.NewGourdianLoggerWithDefault()
// 	defer logger.Close()

// 	// Configure the server
// 	config := gourdiangin.ServerConfig{
// 		Port:            8080,
// 		UseTLS:          false,
// 		UseCORS:         true,
// 		PIDFile:         "/tmp/gourdian-gin.pid",
// 		Logger:          logger,
// 		ShutdownTimeout: 30 * time.Second,
// 		RequestTimeout:  15 * time.Second,
// 		CORSConfig: cors.Config{
// 			AllowOrigins:     []string{"*"},
// 			AllowMethods:     []string{"GET", "POST"},
// 			AllowHeaders:     []string{"Origin", "Content-Type"},
// 			ExposeHeaders:    []string{"Content-Length"},
// 			AllowCredentials: true,
// 			MaxAge:           12 * time.Hour,
// 		},
// 	}

// 	// Create server with default setup
// 	server := gourdiangin.NewGourdianGinServer(&gourdiangin.ServerSetupImpl{}, config)

// 	// Set up routes
// 	router := server.GetRouter()
// 	router.GET("/", func(c *gin.Context) {
// 		c.JSON(200, gin.H{"message": "Welcome to GourdianGin"})
// 	})

// 	router.GET("/slow", func(c *gin.Context) {
// 		time.Sleep(20 * time.Second) // Will timeout due to RequestTimeout
// 		c.JSON(200, gin.H{"message": "This should timeout"})
// 	})

// 	// Start server
// 	logger.Info("Starting server...")
// 	if err := server.Start(); err != nil {
// 		logger.Fatalf("Server failed: %v", err)
// 	}
// }
