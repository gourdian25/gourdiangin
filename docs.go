// Package gourdiangin provides a production-ready, modular, and extensible HTTP server
// implementation using the Gin web framework.
//
// Overview:
// Gourdiangin abstracts the complexity of setting up a secure, reliable, and customizable Gin-based server.
// It supports CORS, graceful shutdown, TLS, PID file management, request timeouts, and structured logging
// via the gourdianlogger package.
//
// Key Features:
// - Structured and graceful server setup using ServerConfig
// - Middleware-based request timeouts
// - Configurable CORS handling
// - TLS support with secure defaults
// - PID file management for process control
// - Graceful shutdown via signal handling
// - Port availability checking
// - Pluggable ServerSetup interface for full customization
// - Designed for production systems with reliable error handling
//
// Example Usage:
//
//	package main
//
//	import (
//	    "log"
//	    "time"
//
//	    "github.com/gin-contrib/cors"
//	    "github.com/gourdian25/gourdianlogger"
//	    "github.com/gourdian25/gourdiangin"
//	)
//
//	func main() {
//	    logger, err := gourdianlogger.NewGourdianLoggerWithDefault()
//	    if err != nil {
//	        log.Fatalf("Failed to create logger: %v", err)
//	    }
//	    defer logger.Close()
//
//	    config := gourdiangin.ServerConfig{
//	        Port:            8080,
//	        UseTLS:          false,
//	        UseCORS:         true,
//	        Logger:          logger,
//	        PIDFile:         "tmp/myapp.pid",
//	        RequestTimeout:  15 * time.Second,
//	        ShutdownTimeout: 20 * time.Second,
//	        CORSConfig: cors.Config{
//	            AllowOrigins:     []string{"*"},
//	            AllowMethods:     []string{"GET", "POST"},
//	            AllowHeaders:     []string{"Origin", "Content-Type"},
//	            AllowCredentials: true,
//	            MaxAge:           12 * time.Hour,
//	        },
//	    }
//
//	    server := gourdiangin.NewGourdianGinServer(&gourdiangin.ServerSetupImpl{}, config)
//
//	    router := server.GetRouter()
//	    router.GET("/", func(c *gin.Context) {
//	        c.JSON(200, gin.H{"message": "Welcome to Gourdiangin!"})
//	    })
//
//	    if err := server.Start(); err != nil {
//	        logger.Fatalf("Server failed: %v", err)
//	    }
//	}
//
// Stopping a Running Server:
// To stop a server gracefully using its PID file:
//
//	err := gourdiangin.StopProcessFromPIDFile("tmp/myapp.pid", nil)
//	if err != nil {
//	    log.Fatalf("Failed to stop process: %v", err)
//	}
//
// Custom Setup:
// You can customize the router, CORS, TLS, or port-checking behavior
// by implementing your own ServerSetup:
//
//	type MySetup struct {
//	    gourdiangin.ServerSetupImpl
//	}
//
//	func (m *MySetup) SetUpRouter(config gourdiangin.ServerConfig) *gin.Engine {
//	    r := gin.New()
//	    r.Use(gin.Recovery())
//	    return r
//	}
//
//	server := gourdiangin.NewGourdianGinServer(&MySetup{}, config)
//
// Best Practices:
// - Always defer logger.Close() to flush logs.
// - Use PIDFile in deployments to enable external shutdown.
// - Keep ShutdownTimeout longer than average request processing time.
// - Avoid setting CORS to AllowAllOrigins in production.
// - Enable TLS in production using proper certificate paths.
// - Use request timeout middleware for improved fault tolerance.
package gourdiangin
