// Package gourdiangin implements a production-ready, thread-safe HTTP server
// built on the Gin framework with enterprise-grade features including:
//
// # Core Features
//   - Robust TLS configuration with certificate validation and secure defaults
//   - Comprehensive CORS policy management for cross-origin requests
//   - Graceful shutdown with configurable connection draining timeouts
//   - Thread-safe server operations with proper synchronization primitives
//   - Port availability verification to prevent startup conflicts
//   - Structured logging integration via gourdianlogger
//
// # Architecture Highlights
//   - Clear separation of concerns through interface-based design
//   - Highly testable components with dependency injection support
//   - Defensive configuration validation to prevent runtime errors
//   - Concurrent request handling with proper resource cleanup
//   - Signal-based shutdown coordination (SIGTERM/SIGINT)
//
// # Usage Example
//
//	logger := gourdianlogger.New(gourdianlogger.Config{Level: "info"})
//	corsConfig := cors.DefaultConfig()
//	corsConfig.AllowOrigins = []string{"https://example.com"}
//
//	config := gourdiangin.ServerConfig{
//	    Port:            8443,
//	    UseTLS:          true,
//	    TLSCertFile:     "/path/to/cert.pem",
//	    TLSKeyFile:      "/path/to/key.pem",
//	    UseCORS:         true,
//	    CORSConfig:      corsConfig,
//	    Logger:          logger,
//	    ShutdownTimeout: 30 * time.Second,
//	}
//
//	setup := &gourdiangin.ServerSetupImpl{}
//	server := gourdiangin.NewGourdianGinServer(setup, config)
//
//	// Register routes
//	router := server.GetRouter()
//	router.GET("/api/v1/health", handlers.HealthCheck)
//
//	// Start server (blocks until shutdown)
//	if err := server.Start(); err != nil {
//	    logger.Fatalf("Server failed: %v", err)
//	}
package gourdiangin
