// Package gourdiangin provides a modular and thread-safe Gin server implementation
// with comprehensive support for TLS, CORS, and graceful shutdown mechanisms.
//
// Key Features:
// - Highly configurable Gin server with robust TLS and CORS support
// - Sophisticated graceful shutdown with customizable timeout
// - Thread-safe server operations with proper synchronization
// - Seamless integration with gourdianlogger for structured, contextual logging
// - Port availability verification to prevent binding conflicts
// - Clean modular architecture enabling straightforward customization and extension
package gourdiangin

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gourdian25/gourdianlogger"
)

// ServerConfig encapsulates all configuration options for the Gin server setup.
//
// Fields:
//   - Port: The TCP port number the server will listen on
//   - UseTLS: Boolean flag to enable/disable TLS encryption (HTTPS)
//   - TLSCertFile: Filesystem path to the TLS certificate file (mandatory when UseTLS=true)
//   - TLSKeyFile: Filesystem path to the TLS private key file (mandatory when UseTLS=true)
//   - UseCORS: Boolean flag to enable/disable Cross-Origin Resource Sharing
//   - CORSConfig: Detailed configuration for CORS policies and allowed origins
//   - Logger: Structured logger instance for comprehensive server activity tracking
//   - ShutdownTimeout: Maximum duration to wait for connections to close during shutdown
//
// Example:
//
//	config := ServerConfig{
//	    Port:            8080,
//	    UseTLS:          true,
//	    TLSCertFile:     "cert.pem",
//	    TLSKeyFile:      "key.pem",
//	    UseCORS:         true,
//	    CORSConfig:      cors.DefaultConfig(),
//	    Logger:          logger,
//	    ShutdownTimeout: 30 * time.Second,
//	}
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

// Validate checks if the ServerConfig fields are valid.
func (c ServerConfig) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", c.Port)
	}
	if c.UseTLS && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		return errors.New("TLS certificate and key files must be provided when UseTLS is true")
	}
	if c.Logger == nil {
		return errors.New("logger must be provided")
	}
	return nil
}

// Server interface defines the core functionality of a Gin HTTP server.
//
// Methods:
//   - Start(): Initializes and launches the server, returning any startup errors
//   - GracefulShutdown(): Initiates an orderly shutdown sequence, waiting for connections to complete
//   - GetRouter(): Provides access to the underlying Gin router for route registration
type Server interface {
	Start() error
	GracefulShutdown()
	GetRouter() *gin.Engine
}

// ServerSetup interface abstracts the server initialization process,
// allowing for flexible configuration and potential mocking in tests.
//
// Methods:
//   - SetUpRouter(): Constructs and configures a new Gin router instance
//   - SetUpTLS(): Prepares TLS configuration based on certificate settings
//   - SetUpCORS(): Applies CORS middleware with appropriate policies
//   - CheckPortAvailability(): Verifies the configured port is available for binding
type ServerSetup interface {
	SetUpRouter(config ServerConfig) *gin.Engine
	SetUpTLS(config ServerConfig) (*tls.Config, error)
	SetUpCORS(router *gin.Engine, config ServerConfig)
	CheckPortAvailability(config ServerConfig) error
}

// ServerSetupImpl provides the standard implementation of the ServerSetup interface.
type ServerSetupImpl struct{}

// SetUpRouter constructs a new Gin router with sensible defaults.
//
// Parameters:
//   - config: Complete server configuration options
//
// Returns:
//   - *gin.Engine: Fully configured Gin router ready for route registration
//
// Example:
//
//	router := setup.SetUpRouter(config)
//	router.GET("/ping", handlePing)
func (s *ServerSetupImpl) SetUpRouter(config ServerConfig) *gin.Engine {
	router := gin.Default()
	// Add custom middleware or configurations here if needed
	return router
}

// SetUpTLS prepares the TLS configuration for secure HTTPS connections.
//
// Parameters:
//   - config: Server configuration containing TLS certificate paths
//
// Returns:
//   - *tls.Config: Complete TLS configuration ready for server use
//   - error: Detailed error if TLS setup fails (nil on success)
//
// Example:
//
//	tlsConfig, err := setup.SetUpTLS(config)
//	if err != nil {
//	    config.Logger.Fatalf("TLS configuration failed: %v", err)
//	}
func (s *ServerSetupImpl) SetUpTLS(config ServerConfig) (*tls.Config, error) {
	if !config.UseTLS {
		return nil, nil
	}

	if config.TLSCertFile == "" || config.TLSKeyFile == "" {
		return nil, fmt.Errorf("TLS certificate and key files must be provided when UseTLS is true")
	}

	cert, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		config.Logger.Errorf("Failed to load TLS certificate: %v", err)
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return tlsConfig, nil
}

// SetUpCORS configures and applies CORS policies to control cross-origin requests.
//
// Parameters:
//   - router: Gin router instance to which CORS middleware will be applied
//   - config: Server configuration containing CORS settings
//
// Example:
//
//	setup.SetUpCORS(router, config)
//	// Router now has CORS middleware applied
func (s *ServerSetupImpl) SetUpCORS(router *gin.Engine, config ServerConfig) {
	if config.UseCORS {
		router.Use(cors.New(config.CORSConfig))
		config.Logger.Infof("CORS configured with settings: %+v", config.CORSConfig)
	}
}

// CheckPortAvailability verifies the configured port is available for binding.
//
// Parameters:
//   - config: Server configuration containing the port to check
//
// Returns:
//   - error: Descriptive error if port is unavailable (nil if port is free)
//
// Example:
//
//	if err := setup.CheckPortAvailability(config); err != nil {
//	    config.Logger.Fatalf("Cannot start server: %v", err)
//	}
func (s *ServerSetupImpl) CheckPortAvailability(config ServerConfig) error {
	address := fmt.Sprintf(":%d", config.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		if strings.Contains(err.Error(), "bind: address already in use") {
			return fmt.Errorf("port %d is already in use; please choose a different port or stop the process using this port", config.Port)
		}
		return fmt.Errorf("failed to check port availability: %w", err)
	}
	listener.Close()
	config.Logger.Infof("Port %d is available", config.Port)
	return nil
}

// GourdianGinServer is the concrete implementation of the Server interface,
// providing a complete, production-ready Gin HTTP server with all features.
//
// Fields:
//   - router: Gin router handling HTTP request routing and middleware
//   - server: Underlying HTTP server instance managing connections
//   - serverSetup: Strategy for server configuration and initialization
//   - config: Complete server configuration parameters
//   - shutdownWg: WaitGroup coordinating graceful shutdown sequence
//   - stopChan: Signal channel for handling termination requests
type GourdianGinServer struct {
	router      *gin.Engine
	server      *http.Server
	serverSetup ServerSetup
	config      ServerConfig
	shutdownWg  sync.WaitGroup
	stopChan    chan os.Signal
}

// NewGourdianGinServer constructs a fully configured Server instance ready to start.
//
// Parameters:
//   - setup: Implementation of ServerSetup for initialization strategy
//   - config: Complete configuration parameters for the server
//
// Returns:
//   - Server: Ready-to-use server instance
//
// Example:
//
//	setup := &ServerSetupImpl{}
//	server := NewGourdianGinServer(setup, config)
//	if err := server.Start(); err != nil {
//	    log.Fatalf("Server failed: %v", err)
//	}
func NewGourdianGinServer(setup ServerSetup, config ServerConfig) Server {
	if err := config.Validate(); err != nil {
		panic(fmt.Sprintf("Invalid server configuration: %v", err))
	}

	// Check port availability
	if err := setup.CheckPortAvailability(config); err != nil {
		config.Logger.Fatalf("%v", err)
	}

	router := setup.SetUpRouter(config)
	setup.SetUpCORS(router, config)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: router,
	}

	tlsConfig, err := setup.SetUpTLS(config)
	if err != nil {
		config.Logger.Fatalf("Error setting up TLS: %v", err)
	}
	server.TLSConfig = tlsConfig

	// Create stop channel for shutdown signals
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	return &GourdianGinServer{
		router:      router,
		server:      server,
		serverSetup: setup,
		config:      config,
		stopChan:    stopChan,
	}
}

// Start launches the HTTP server and begins accepting connections.
// It blocks until server shutdown is triggered by signals or errors.
//
// Returns:
//   - error: Any server startup or runtime error encountered
//
// Example:
//
//	go func() {
//	    if err := server.Start(); err != nil {
//	        log.Fatalf("Server error: %v", err)
//	    }
//	}()
func (gs *GourdianGinServer) Start() error {
	gs.shutdownWg.Add(1)
	defer gs.shutdownWg.Done()

	serverErr := make(chan error, 1)
	go func() {
		if gs.config.UseTLS {
			gs.config.Logger.Infof("Starting server on port %d with TLS", gs.config.Port)
			if err := gs.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				gs.config.Logger.Errorf("Server error: %v", err)
				serverErr <- err
			}
		} else {
			gs.config.Logger.Infof("Starting server on port %d without TLS", gs.config.Port)
			if err := gs.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				gs.config.Logger.Errorf("Server error: %v", err)
				serverErr <- err
			}
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	case <-gs.stopChan:
		gs.config.Logger.Info("Received shutdown signal")
		return gs.shutdown()
	}
}

// shutdown performs the actual graceful termination sequence for the server.
// It allows existing connections to complete within the configured timeout.
//
// Returns:
//   - error: Any error encountered during the shutdown process
func (gs *GourdianGinServer) shutdown() error {
	gs.config.Logger.Info("Shutting down server...")

	// Use configurable timeout
	timeout := gs.config.ShutdownTimeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := gs.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	gs.config.Logger.Info("Server shutdown complete")
	return nil
}

// GetRouter provides access to the underlying Gin router for route registration.
//
// Returns:
//   - *gin.Engine: The Gin router instance used by this server
//
// Example:
//
//	router := server.GetRouter()
//	router.GET("/health", func(c *gin.Context) {
//	    c.JSON(http.StatusOK, gin.H{"status": "healthy"})
//	})
func (gs *GourdianGinServer) GetRouter() *gin.Engine {
	return gs.router
}

// GracefulShutdown initiates an orderly server shutdown sequence,
// allowing in-flight requests to complete within the timeout period.
//
// Example:
//
//	// In a separate goroutine or signal handler:
//	go func() {
//	    <-shutdownTrigger
//	    server.GracefulShutdown()
//	}()
func (gs *GourdianGinServer) GracefulShutdown() {
	select {
	case gs.stopChan <- syscall.SIGTERM:
		// Signal sent successfully
		gs.config.Logger.Info("SIGTERM signal sent to server")
	case <-time.After(1 * time.Second):
		gs.config.Logger.Warn("Failed to send shutdown signal: stopChan may be closed")
	}

	// Wait for shutdown to complete
	gs.shutdownWg.Wait()
	gs.config.Logger.Info("Server shutdown completed")
}
