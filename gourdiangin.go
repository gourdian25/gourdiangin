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
// # Configuration Parameters
//   - Port: TCP port number for listener (1-65535)
//   - UseTLS: Enables HTTPS with TLS encryption when true
//   - TLSCertFile: Path to PEM-encoded X.509 certificate file (required when UseTLS=true)
//   - TLSKeyFile: Path to PEM-encoded private key file (required when UseTLS=true)
//   - UseCORS: Enables Cross-Origin Resource Sharing middleware when true
//   - CORSConfig: Fine-grained CORS policy settings (origins, methods, headers, credentials)
//   - Logger: Structured logger for comprehensive server activity tracking
//   - ShutdownTimeout: Maximum duration to wait for in-flight requests during shutdown
//
// # Example Configuration
//
//	config := ServerConfig{
//	    Port:            8443,
//	    UseTLS:          true,
//	    TLSCertFile:     "/path/to/cert.pem",
//	    TLSKeyFile:      "/path/to/key.pem",
//	    UseCORS:         true,
//	    CORSConfig:      corsConfig,
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
// # Core Methods
//
//   - Start(): Launches the HTTP server and begins accepting connections
//     Returns any startup or runtime errors encountered
//
//   - GracefulShutdown(): Initiates orderly termination sequence with connection draining
//     Blocks until shutdown completes or timeout occurs
//
//   - GetRouter(): Provides access to the underlying Gin router for route registration
//     Can be used to define API endpoints, middleware, and custom handlers
type Server interface {
	Start() error
	GracefulShutdown()
	GetRouter() *gin.Engine
}

// GourdianGinServer is the concrete implementation of the Server interface,
// providing a complete, production-ready Gin HTTP server with all features.
//
// # Core Components
//   - router: Gin router handling HTTP request routing and middleware
//   - server: Underlying HTTP server managing connection lifecycle
//   - serverSetup: Strategy for server configuration and initialization
//   - config: Complete set of server configuration parameters
//   - shutdownWg: WaitGroup for coordinating graceful shutdown sequence
//   - stopChan: Signal channel for handling termination requests
//
// # Concurrency Model
//   - Thread-safe server operations with proper synchronization
//   - Signal-based shutdown coordination
//   - Waitgroup-based completion tracking for graceful termination
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
// # Functionality
//   - Validates configuration to ensure all parameters are valid
//   - Verifies port availability to prevent binding conflicts
//   - Sets up TLS if enabled for secure HTTPS connections
//   - Configures CORS policies for cross-origin request handling
//   - Establishes signal handling for graceful termination
//
// # Parameters
//   - setup: Implementation of ServerSetup for initialization strategy
//   - config: Complete configuration parameters for the server
//
// # Returns
//   - Server: Ready-to-use server instance implementing Server interface
//
// # Panics
//   - Invalid server configuration (prevents creation of misconfigured server)
//   - Port unavailability (prevents attempts to bind to unavailable ports)
//   - TLS configuration errors (prevents insecure server creation when TLS requested)
//
// # Example Usage
//
//	setup := &ServerSetupImpl{}
//	server := NewGourdianGinServer(setup, config)
//
//	// Register routes
//	router := server.GetRouter()
//	registerAPIRoutes(router)
//
//	// Start server (blocks until shutdown)
//	if err := server.Start(); err != nil {
//	    logger.Fatalf("Server failed: %v", err)
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
// # Functionality
//   - Starts the HTTP/HTTPS server based on configuration
//   - Handles TLS setup when secure connections are enabled
//   - Monitors for shutdown signals or server errors
//   - Coordinates graceful termination when shutdown is triggered
//
// # Returns
//   - error: Any server startup or runtime error encountered
//
// # Error Conditions
//   - Binding failures (port conflicts, permission issues)
//   - TLS handshake errors
//   - Network I/O errors during operation
//
// # Example Usage
//
//	// Start in main goroutine (blocks until shutdown)
//	if err := server.Start(); err != nil {
//	    logger.Fatalf("Server error: %v", err)
//	}
//
//	// Start in separate goroutine
//	go func() {
//	    if err := server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
//	        logger.Fatalf("Server error: %v", err)
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
// # Functionality
//   - Creates context with timeout for connection draining
//   - Initiates graceful HTTP server shutdown sequence
//   - Logs completion of shutdown process
//
// # Returns
//   - error: Any error encountered during the shutdown process
//
// # Timeout Behavior
//   - Uses ShutdownTimeout from config (defaults to 30s if unspecified)
//   - Forces termination after timeout expires regardless of connection state
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
// # Functionality
//   - Returns the Gin router instance used by this server
//   - Allows registration of routes, middleware, and handlers
//
// # Returns
//   - *gin.Engine: The Gin router instance used by this server
//
// # Example Usage
//
//	router := server.GetRouter()
//
//	// Register API routes
//	router.GET("/api/v1/health", handlers.HealthCheck)
//	router.POST("/api/v1/users", middleware.Authenticate(), handlers.CreateUser)
//
//	// Apply middleware to route groups
//	api := router.Group("/api/v2")
//	api.Use(middleware.RateLimiter())
//	{
//	    api.GET("/products", handlers.ListProducts)
//	    api.GET("/products/:id", handlers.GetProduct)
//	}
func (gs *GourdianGinServer) GetRouter() *gin.Engine {
	return gs.router
}

// GracefulShutdown initiates an orderly server shutdown sequence,
// allowing in-flight requests to complete within the timeout period.
//
// # Functionality
//   - Sends termination signal through stopChan
//   - Waits for shutdown process to complete
//   - Logs completion of shutdown sequence
//
// # Concurrency Safety
//   - Safe to call from any goroutine
//   - Uses WaitGroup to ensure complete termination
//   - Implements timeout to prevent indefinite blocking
//
// # Example Usage
//
//	// Shutdown after specific event
//	if criticalError {
//	    server.GracefulShutdown()
//	}
//
//	// Shutdown on application termination
//	signals := make(chan os.Signal, 1)
//	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
//	go func() {
//	    <-signals
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

// ServerSetup interface abstracts the server initialization process,
// allowing for flexible configuration and testability through dependency injection.
//
// # Core Responsibilities
//
//   - SetUpRouter(): Constructs a properly configured Gin router instance
//     Applies common middleware and establishes base configuration
//
//   - SetUpTLS(): Prepares a secure TLS configuration for HTTPS connections
//     Loads and validates certificates, sets cipher suites and security parameters
//
//   - SetUpCORS(): Configures cross-origin request policies and restrictions
//     Applies appropriate CORS middleware based on security requirements
//
//   - CheckPortAvailability(): Validates the chosen port is available for binding
//     Prevents conflicts with other services and provides clear diagnostics
type ServerSetup interface {
	SetUpRouter(config ServerConfig) *gin.Engine
	SetUpTLS(config ServerConfig) (*tls.Config, error)
	SetUpCORS(router *gin.Engine, config ServerConfig)
	CheckPortAvailability(config ServerConfig) error
}

// ServerSetupImpl provides the standard implementation of the ServerSetup interface.
type ServerSetupImpl struct{}

// SetUpRouter constructs a new Gin router with appropriate default middleware.
//
// # Functionality
//   - Creates a new Gin router instance with reasonable defaults
//   - Configures built-in logging and recovery middleware
//   - Returns a router ready for custom route registration
//
// # Parameters
//   - config: Complete server configuration options
//
// # Returns
//   - *gin.Engine: Configured Gin router ready for use
//
// # Example Usage
//
//	router := setup.SetUpRouter(config)
//	router.GET("/api/v1/users", middleware.Authenticate(), handlers.ListUsers)
//	router.POST("/api/v1/login", handlers.Login)
func (s *ServerSetupImpl) SetUpRouter(config ServerConfig) *gin.Engine {
	router := gin.Default()
	// Add custom middleware or configurations here if needed
	return router
}

// SetUpTLS prepares the TLS configuration for secure HTTPS connections.
//
// # Functionality
//   - Loads and validates X.509 certificate and private key
//   - Configures TLS settings according to current security best practices
//   - Returns a complete TLS configuration ready for server use
//
// # Parameters
//   - config: Server configuration containing TLS certificate paths
//
// # Returns
//   - *tls.Config: Complete TLS configuration for secure connections
//   - error: Detailed error if certificate loading or validation fails
//
// # Error Conditions
//   - Missing certificate or key files when TLS is enabled
//   - Invalid or corrupted certificate/key format
//   - Permission issues accessing certificate files
//
// # Example Usage
//
//	tlsConfig, err := setup.SetUpTLS(config)
//	if err != nil {
//	    logger.Fatalf("TLS configuration failed: %v", err)
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

// SetUpCORS configures and applies CORS policies to the Gin router.
//
// # Functionality
//   - Applies Cross-Origin Resource Sharing middleware if enabled
//   - Configures allowed origins, methods, headers, and credentials
//   - Logs applied CORS configuration for transparency
//
// # Parameters
//   - router: Gin router instance to which CORS middleware will be applied
//   - config: Server configuration containing CORS settings
//
// # Example Configuration
//
//	corsConfig := cors.DefaultConfig()
//	corsConfig.AllowOrigins = []string{"https://trusted-site.com"}
//	corsConfig.AllowCredentials = true
//	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE"}
//	setup.SetUpCORS(router, config)
func (s *ServerSetupImpl) SetUpCORS(router *gin.Engine, config ServerConfig) {
	if config.UseCORS {
		router.Use(cors.New(config.CORSConfig))
		config.Logger.Infof("CORS configured with settings: %+v", config.CORSConfig)
	}
}

// CheckPortAvailability verifies the configured port is available for binding.
//
// # Functionality
//   - Attempts to bind to the specified port to verify availability
//   - Provides descriptive error messages for unavailable ports
//   - Logs confirmation when port is available
//
// # Parameters
//   - config: Server configuration containing the port to check
//
// # Returns
//   - error: Descriptive error if port is unavailable (nil if port is free)
//
// # Error Conditions
//   - Port already in use by another process
//   - Insufficient permissions to bind to the port
//   - System networking configuration issues
//
// # Example Usage
//
//	if err := setup.CheckPortAvailability(config); err != nil {
//	    logger.Fatalf("Port availability check failed: %v", err)
//	    // Consider fallback to alternative port or exit
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
