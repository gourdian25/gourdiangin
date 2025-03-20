package gourdiangin

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

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
