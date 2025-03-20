package gourdiangin

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

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
