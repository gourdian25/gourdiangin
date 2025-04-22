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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
	"github.com/gourdian25/gourdianlogger"
)

// ServerConfig defines the configuration options for the GourdianGin server.
//
// Fields:
//   - Port: The port number to listen on (1-65535)
//   - UseTLS: Whether to enable TLS/HTTPS
//   - UseCORS: Whether to enable CORS middleware
//   - TLSKeyFile: Path to TLS key file (required if UseTLS is true)
//   - TLSCertFile: Path to TLS certificate file (required if UseTLS is true)
//   - PIDFile: Path to write the process ID file (optional)
//   - CORSConfig: Configuration for CORS middleware
//   - Logger: Custom logger instance (will create default if nil)
//   - ShutdownTimeout: Duration to wait for graceful shutdown (default 30s)
//   - RequestTimeout: Timeout for HTTP requests (must be > 0)
//
// Example:
//
//	config := ServerConfig{
//	    Port:           8080,
//	    UseTLS:         false,
//	    RequestTimeout: 10 * time.Second,
//	    Logger:         myCustomLogger,
//	}
type ServerConfig struct {
	Port            int
	UseTLS          bool
	UseCORS         bool
	TLSKeyFile      string
	TLSCertFile     string
	PIDFile         string
	CORSConfig      cors.Config
	Logger          *gourdianlogger.Logger
	ShutdownTimeout time.Duration
	RequestTimeout  time.Duration
}

// Validate checks the server configuration for correctness.
//
// Checks:
//   - Port is in valid range (1-65535)
//   - TLS files are provided if TLS is enabled
//   - Request timeout is positive
//
// Returns:
//   - error describing any validation failures
//
// Example:
//
//	config := ServerConfig{Port: 8080}
//	if err := config.Validate(); err != nil {
//	    // Handle invalid config
//	}
func (c ServerConfig) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", c.Port)
	}
	if c.UseTLS && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		return errors.New("TLS certificate and key files must be provided when UseTLS is true")
	}
	if c.RequestTimeout <= 0 {
		return errors.New("request timeout must be greater than 0")
	}
	return nil
}

// Server defines the interface for the GourdianGin server.
//
// Implementations should provide:
//   - Start(): Start the server and listen for requests
//   - GracefulShutdown(): Initiate a graceful shutdown
//   - GetRouter(): Access the Gin router for route registration
//   - GetServer(): Access the underlying HTTP server
//
// Example:
//
//	server := NewGourdianGinServer(&ServerSetupImpl{}, config)
//	router := server.GetRouter()
//	router.GET("/", func(c *gin.Context) { c.String(200, "Hello") })
//	go server.Start()
//	// Later...
//	server.GracefulShutdown()
type Server interface {
	Start() error
	GracefulShutdown()
	GetRouter() *gin.Engine
	GetServer() *http.Server
}

// GourdianGinServer implements the Server interface with Gin as the HTTP engine.
//
// It provides:
//   - Graceful startup and shutdown
//   - PID file management
//   - TLS support
//   - Request timeouts
//   - CORS configuration
//
// Create using NewGourdianGinServer() rather than direct instantiation.
type GourdianGinServer struct {
	router      *gin.Engine
	server      *http.Server
	serverSetup ServerSetup
	config      ServerConfig
	shutdownWg  sync.WaitGroup
	stopChan    chan os.Signal
}

// NewGourdianGinServer creates a new configured GourdianGin server instance.
//
// Parameters:
//   - setup: ServerSetup implementation for customizing server behavior
//   - config: Server configuration
//
// Returns:
//   - A ready-to-use Server instance
//
// Example:
//
//	setup := &ServerSetupImpl{}
//	config := ServerConfig{
//	    Port: 8080,
//	    RequestTimeout: 10 * time.Second,
//	}
//	server := NewGourdianGinServer(setup, config)
//	server.GetRouter().GET("/", func(c *gin.Context) {
//	    c.JSON(200, gin.H{"message": "Hello"})
//	})
//	if err := server.Start(); err != nil {
//	    log.Fatal(err)
//	}
func NewGourdianGinServer(setup ServerSetup, config ServerConfig) Server {
	if config.Logger == nil {
		logger, err := gourdianlogger.NewGourdianLoggerWithDefault()
		if err != nil {
			panic(fmt.Sprintf("Failed to create default logger: %v", err))
		}
		defer logger.Close()
		config.Logger = logger
	}

	if err := config.Validate(); err != nil {
		config.Logger.Fatalf("Invalid server configuration: %v", err)
	}

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

// GetServer returns the underlying http.Server instance.
//
// Useful for advanced configuration not exposed through ServerConfig.
//
// Returns:
//   - *http.Server: The HTTP server instance
//
// Example:
//
//	server := NewGourdianGinServer(setup, config)
//	httpServer := server.GetServer()
//	httpServer.ReadTimeout = 5 * time.Second
func (gs *GourdianGinServer) GetServer() *http.Server {
	return gs.server
}

func (gs *GourdianGinServer) createPIDFile() error {
	if gs.config.PIDFile == "" {
		return nil
	}

	pid := os.Getpid()
	pidDir := filepath.Dir(gs.config.PIDFile)

	if err := os.MkdirAll(pidDir, 0755); err != nil {
		return fmt.Errorf("failed to create PID directory: %w", err)
	}

	if err := os.WriteFile(gs.config.PIDFile, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		return fmt.Errorf("failed to create PID file: %w", err)
	}

	gs.config.Logger.Infof("Created PID file at %s with PID %d", gs.config.PIDFile, pid)
	return nil
}

func (gs *GourdianGinServer) removePIDFile() error {
	if gs.config.PIDFile == "" {
		return nil
	}

	if err := os.Remove(gs.config.PIDFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove PID file: %w", err)
	}

	gs.config.Logger.Infof("Removed PID file at %s", gs.config.PIDFile)
	return nil
}

// StopProcessFromPIDFile stops a running server process by reading its PID from a file.
//
// Parameters:
//   - pidFile: Path to the PID file
//   - logger: Optional logger (will create default if nil)
//
// Returns:
//   - error if any critical error occurs during shutdown
//
// Example:
//
//	err := StopProcessFromPIDFile("/var/run/server.pid", nil)
//	if err != nil {
//	    log.Fatalf("Failed to stop process: %v", err)
//	}
func StopProcessFromPIDFile(pidFile string, logger *gourdianlogger.Logger) error {
	if logger == nil {
		logger, _ = gourdianlogger.NewGourdianLoggerWithDefault()
		defer logger.Close()
	}

	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warnf("PID file (%s) does not exist; server may not be running", pidFile)
			return nil
		}
		return fmt.Errorf("failed to read PID file (%s): %w", pidFile, err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		return fmt.Errorf("failed to parse PID: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		logger.Warnf("Process %d not found (may already be terminated)", pid)
		if removeErr := os.Remove(pidFile); removeErr != nil && !os.IsNotExist(removeErr) {
			logger.Errorf("Failed to remove stale PID file: %v", removeErr)
		}
		return nil
	}

	logger.Infof("Sending SIGTERM to process %d", pid)
	if err := process.Signal(syscall.SIGTERM); err != nil {
		if err.Error() == "os: process already finished" ||
			strings.Contains(err.Error(), "no such process") {
			logger.Warnf("Process %d is already terminated", pid)
			if removeErr := os.Remove(pidFile); removeErr != nil && !os.IsNotExist(removeErr) {
				logger.Errorf("Failed to remove stale PID file: %v", removeErr)
			}
			return nil
		}
		return fmt.Errorf("failed to send SIGTERM to process: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := process.Wait()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			if strings.Contains(err.Error(), "no child processes") {
				logger.Warnf("Process %d already terminated", pid)
			} else {
				logger.Warnf("Process wait returned error: %v", err)
			}
		}
	case <-time.After(5 * time.Second):
		logger.Warnf("Timeout waiting for process %d to terminate", pid)
	}

	if err := os.Remove(pidFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove PID file: %w", err)
	}

	logger.Infof("Successfully stopped process %d", pid)
	return nil
}

// Start begins listening for HTTP requests and blocks until shutdown.
//
// Features:
//   - Creates PID file if configured
//   - Starts HTTP or HTTPS server based on config
//   - Handles shutdown signals
//   - Cleans up PID file on exit
//
// Returns:
//   - error if server fails to start or shutdown properly
//
// Example:
//
//	server := NewGourdianGinServer(setup, config)
//	if err := server.Start(); err != nil {
//	    log.Fatal(err)
//	}
func (gs *GourdianGinServer) Start() error {
	gs.shutdownWg.Add(1)
	defer gs.shutdownWg.Done()

	if err := gs.createPIDFile(); err != nil {
		return fmt.Errorf("failed to create PID file: %w", err)
	}
	defer gs.removePIDFile()

	serverErr := make(chan error, 1)
	go func() {
		var err error
		if gs.config.UseTLS {
			gs.config.Logger.Infof("Starting server on port %d with TLS", gs.config.Port)
			err = gs.server.ListenAndServeTLS("", "")
		} else {
			gs.config.Logger.Infof("Starting server on port %d without TLS", gs.config.Port)
			err = gs.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			gs.config.Logger.Errorf("Server error: %v", err)
			serverErr <- err
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

// GracefulShutdown initiates a graceful shutdown of the server.
//
// Behavior:
//   - Sends shutdown signal to server
//   - Waits for active connections to complete
//   - Times out after ShutdownTimeout + 5s buffer
//
// Example:
//
//	server := NewGourdianGinServer(setup, config)
//	go server.Start()
//	// On SIGTERM or other shutdown need:
//	server.GracefulShutdown()
func (gs *GourdianGinServer) shutdown() error {
	gs.config.Logger.Info("Shutting down server...")

	timeout := gs.config.ShutdownTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := gs.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	gs.config.Logger.Info("Server shutdown complete")
	return nil
}

// GetRouter returns the Gin router instance for route registration.
//
// This allows adding routes and middleware before starting the server.
//
// Returns:
//   - *gin.Engine: The Gin router instance
//
// Example:
//
//	server := NewGourdianGinServer(setup, config)
//	router := server.GetRouter()
//	router.GET("/", func(c *gin.Context) {
//	    c.String(200, "Hello World")
//	})
func (gs *GourdianGinServer) GetRouter() *gin.Engine {
	return gs.router
}

func (gs *GourdianGinServer) GracefulShutdown() {
	select {
	case gs.stopChan <- syscall.SIGTERM:
		gs.config.Logger.Info("SIGTERM signal sent to server")
	case <-time.After(1 * time.Second):
		gs.config.Logger.Warn("Failed to send shutdown signal: stopChan may be closed")
	}

	done := make(chan struct{})
	go func() {
		gs.shutdownWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		gs.config.Logger.Info("Server shutdown completed")
	case <-time.After(gs.config.ShutdownTimeout + 5*time.Second):
		gs.config.Logger.Error("Server shutdown timed out")
	}
}

// ServerSetup defines the interface for customizing server setup behavior.
//
// Implementations should provide methods for:
//   - Router setup
//   - TLS configuration
//   - CORS setup
//   - Port availability checking
//
// The default implementation is ServerSetupImpl.
//
// Example of custom setup:
//
//	type MyCustomSetup struct {
//	    ServerSetupImpl // embed default implementation
//	}
//
//	func (s *MyCustomSetup) SetUpRouter(config ServerConfig) *gin.Engine {
//	    router := gin.New()
//	    // Custom middleware
//	    router.Use(myCustomMiddleware)
//	    return router
//	}
type ServerSetup interface {
	SetUpRouter(config ServerConfig) *gin.Engine
	SetUpTLS(config ServerConfig) (*tls.Config, error)
	SetUpCORS(router *gin.Engine, config ServerConfig)
	CheckPortAvailability(config ServerConfig) error
}

// ServerSetupImpl provides the default implementation of ServerSetup.
//
// Features:
//   - Creates Gin router with default middleware
//   - Implements request timeouts
//   - Configures TLS with secure defaults
//   - Sets up CORS if enabled
//   - Checks port availability with retries
//
// Can be embedded in custom implementations to override specific methods.
type ServerSetupImpl struct{}

func (s *ServerSetupImpl) SetUpRouter(config ServerConfig) *gin.Engine {
	router := gin.Default()
	if config.RequestTimeout > 0 {
		router.Use(timeout.New(
			timeout.WithTimeout(config.RequestTimeout),
			timeout.WithHandler(func(c *gin.Context) { c.Next() }),
			timeout.WithResponse(func(c *gin.Context) {
				c.AbortWithStatusJSON(http.StatusGatewayTimeout, gin.H{
					"request_id": c.Writer.Header().Get("X-Request-ID"),
					"error":      "request timeout",
				})
			}),
		))
	}
	return router
}

func (s *ServerSetupImpl) SetUpTLS(config ServerConfig) (*tls.Config, error) {
	if !config.UseTLS {
		return nil, nil
	}

	if config.TLSCertFile == "" || config.TLSKeyFile == "" {
		return nil, fmt.Errorf("TLS certificate and key files must be provided when UseTLS is true")
	}

	cert, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		if config.Logger != nil {
			config.Logger.Errorf("Failed to load TLS certificate: %v", err)
		}
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}, nil
}

func (s *ServerSetupImpl) SetUpCORS(router *gin.Engine, config ServerConfig) {
	if config.UseCORS {
		router.Use(cors.New(config.CORSConfig))
		if config.Logger != nil {
			config.Logger.Infof("CORS configured with settings: %+v", config.CORSConfig)
		}
	}
}

func (s *ServerSetupImpl) CheckPortAvailability(config ServerConfig) error {
	address := fmt.Sprintf(":%d", config.Port)
	var listener net.Listener
	var err error

	for i := 0; i < 3; i++ {
		listener, err = net.Listen("tcp", address)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		if strings.Contains(err.Error(), "bind: address already in use") {
			return fmt.Errorf("port %d is already in use; please choose a different port or stop the process using this port", config.Port)
		}
		return fmt.Errorf("failed to check port availability: %w", err)
	}

	listener.Close()
	if config.Logger != nil {
		config.Logger.Infof("Port %d is available", config.Port)
	}
	return nil
}
