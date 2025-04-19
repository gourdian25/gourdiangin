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
	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
	"github.com/gourdian25/gourdianlogger"
)

type ServerConfig struct {
	Port            int
	UseTLS          bool
	UseCORS         bool
	TLSKeyFile      string
	TLSCertFile     string
	CORSConfig      cors.Config
	Logger          *gourdianlogger.Logger
	ShutdownTimeout time.Duration
	RequestTimeout  time.Duration // New field for per-request timeout
}

// Validate checks if the ServerConfig fields are valid.
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

// Server defines the interface for the HTTP server
type Server interface {
	Start() error
	GracefulShutdown()
	GetRouter() *gin.Engine
	GetServer() *http.Server
}

type GourdianGinServer struct {
	router      *gin.Engine
	server      *http.Server
	serverSetup ServerSetup
	config      ServerConfig
	shutdownWg  sync.WaitGroup
	stopChan    chan os.Signal
}

func NewGourdianGinServer(setup ServerSetup, config ServerConfig) Server {
	// Initialize a default logger if none provided
	if config.Logger == nil {
		Logger, err := gourdianlogger.NewGourdianLoggerWithDefault()
		if err != nil {
			panic(fmt.Sprintf("Failed to create default logger: %v", err))
		}
		defer Logger.Close()
		config.Logger = Logger
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		config.Logger.Fatalf("Invalid server configuration: %v", err)
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

func (gs *GourdianGinServer) GetServer() *http.Server {
	return gs.server
}

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

	// Wait for shutdown to complete
	done := make(chan struct{})
	go func() {
		gs.shutdownWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		gs.config.Logger.Info("Server shutdown completed")
	case <-time.After(gs.config.ShutdownTimeout + 5*time.Second): // Add buffer for safety
		gs.config.Logger.Error("Server shutdown timed out")
	}
}

type ServerSetup interface {
	SetUpRouter(config ServerConfig) *gin.Engine
	SetUpTLS(config ServerConfig) (*tls.Config, error)
	SetUpCORS(router *gin.Engine, config ServerConfig)
	CheckPortAvailability(config ServerConfig) error
}

// ServerSetupImpl provides the standard implementation of the ServerSetup interface.
type ServerSetupImpl struct{}

func (s *ServerSetupImpl) SetUpRouter(config ServerConfig) *gin.Engine {
	router := gin.Default()

	// Add timeout middleware if RequestTimeout is set
	if config.RequestTimeout > 0 {
		router.Use(timeoutMiddleware(config))
	}

	return router
}

// timeoutMiddleware adds per-request timeout
func timeoutMiddleware(config ServerConfig) gin.HandlerFunc {
	return timeout.New(
		timeout.WithTimeout(config.RequestTimeout),
		timeout.WithHandler(func(c *gin.Context) {
			c.Next()
		}),
		timeout.WithResponse(func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusGatewayTimeout, gin.H{
				"request_id": c.Writer.Header().Get("X-Request-ID"),
				"error":      "request timeout",
			})
		}),
	)
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

	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12, // Enforce minimum TLS version
		PreferServerCipherSuites: true,             // Prefer server cipher suites for better security
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	return tlsConfig, nil
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

	// Retry binding up to 3 times
	for i := 0; i < 3; i++ {
		listener, err = net.Listen("tcp", address)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second) // Wait before retrying
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
func (s *ServerSetupImpl) SetUpHealthCheck(router *gin.Engine, config ServerConfig) {
	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	if config.Logger != nil {
		config.Logger.Info("Health check endpoint /health is set up")
	}
}
