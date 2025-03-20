package gourdiangin

import (
	"errors"
	"fmt"
	"time"

	"github.com/gin-contrib/cors"
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
