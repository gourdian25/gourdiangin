package gourdiangin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gourdian25/gourdianlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerConfig_Validate tests the ServerConfig validation
func TestServerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ServerConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: ServerConfig{
				Port:           8080,
				UseTLS:         false,
				RequestTimeout: 10 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "invalid port - too low",
			config: ServerConfig{
				Port:           0,
				RequestTimeout: 10 * time.Second,
			},
			wantErr: true,
			errMsg:  "invalid port number: 0",
		},
		{
			name: "invalid port - too high",
			config: ServerConfig{
				Port:           65536,
				RequestTimeout: 10 * time.Second,
			},
			wantErr: true,
			errMsg:  "invalid port number: 65536",
		},
		{
			name: "TLS enabled but missing cert files",
			config: ServerConfig{
				Port:           8080,
				UseTLS:         true,
				RequestTimeout: 10 * time.Second,
			},
			wantErr: true,
			errMsg:  "TLS certificate and key files must be provided when UseTLS is true",
		},
		{
			name: "invalid request timeout",
			config: ServerConfig{
				Port:           8080,
				RequestTimeout: 0,
			},
			wantErr: true,
			errMsg:  "request timeout must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestServerSetupImpl_SetUpRouter tests the router setup
func TestServerSetupImpl_SetUpRouter(t *testing.T) {
	setup := &ServerSetupImpl{}
	config := ServerConfig{
		Port:           8080,
		RequestTimeout: 10 * time.Second,
		Logger:         nil,
	}

	router := setup.SetUpRouter(config)
	assert.NotNil(t, router)

	// Test the timeout middleware by creating a test route that sleeps longer than the timeout
	router.GET("/timeout", func(c *gin.Context) {
		time.Sleep(config.RequestTimeout + 1*time.Second)
		c.String(http.StatusOK, "should timeout")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/timeout", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
}

// TestGourdianGinServer_StartShutdown tests server start and shutdown
func TestGourdianGinServer_StartShutdown(t *testing.T) {
	// Use a random available port
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	config := ServerConfig{
		Port:            port,
		RequestTimeout:  5 * time.Second,
		ShutdownTimeout: 5 * time.Second,
		Logger:          nil,
	}

	setup := &ServerSetupImpl{}
	server := NewGourdianGinServer(setup, config).(*GourdianGinServer)

	// Add a test endpoint
	server.router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Start server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Test server is running
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/test", port))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Test graceful shutdown
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.GracefulShutdown()
	}()

	// Wait for shutdown to complete
	wg.Wait()

	// Verify server is shut down
	_, err = http.Get(fmt.Sprintf("http://localhost:%d/test", port))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")

	// Check server error
	select {
	case err := <-serverErr:
		assert.NoError(t, err)
	default:
	}
}

func TestServerConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  ServerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: ServerConfig{
				Port:           8080,
				RequestTimeout: 10 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "invalid port",
			config: ServerConfig{
				Port:           0,
				RequestTimeout: 10 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "TLS missing files",
			config: ServerConfig{
				Port:           8080,
				UseTLS:         true,
				RequestTimeout: 10 * time.Second,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPIDFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "test.pid")

	logger, _ := gourdianlogger.NewGourdianLoggerWithDefault()
	defer logger.Close()

	server := &GourdianGinServer{
		config: ServerConfig{
			PIDFile: pidFile,
			Logger:  logger,
		},
	}

	// Test create
	if err := server.createPIDFile(); err != nil {
		t.Fatalf("createPIDFile() failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(pidFile); os.IsNotExist(err) {
		t.Fatal("PID file was not created")
	}

	// Test remove
	if err := server.removePIDFile(); err != nil {
		t.Fatalf("removePIDFile() failed: %v", err)
	}

	// Verify file removed
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Fatal("PID file was not removed")
	}
}

func TestRequestTimeoutMiddleware(t *testing.T) {
	config := ServerConfig{
		RequestTimeout: 100 * time.Millisecond,
	}

	setup := &ServerSetupImpl{}
	router := setup.SetUpRouter(config)

	// Add a slow route
	router.GET("/slow", func(c *gin.Context) {
		time.Sleep(200 * time.Millisecond)
		c.String(http.StatusOK, "too slow")
	})

	// Test the timeout
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/slow", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusGatewayTimeout {
		t.Errorf("Expected status %d, got %d", http.StatusGatewayTimeout, w.Code)
	}
}

func TestStopProcessFromPIDFile(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "test.pid")
	nonexistentPidFile := filepath.Join(tempDir, "nonexistent.pid")

	logger, _ := gourdianlogger.NewGourdianLoggerWithDefault()
	defer logger.Close()

	t.Run("Non-existent PID file", func(t *testing.T) {
		err := StopProcessFromPIDFile(nonexistentPidFile, logger)
		if err != nil {
			t.Errorf("Expected no error for non-existent PID file, got: %v", err)
		}
	})

	t.Run("Non-existent process", func(t *testing.T) {
		// Use a PID that we know doesn't exist (max PID + 1)
		maxPid := 1 << 22 // Common max PID on Linux systems
		nonExistentPid := maxPid + 1
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", nonExistentPid)), 0644); err != nil {
			t.Fatalf("Failed to create test PID file: %v", err)
		}

		err := StopProcessFromPIDFile(pidFile, logger)
		if err != nil {
			t.Errorf("Expected no error for non-existent process, got: %v", err)
		}

		// Verify PID file was removed
		if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
			t.Error("PID file should have been removed")
		}
	})

	t.Run("Invalid PID file content", func(t *testing.T) {
		if err := os.WriteFile(pidFile, []byte("not-a-number"), 0644); err != nil {
			t.Fatalf("Failed to create test PID file: %v", err)
		}

		err := StopProcessFromPIDFile(pidFile, logger)
		if err == nil {
			t.Error("Expected error for invalid PID content, got nil")
		}
	})
}

// TestServerSetupImpl_SetUpTLS tests the TLS setup
func TestServerSetupImpl_SetUpTLS(t *testing.T) {
	setup := &ServerSetupImpl{}

	// Create temporary self-signed cert and key for testing
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")

	// Generate a self-signed certificate for testing
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	// Write certificate
	certOut, err := os.Create(certFile)
	require.NoError(t, err)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	// Write key
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	require.NoError(t, err)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	tests := []struct {
		name      string
		config    ServerConfig
		wantTLS   bool
		wantError bool
	}{
		{
			name: "TLS disabled",
			config: ServerConfig{
				UseTLS: false,
			},
			wantTLS:   false,
			wantError: false,
		},
		{
			name: "TLS enabled with valid files",
			config: ServerConfig{
				UseTLS:      true,
				TLSCertFile: certFile,
				TLSKeyFile:  keyFile,
			},
			wantTLS:   true,
			wantError: false,
		},
		{
			name: "TLS enabled with missing cert file",
			config: ServerConfig{
				UseTLS:     true,
				TLSKeyFile: keyFile,
			},
			wantTLS:   false,
			wantError: true,
		},
		{
			name: "TLS enabled with invalid cert file",
			config: ServerConfig{
				UseTLS:      true,
				TLSCertFile: filepath.Join(tempDir, "invalid.pem"),
				TLSKeyFile:  keyFile,
			},
			wantTLS:   false,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig, err := setup.SetUpTLS(tt.config)

			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, tlsConfig)
			} else {
				assert.NoError(t, err)
				if tt.wantTLS {
					assert.NotNil(t, tlsConfig)
					assert.NotEmpty(t, tlsConfig.Certificates)
					assert.Equal(t, tls.VersionTLS12, tlsConfig.MinVersion)
					assert.Len(t, tlsConfig.CipherSuites, 2)
				} else {
					assert.Nil(t, tlsConfig)
				}
			}
		})
	}
}

// // TestServerSetupImpl_SetUpCORS tests the CORS setup
// func TestServerSetupImpl_SetUpCORS(t *testing.T) {
// 	setup := &ServerSetupImpl{}
// 	router := gin.New()

// 	config := ServerConfig{
// 		UseCORS: true,
// 		CORSConfig: cors.Config{
// 			AllowOrigins: []string{"https://example.com"},
// 		},
// 		Logger: nil,
// 	}

// 	setup.SetUpCORS(router, config)

// 	// Verify CORS middleware is added by checking the handlers count
// 	// Note: This is a bit implementation-dependent, but works for basic verification
// 	assert.Greater(t, len(router.Handlers), 1)
// }

// // TestServerSetupImpl_CheckPortAvailability tests port availability checking
// func TestServerSetupImpl_CheckPortAvailability(t *testing.T) {
// 	setup := &ServerSetupImpl{}

// 	// Find an available port for testing
// 	listener, err := net.Listen("tcp", ":0")
// 	require.NoError(t, err)
// 	usedPort := listener.Addr().(*net.TCPAddr).Port
// 	listener.Close()

// 	tests := []struct {
// 		name      string
// 		port      int
// 		wantError bool
// 	}{
// 		{
// 			name:      "available port",
// 			port:      0, // Let system choose an available port
// 			wantError: false,
// 		},
// 		{
// 			name:      "unavailable port",
// 			port:      usedPort,
// 			wantError: true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			config := ServerConfig{
// 				Port:   tt.port,
// 				Logger: nil,
// 			}

// 			err := setup.CheckPortAvailability(config)
// 			if tt.wantError {
// 				assert.Error(t, err)
// 				assert.Contains(t, err.Error(), "address already in use")
// 			} else {
// 				assert.NoError(t, err)
// 			}
// 		})
// 	}
// }

// // TestGourdianGinServer_PIDFile tests PID file creation and removal
// func TestGourdianGinServer_PIDFile(t *testing.T) {
// 	tempDir := t.TempDir()
// 	pidFile := filepath.Join(tempDir, "test.pid")

// 	config := ServerConfig{
// 		Port:    8080,
// 		PIDFile: pidFile,
// 		Logger:  nil,
// 	}

// 	setup := &ServerSetupImpl{}
// 	server := NewGourdianGinServer(setup, config).(*GourdianGinServer)

// 	// Test createPIDFile
// 	err := server.createPIDFile()
// 	assert.NoError(t, err)
// 	assert.FileExists(t, pidFile)

// 	// Verify PID file content
// 	pidData, err := os.ReadFile(pidFile)
// 	assert.NoError(t, err)
// 	pid, err := strconv.Atoi(string(pidData))
// 	assert.NoError(t, err)
// 	assert.Equal(t, os.Getpid(), pid)

// 	// Test removePIDFile
// 	err = server.removePIDFile()
// 	assert.NoError(t, err)
// 	assert.NoFileExists(t, pidFile)
// }

// // TestStopProcessFromPIDFile tests the process stopping functionality
// func TestStopProcessFromPIDFile(t *testing.T) {
// 	tempDir := t.TempDir()
// 	pidFile := filepath.Join(tempDir, "test.pid")

// 	// Test with non-existent PID file
// 	err := StopProcessFromPIDFile("nonexistent.pid", nil)
// 	assert.NoError(t, err)

// 	// Test with invalid PID file content
// 	err = os.WriteFile(pidFile, []byte("invalid"), 0644)
// 	assert.NoError(t, err)
// 	err = StopProcessFromPIDFile(pidFile, nil)
// 	assert.Error(t, err)
// 	assert.Contains(t, err.Error(), "failed to parse PID")

// 	// Test with PID of current process
// 	err = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
// 	assert.NoError(t, err)
// 	err = StopProcessFromPIDFile(pidFile, nil)
// 	assert.NoError(t, err)
// 	assert.NoFileExists(t, pidFile)
// }

// // TestGourdianGinServer_GetRouter tests GetRouter method
// func TestGourdianGinServer_GetRouter(t *testing.T) {
// 	config := ServerConfig{
// 		Port:   8080,
// 		Logger: nil,
// 	}

// 	setup := &ServerSetupImpl{}
// 	server := NewGourdianGinServer(setup, config)

// 	router := server.GetRouter()
// 	assert.NotNil(t, router)

// 	// Add a route and test it
// 	router.GET("/test", func(c *gin.Context) {
// 		c.String(http.StatusOK, "test")
// 	})

// 	w := httptest.NewRecorder()
// 	req, _ := http.NewRequest("GET", "/test", nil)
// 	router.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusOK, w.Code)
// 	assert.Equal(t, "test", w.Body.String())
// }

// // TestGourdianGinServer_GetServer tests GetServer method
// func TestGourdianGinServer_GetServer(t *testing.T) {
// 	config := ServerConfig{
// 		Port:   8080,
// 		Logger: nil,
// 	}

// 	setup := &ServerSetupImpl{}
// 	server := NewGourdianGinServer(setup, config)

// 	httpServer := server.GetServer()
// 	assert.NotNil(t, httpServer)
// 	assert.Equal(t, fmt.Sprintf(":%d", config.Port), httpServer.Addr)
// }
