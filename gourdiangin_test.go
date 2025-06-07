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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-contrib/cors"
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

	logger, _ := gourdianlogger.NewDefaultGourdianLogger()
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

	logger, _ := gourdianlogger.NewDefaultGourdianLogger()
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

func TestServerSetupImpl_SetUpCORS(t *testing.T) {
	setup := &ServerSetupImpl{}

	t.Run("CORS enabled", func(t *testing.T) {
		router := gin.New()
		initialHandlers := len(router.Handlers)

		config := ServerConfig{
			UseCORS: true,
			CORSConfig: cors.Config{
				AllowOrigins: []string{"https://example.com"},
			},
			Logger: nil,
		}

		setup.SetUpCORS(router, config)
		assert.Greater(t, len(router.Handlers), initialHandlers, "CORS middleware should be added")
	})

	t.Run("CORS disabled", func(t *testing.T) {
		router := gin.New()
		initialHandlers := len(router.Handlers)

		config := ServerConfig{
			UseCORS: false,
			CORSConfig: cors.Config{
				AllowOrigins: []string{"https://example.com"},
			},
			Logger: nil,
		}

		setup.SetUpCORS(router, config)
		assert.Equal(t, initialHandlers, len(router.Handlers), "No middleware should be added when CORS is disabled")
	})
}

func TestServerSetupImpl_SetUpCORS2(t *testing.T) {
	setup := &ServerSetupImpl{}

	t.Run("CORS headers present when enabled", func(t *testing.T) {
		router := gin.New()
		config := ServerConfig{
			UseCORS: true,
			CORSConfig: cors.Config{
				AllowOrigins: []string{"https://example.com"},
			},
		}
		setup.SetUpCORS(router, config)

		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		srv := httptest.NewServer(router)
		defer srv.Close()

		req, _ := http.NewRequest("OPTIONS", srv.URL+"/test", nil)
		req.Header.Set("Origin", "https://example.com")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, "https://example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	})
}

func TestGourdianGinServer_PIDFile(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "test.pid")

	// Create a logger that won't panic if used
	logger, err := gourdianlogger.NewDefaultGourdianLogger()
	require.NoError(t, err)
	defer logger.Close()

	config := ServerConfig{
		Port:            8080,
		PIDFile:         pidFile,
		Logger:          logger,
		RequestTimeout:  30 * time.Second, // Added required field
		ShutdownTimeout: 10 * time.Second, // Optional but good practice
	}

	setup := &ServerSetupImpl{}
	server := NewGourdianGinServer(setup, config).(*GourdianGinServer)

	t.Run("create PID file", func(t *testing.T) {
		err := server.createPIDFile()
		assert.NoError(t, err)
		assert.FileExists(t, pidFile)

		// Verify PID file content
		pidData, err := os.ReadFile(pidFile)
		assert.NoError(t, err)
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
		assert.NoError(t, err)
		assert.Equal(t, os.Getpid(), pid)
	})

	t.Run("remove PID file", func(t *testing.T) {
		// Ensure file exists first
		err := server.createPIDFile()
		require.NoError(t, err)
		require.FileExists(t, pidFile)

		err = server.removePIDFile()
		assert.NoError(t, err)
		assert.NoFileExists(t, pidFile)
	})

	t.Run("remove non-existent PID file", func(t *testing.T) {
		// Ensure file doesn't exist
		_ = os.Remove(pidFile)

		err := server.removePIDFile()
		assert.NoError(t, err)
	})
}

func TestGourdianGinServer_GetRouter(t *testing.T) {
	t.Run("router has timeout middleware", func(t *testing.T) {
		// Use a shorter timeout for testing (500ms)
		config := ServerConfig{
			Port:           8080,
			RequestTimeout: 500 * time.Millisecond, // Shorter timeout for tests
		}

		setup := &ServerSetupImpl{}
		server := NewGourdianGinServer(setup, config).(*GourdianGinServer)
		router := server.GetRouter()

		// Create a test request
		req, _ := http.NewRequest("GET", "/timeout-test", nil)
		w := httptest.NewRecorder()

		// Add a route that will sleep slightly longer than the timeout
		router.GET("/timeout-test", func(c *gin.Context) {
			time.Sleep(600 * time.Millisecond) // Just over the timeout
			c.String(200, "should not reach here")
		})

		// Serve the request
		router.ServeHTTP(w, req)

		// Verify we got a timeout response
		if w.Code != http.StatusGatewayTimeout {
			t.Errorf("Expected status code %d, got %d", http.StatusGatewayTimeout, w.Code)
		}
		if !strings.Contains(w.Body.String(), "request timeout") {
			t.Errorf("Expected timeout message, got: %s", w.Body.String())
		}
	})

	t.Run("router handles successful requests", func(t *testing.T) {
		config := ServerConfig{
			Port:           8080,
			RequestTimeout: 500 * time.Millisecond,
		}

		setup := &ServerSetupImpl{}
		server := NewGourdianGinServer(setup, config).(*GourdianGinServer)
		router := server.GetRouter()

		router.GET("/success-test", func(c *gin.Context) {
			time.Sleep(100 * time.Millisecond) // Well under timeout
			c.String(200, "success")
		})

		req, _ := http.NewRequest("GET", "/success-test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
		}
		if w.Body.String() != "success" {
			t.Errorf("Expected body 'success', got: %s", w.Body.String())
		}
	})
}

func TestTimeoutScenarios(t *testing.T) {
	tests := []struct {
		name           string
		timeout        time.Duration
		handlerSleep   time.Duration
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "within timeout",
			timeout:        500 * time.Millisecond,
			handlerSleep:   100 * time.Millisecond,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "exceeds timeout",
			timeout:        500 * time.Millisecond,
			handlerSleep:   600 * time.Millisecond,
			expectedStatus: http.StatusGatewayTimeout,
			expectedBody:   "request timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ServerConfig{
				Port:           8080,
				RequestTimeout: tt.timeout,
			}

			setup := &ServerSetupImpl{}
			server := NewGourdianGinServer(setup, config).(*GourdianGinServer)
			router := server.GetRouter()

			router.GET("/test", func(c *gin.Context) {
				time.Sleep(tt.handlerSleep)
				if tt.expectedStatus == http.StatusOK {
					c.String(200, tt.expectedBody)
				}
			})

			req, _ := http.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
			if !strings.Contains(w.Body.String(), tt.expectedBody) {
				t.Errorf("Expected body to contain %q, got %q", tt.expectedBody, w.Body.String())
			}
		})
	}
}

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
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	require.NoError(t, err, "failed to write certificate")
	certOut.Close()

	// Write key
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	require.NoError(t, err)
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	require.NoError(t, err, "failed to write private key")
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
				return
			}

			assert.NoError(t, err)

			if !tt.wantTLS {
				assert.Nil(t, tlsConfig)
				return
			}

			// Verify TLS configuration
			assert.NotNil(t, tlsConfig)
			assert.NotEmpty(t, tlsConfig.Certificates)
			assert.Equal(t, tls.VersionTLS12, tlsConfig.MinVersion)

			// Verify cipher suites
			expectedSuites := map[uint16]bool{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: true,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: true,
			}
			for _, suite := range tlsConfig.CipherSuites {
				if !expectedSuites[suite] {
					t.Errorf("Unexpected cipher suite: %x", suite)
				}
				delete(expectedSuites, suite)
			}
			for suite := range expectedSuites {
				t.Errorf("Missing expected cipher suite: %x", suite)
			}
		})
	}
}

// TestTLSStartup tests server startup with TLS
func TestTLSStartup(t *testing.T) {
	// Create temporary self-signed cert and key
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")

	// Generate test certs
	generateTestCert(t, certFile, keyFile)

	// Use a random available port
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	config := ServerConfig{
		Port:           port, // Use the random port we just found
		UseTLS:         true,
		TLSCertFile:    certFile,
		TLSKeyFile:     keyFile,
		RequestTimeout: 5 * time.Second,
		Logger:         nil,
	}

	setup := &ServerSetupImpl{}
	server := NewGourdianGinServer(setup, config).(*GourdianGinServer)

	// Add test endpoint
	server.router.GET("/tls-test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Test TLS connection
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://localhost:%d/tls-test", config.Port))
	require.NoError(t, err, "Failed to make TLS request")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Shutdown server
	server.GracefulShutdown()
}

func generateTestCert(t *testing.T, certFile, keyFile string) {
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

	certOut, err := os.Create(certFile)
	require.NoError(t, err)
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	require.NoError(t, err, "failed to write certificate")
	certOut.Close()

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	require.NoError(t, err)
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	require.NoError(t, err, "failed to write private key")
	keyOut.Close()
}
