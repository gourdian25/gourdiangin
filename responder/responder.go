// File: responder/responder.go

package responder

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gourdian25/gourdiangin/constants"
)

// getStatusByStatusCode maps HTTP status codes to standardized status strings
// This provides consistent status categorization across all API responses
//
// Parameters:
//   - statusCode: HTTP status code (e.g., 200, 404, 500)
//
// Returns:
//   - string: Standardized status string (e.g., "SUCCESS", "NOT_FOUND")
func getStatusByStatusCode(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "SUCCESS"
	case statusCode == 400:
		return "BAD_REQUEST"
	case statusCode == 401:
		return "UNAUTHORIZED"
	case statusCode == 403:
		return "FORBIDDEN"
	case statusCode == 404:
		return "NOT_FOUND"
	case statusCode == 422:
		return "VALIDATION_ERROR"
	case statusCode >= 400 && statusCode < 500:
		return "CLIENT_ERROR"
	case statusCode >= 500:
		return "SERVER_ERROR"
	default:
		return "UNKNOWN"
	}
}

// StandardResponses defines the core structure for all API responses
// This struct represents the minimal required fields for all responses
// while allowing optional data/error payloads
type StandardResponses struct {
	StatusCode int         `json:"status_code"`     // HTTP status code (e.g., 200, 400)
	Status     string      `json:"status"`          // Standardized status string from getStatusByStatusCode
	Message    string      `json:"message"`         // Human-readable response message
	MessageKey int         `json:"message_key"`     // Machine-readable code for i18n/l10n
	Data       interface{} `json:"data,omitempty"`  // Response payload (optional)
	Error      interface{} `json:"error,omitempty"` // Error details (optional)
}

// NewGinResponse creates a new standardized API response and sets standard headers
// This is the base function used by all other response constructors
//
// Parameters:
//   - c: Gin context for request-scoped operations
//   - statusCode: HTTP status code
//   - messageKey: Machine-readable message identifier
//   - message: Human-readable message
//   - data: Response payload (can be nil)
//   - err: Error details (can be nil)
//
// Returns:
//   - StandardResponses: Fully populated response structure
func NewGinResponse(c *gin.Context, statusCode, messageKey int, message string, data interface{}, err interface{}) StandardResponses {
	setStandardHeaders(c)
	return StandardResponses{
		Status:     getStatusByStatusCode(statusCode),
		StatusCode: statusCode,
		Message:    message,
		MessageKey: messageKey,
		Data:       data,
		Error:      formatError(err),
	}
}

// setStandardHeaders sets common HTTP headers for all responses
// These headers provide consistent metadata and improve API security
//
// Parameters:
//   - c: Gin context for header operations
func setStandardHeaders(c *gin.Context) {
	// ==========================================
	// 1. REQUEST IDENTIFICATION & TRACING
	// ==========================================
	c.Header(constants.RequestIDHeaderKey, getRequestID(c))
	c.Header(constants.UserAgentHeaderKey, getUserAgent(c))
	c.Header(constants.RealIPHeaderKey, getClientIP(c))

	// ==========================================
	// 2. SECURITY HEADERS
	// ==========================================
	c.Header(constants.ContentTypeHeaderKey, "application/json; charset=utf-8")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	c.Header("X-XSS-Protection", "1; mode=block")
	c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
	c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	c.Header("Cross-Origin-Opener-Policy", "same-origin")
	c.Header("Cross-Origin-Resource-Policy", "same-origin")
	c.Header("Cross-Origin-Embedder-Policy", "require-corp")

	// ==========================================
	// 3. DIAGNOSTIC & DEBUGGING HEADERS
	// ==========================================
	c.Header(constants.RequestMethodHeaderKey, c.Request.Method)
	c.Header(constants.RequestPathHeaderKey, c.Request.URL.Path)
	c.Header(constants.ResponseTimestampHeaderKey, fmt.Sprintf("%d", time.Now().UnixMilli()))
}

// NewSuccessResponse creates a standardized success response
// This should be used for all successful (2xx) API responses
//
// Parameters:
//   - c: Gin context
//   - status: HTTP success status code (2xx)
//   - messageKey: Machine-readable message identifier
//   - message: Human-readable success message
//   - data: Response payload
//
// Returns:
//   - StandardResponses: Success response structure
func NewSuccessResponse(c *gin.Context, status, messageKey int, message string, data interface{}) StandardResponses {
	return NewGinResponse(c, status, messageKey, message, data, nil)
}

// NewErrorResponse creates a standardized error response
// This should be used for all error (4xx/5xx) API responses
//
// Parameters:
//   - c: Gin context
//   - status: HTTP error status code (4xx or 5xx)
//   - messageKey: Machine-readable error identifier
//   - message: Human-readable error message
//   - err: Error details (can be error, string, or any type)
//
// Returns:
//   - StandardResponses: Error response structure
func NewErrorResponse(c *gin.Context, status, messageKey int, message string, err interface{}) StandardResponses {
	return NewGinResponse(c, status, messageKey, message, nil, err)
}

// getRequestID extracts the request ID from Gin context if available
// This ID is used for request tracing and correlation
//
// Parameters:
//   - c: Gin context containing request metadata
//
// Returns:
//   - string: Request ID if present, empty string otherwise
func getRequestID(c *gin.Context) string {
	if requestID, exists := c.Get(constants.RequestIDContextKey); exists {
		if idStr, ok := requestID.(string); ok {
			return idStr
		}
	}
	return ""
}

func getUserAgent(c *gin.Context) string {
	return c.GetHeader(constants.UserAgentHeaderKey)
}

func getClientIP(c *gin.Context) string {
	// Check common proxy headers
	headers := []string{
		constants.ForwardedForHeaderKey,
		constants.RealIPHeaderKey,
		"X-Client-IP",
		"X-Forwarded-For",
		"CF-Connecting-IP",
	}

	for _, header := range headers {
		if ip := strings.TrimSpace(c.GetHeader(header)); ip != "" {
			// Handle comma-separated lists (X-Forwarded-For)
			if strings.Contains(ip, ",") {
				ip = strings.Split(ip, ",")[0]
			}
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Fallback to remote address
	if ip, _, err := net.SplitHostPort(c.Request.RemoteAddr); err == nil {
		return ip
	}

	return c.Request.RemoteAddr
}

// formatError converts various error types to a consistent format
// Ensures all error responses have a predictable structure
//
// Parameters:
//   - err: Input error (can be error, string, or any type)
//
// Returns:
//   - interface{}: Formatted error (nil if input was nil)
func formatError(err interface{}) interface{} {
	if err == nil {
		return nil
	}
	switch e := err.(type) {
	case error:
		return e.Error()
	case string:
		return e
	default:
		return fmt.Sprintf("%v", e)
	}
}

// PaginationMeta contains metadata for paginated responses
// This structure provides clients with navigation information
type PaginationMeta struct {
	Page       int `json:"page"`       // Current page number (1-based)
	PageSize   int `json:"pageSize"`   // Number of items per page
	TotalItems int `json:"totalItems"` // Total items across all pages
	TotalPages int `json:"totalPages"` // Calculated total pages
}

// PaginatedResponse extends StandardResponses with pagination metadata
// Used for endpoints that return paginated data sets
type PaginatedResponse struct {
	StandardResponses
	Meta *PaginationMeta `json:"meta,omitempty"` // Pagination metadata
}

// NewPaginatedResponse creates a standardized paginated response
//
// Parameters:
//   - c: Gin context
//   - messageKey: Machine-readable message identifier
//   - message: Human-readable message
//   - data: Paginated data payload
//   - meta: Pagination metadata
//
// Returns:
//   - PaginatedResponse: Paginated response structure
func NewPaginatedResponse(c *gin.Context, messageKey int, message string, data interface{}, meta PaginationMeta) PaginatedResponse {
	base := NewSuccessResponse(c, 200, messageKey, message, data)
	return PaginatedResponse{
		StandardResponses: base,
		Meta:              &meta,
	}
}

// ValidationErrorResponse extends StandardResponses with validation errors
// Used specifically for 422 Unprocessable Entity responses
type ValidationErrorResponse struct {
	StandardResponses
	Errors map[string]interface{} `json:"errors"` // Field-specific validation errors
}

// NewValidationErrorResponse creates a validation error response
//
// Parameters:
//   - c: Gin context
//   - statusCode: HTTP status code (typically 422)
//   - messageKey: Machine-readable message identifier
//   - message: Human-readable message
//   - validationErrors: Map of field names to error messages
//
// Returns:
//   - *ValidationErrorResponse: Validation error response structure
func NewValidationErrorResponse(c *gin.Context, statusCode, messageKey int, message string, validationErrors map[string]interface{}) *ValidationErrorResponse {
	base := NewGinResponse(c, statusCode, messageKey, message, nil, nil)
	return &ValidationErrorResponse{
		StandardResponses: base,
		Errors:            validationErrors,
	}
}
