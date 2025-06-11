package gcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// gcpRpcDetail is a minimal struct to map the objects inside the "Details" array.
// We only parse the fields we specifically need, such as "@type" and "reason."
type gcpRpcDetail struct {
	Type   string `json:"@type"`
	Reason string `json:"reason"`
}

// gcpErrorDetail is a minimal struct to parse Google Cloud API error responses.
// We only map the fields we need for error handling.
type gcpErrorDetail struct {
	Message string         `json:"message"`
	Details []gcpRpcDetail `json:"details"`
}

// ExtractGCPErrorReason attempts to extract a meaningful error reason from a Google Cloud API error.
// It parses the error message to find specific error reasons and returns a concise summary.
func ExtractGCPErrorReason(err error) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()
	var detail gcpErrorDetail

	// Try to parse the error as JSON
	if strings.Contains(errStr, "{") {
		jsonStr := errStr[strings.Index(errStr, "{"):]
		if err := json.Unmarshal([]byte(jsonStr), &detail); err == nil {
			// Check for specific error reasons in the details
			for _, d := range detail.Details {
				if d.Reason != "" {
					return d.Reason
				}
			}
		}
	}

	// If JSON parsing fails or no specific reason found, extract from error string
	switch {
	case strings.Contains(errStr, "403"):
		return "permission_denied"
	case strings.Contains(errStr, "404"):
		return "not_found"
	case strings.Contains(errStr, "API not enabled"):
		return "api_not_enabled"
	default:
		return "unknown_error"
	}
}

// FormatGCPError wraps the original error with a concise reason
func FormatGCPError(err error) error {
	if err == nil {
		return nil
	}
	reason := ExtractGCPErrorReason(err)
	return fmt.Errorf("%s: %w", reason, err)
}
