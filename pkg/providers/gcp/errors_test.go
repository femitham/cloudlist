package gcp

import (
	"errors"
	"testing"
)

func TestExtractGCPErrorReason(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "permission denied error",
			err:      errors.New(`{"error":{"code":403,"message":"Permission denied","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"PERMISSION_DENIED"}]}}`),
			expected: "PERMISSION_DENIED",
		},
		{
			name:     "API not enabled error",
			err:      errors.New("API compute.googleapis.com is not enabled for project"),
			expected: "api_not_enabled",
		},
		{
			name:     "404 error",
			err:      errors.New("Error 404: Resource not found"),
			expected: "not_found",
		},
		{
			name:     "unknown error",
			err:      errors.New("some other error"),
			expected: "unknown_error",
		},
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractGCPErrorReason(tt.err)
			if got != tt.expected {
				t.Errorf("ExtractGCPErrorReason() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFormatGCPError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "formats permission denied error",
			err:      errors.New(`{"error":{"code":403,"message":"Permission denied","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"PERMISSION_DENIED"}]}}`),
			contains: "PERMISSION_DENIED",
		},
		{
			name:     "nil error",
			err:      nil,
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatGCPError(tt.err)
			if tt.err == nil {
				if got != nil {
					t.Errorf("FormatGCPError() = %v, want nil", got)
				}
				return
			}
			if got == nil || tt.contains != "" && !errors.Is(got, tt.err) {
				t.Errorf("FormatGCPError() error = %v, want error containing %v", got, tt.contains)
			}
		})
	}
}
