package testing

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ghostsecurity/reaper/internal/database/models"
)

// InjectionTestTypes represents different types of injection tests
const (
	TestTypeSQLInjection TestType = "SQLI"
	TestTypeXXE          TestType = "XXE"
	TestTypeXSS          TestType = "XSS"
	TestTypeRCE          TestType = "RCE"
	TestTypeSSRF         TestType = "SSRF"
	TestTypeFileUpload   TestType = "FILE_UPLOAD"
	TestTypeInsecureDeserialize TestType = "INSECURE_DESERIALIZE"
	TestTypeAPIVulnerability TestType = "API_VULNERABILITY"
	TestTypeSecurityBypass TestType = "SECURITY_BYPASS"
	TestTypeRaceCondition TestType = "RACE_CONDITION"
)

// InjectionPayload represents a test payload for injection testing
type InjectionPayload struct {
	Type        TestType     `json:"type"`
	Value       string       `json:"value"`
	Description string       `json:"description"`
	Severity    TestSeverity `json:"severity"`
}

// InjectionTestConfig holds configuration for injection testing
type InjectionTestConfig struct {
	Target      string            `json:"target"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Parameters  map[string]string `json:"parameters"`
	Cookies     map[string]string `json:"cookies"`
	Auth        *AuthConfig       `json:"auth,omitempty"`
	TestTypes   []TestType        `json:"test_types"`
	Concurrency int               `json:"concurrency"`
	Delay       time.Duration     `json:"delay"`
}

// executeInjectionTest performs various injection tests based on configuration
func (wm *WorkflowManager) executeInjectionTest(workflow *TestWorkflow, settings *models.Settings) error {
	config, ok := workflow.Config.(InjectionTestConfig)
	if !ok {
		return fmt.Errorf("invalid config type for injection test")
	}

	payloads := generatePayloads(config.TestTypes)
	results := make(chan TestFinding)
	var wg sync.WaitGroup

	// Create worker pool for concurrent testing
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range payloads {
				if err := wm.testPayload(config, payload, results); err != nil {
					// Log error but continue testing
					fmt.Printf("Error testing payload: %v\n", err)
				}
				time.Sleep(config.Delay)
			}
		}()
	}

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process findings
	for finding := range results {
		if err := wm.AddFinding(&finding); err != nil {
			return fmt.Errorf("failed to add finding: %v", err)
		}
	}

	return nil
}

// testPayload tests a single injection payload against the target
func (wm *WorkflowManager) testPayload(config InjectionTestConfig, payload InjectionPayload, results chan<- TestFinding) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create request with payload
	req, err := http.NewRequestWithContext(wm.ctx, config.Method, config.Target, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Add headers
	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	// Add cookies
	for k, v := range config.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	// Send request and analyze response
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Analyze response for vulnerabilities
	if finding := analyzeResponse(payload, resp); finding != nil {
		results <- *finding
	}

	return nil
}

// analyzeResponse analyzes the response for potential vulnerabilities
func analyzeResponse(payload InjectionPayload, resp *http.Response) *TestFinding {
	// Common error patterns that might indicate vulnerabilities
	errorPatterns := map[TestType][]string{
		TestTypeSQLInjection: {
			"SQL syntax",
			"mysql_fetch_array",
			"ORA-",
			"PostgreSQL",
		},
		TestTypeXSS: {
			"<script>alert(1)</script>",
			"javascript:alert",
		},
		TestTypeRCE: {
			"root:",
			"bin/bash",
		},
		// Add more patterns for other vulnerability types
	}

	// Read response body
	body := make([]byte, 1024*10) // Read first 10KB
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	// Check for patterns
	patterns, exists := errorPatterns[payload.Type]
	if exists {
		for _, pattern := range patterns {
			if strings.Contains(bodyStr, pattern) {
				return &TestFinding{
					Type:        payload.Type,
					Severity:    payload.Severity,
					Title:       fmt.Sprintf("Potential %s vulnerability detected", payload.Type),
					Description: fmt.Sprintf("Found indication of %s vulnerability using payload: %s", payload.Type, payload.Value),
					Evidence: Evidence{
						Request:    payload.Value,
						Response:   bodyStr,
						StatusCode: resp.StatusCode,
						Headers:    flattenHeaders(resp.Header),
						Payload:    payload.Value,
					},
					CreatedAt: time.Now(),
				}
			}
		}
	}

	return nil
}

// flattenHeaders converts http.Header to map[string]string
func flattenHeaders(headers http.Header) map[string]string {
	flat := make(map[string]string)
	for k, v := range headers {
		flat[k] = strings.Join(v, ", ")
	}
	return flat
}
