package testing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// BOLATestConfig specific configuration for BOLA tests
type BOLATestConfig struct {
	// Base configuration inherited from TestConfig
	TestConfig

	// BOLA specific fields
	IDParameters     []string          `json:"id_parameters"`      // Parameters that contain IDs to test
	AuthTokens       []string          `json:"auth_tokens"`        // Different user auth tokens to test with
	BaselineRequest  string            `json:"baseline_request"`   // Original request with valid auth
	BaselineResponse string            `json:"baseline_response"`  // Expected valid response
}

// executeBOLATest implements BOLA testing logic
func (wm *WorkflowManager) executeBOLATest(workflow *TestWorkflow) error {
	// Parse BOLA specific config
	var config BOLATestConfig
	configBytes, err := json.Marshal(workflow.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return fmt.Errorf("failed to unmarshal BOLA config: %v", err)
	}

	// Initialize results
	results := TestResults{
		TotalTests:  0,
		PassedTests: 0,
		FailedTests: 0,
	}
	startTime := time.Now()

	// For each auth token
	for _, token := range config.AuthTokens {
		// For each ID parameter
		for _, param := range config.IDParameters {
			// Generate test values for the parameter
			testValues := generateTestValues(param, config.BaselineRequest)

			// Test each value
			for _, value := range testValues {
				results.TotalTests++

				// Create test request
				req, err := createTestRequest(config.TargetEndpoint, token, param, value, config.Headers)
				if err != nil {
					results.FailedTests++
					continue
				}

				// Send request
				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					results.FailedTests++
					continue
				}
				defer resp.Body.Close()

				// Check if the request was successful (potential BOLA vulnerability)
				if isSuccessfulBOLATest(resp, config.SuccessCode) {
					// Create and save finding
					finding := &TestFinding{
						WorkflowID:  workflow.ID,
						Type:        TestTypeBOLA,
						Severity:    SeverityHigh,
						Title:       fmt.Sprintf("BOLA Vulnerability in %s", config.TargetEndpoint),
						Description: fmt.Sprintf("Successfully accessed resource with ID %s using unauthorized token", value),
						Evidence: Evidence{
							Request:    fmt.Sprintf("%s %s", req.Method, req.URL.String()),
							Response:   readResponse(resp),
							StatusCode: resp.StatusCode,
							Headers:    flattenHeaders(resp.Header),
							Payload:    value,
						},
						CreatedAt: time.Now(),
					}
					
					if err := wm.AddFinding(finding); err != nil {
						return fmt.Errorf("failed to save finding: %v", err)
					}

					results.FailedTests++
				} else {
					results.PassedTests++
				}

				// Respect rate limiting
				if config.DelayMS > 0 {
					time.Sleep(time.Duration(config.DelayMS) * time.Millisecond)
				}
			}
		}
	}

	// Update results
	results.ElapsedTime = time.Since(startTime).Seconds()
	workflow.Results = results

	return nil
}

// Helper functions

func generateTestValues(param, baselineRequest string) []string {
	// Extract current value
	current := extractParamValue(param, baselineRequest)
	if current == "" {
		return nil
	}

	// Generate test values based on the parameter type
	values := []string{}

	// If numeric
	if isNumeric(current) {
		num := parseInt(current)
		// Test adjacent values
		values = append(values,
			fmt.Sprintf("%d", num-1),
			fmt.Sprintf("%d", num+1),
			"0",
			"999999",
		)
	}

	// If UUID
	if isUUID(current) {
		values = append(values,
			"00000000-0000-0000-0000-000000000000",
			"11111111-1111-1111-1111-111111111111",
		)
	}

	// Add some common test values
	values = append(values,
		"null",
		"undefined",
		"'",
		"\"",
		"../",
		"./",
		"/",
	)

	return values
}

func createTestRequest(endpoint, token, param, value string, headers map[string]string) (*http.Request, error) {
	// Create request
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Add headers
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	// Add auth token
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	// Add parameter
	q := req.URL.Query()
	q.Add(param, value)
	req.URL.RawQuery = q.Encode()

	return req, nil
}

func isSuccessfulBOLATest(resp *http.Response, expectedCode int) bool {
	// Consider it successful (vulnerable) if:
	// 1. Status code matches expected success code
	// 2. Response contains sensitive data
	return resp.StatusCode == expectedCode
}

func readResponse(resp *http.Response) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	return buf.String()
}

func flattenHeaders(headers http.Header) map[string]string {
	flat := make(map[string]string)
	for k, v := range headers {
		flat[k] = strings.Join(v, ", ")
	}
	return flat
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func parseInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func isUUID(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}
