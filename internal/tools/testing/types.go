package testing

// Test Types
const (
	TestTypeBOLA                TestType = "BOLA"
	TestTypeIDOR                TestType = "IDOR"
	TestTypeXSS                 TestType = "XSS"
	TestTypeSQLInjection        TestType = "SQLI"
	TestTypeXXE                 TestType = "XXE"
	TestTypeRCE                 TestType = "RCE"
	TestTypeSSRF                TestType = "SSRF"
	TestTypeFileUpload          TestType = "FILE_UPLOAD"
	TestTypeInsecureDeserialize TestType = "INSECURE_DESERIALIZE"
	TestTypeAPIVulnerability    TestType = "API_VULNERABILITY"
	TestTypeSecurityBypass      TestType = "SECURITY_BYPASS"
	TestTypeRaceCondition       TestType = "RACE_CONDITION"
	TestTypeRateLimits          TestType = "RATE_LIMITS"
	TestTypeJWT                 TestType = "JWT"
	TestTypeCrawl               TestType = "CRAWL"
)

// TestType represents the type of security test
type TestType string

// TestSeverity represents the severity level of a test finding
type TestSeverity string

// Severity levels
const (
	SeverityCritical TestSeverity = "CRITICAL"
	SeverityHigh     TestSeverity = "HIGH"
	SeverityMedium   TestSeverity = "MEDIUM"
	SeverityLow      TestSeverity = "LOW"
	SeverityInfo     TestSeverity = "INFO"
)

// Common helper functions
func flattenHeaders(headers map[string][]string) map[string]string {
	flat := make(map[string]string)
	for k, v := range headers {
		flat[k] = strings.Join(v, ", ")
	}
	return flat
}
