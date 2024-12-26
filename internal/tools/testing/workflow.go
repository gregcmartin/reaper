package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ghostsecurity/reaper/internal/database/models"
	"github.com/ghostsecurity/reaper/internal/tools/browser"
)

// TestType represents different types of security tests
type TestType string

const (
	TestTypeBOLA       TestType = "BOLA"
	TestTypeIDOR       TestType = "IDOR"
	TestTypeXSS        TestType = "XSS"
	TestTypeSQLI       TestType = "SQLI"
	TestTypeRateLimits TestType = "RATE_LIMITS"
	TestTypeJWT        TestType = "JWT"
	TestTypeCrawl      TestType = "CRAWL"
)

// TestSeverity represents the severity level of a test finding
type TestSeverity string

const (
	SeverityCritical TestSeverity = "CRITICAL"
	SeverityHigh     TestSeverity = "HIGH"
	SeverityMedium   TestSeverity = "MEDIUM"
	SeverityLow      TestSeverity = "LOW"
	SeverityInfo     TestSeverity = "INFO"
)

// TestWorkflow defines a security test workflow
type TestWorkflow struct {
	ID          uint        `json:"id" gorm:"primaryKey"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Type        TestType    `json:"type"`
	Config      TestConfig  `json:"config"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Status      TestStatus  `json:"status"`
	Results     TestResults `json:"results,omitempty"`
}

// TestConfig holds configuration for a test workflow
type TestConfig struct {
	// Common configuration
	TargetEndpoint string            `json:"target_endpoint"`
	Headers        map[string]string `json:"headers"`
	Parameters     []string          `json:"parameters"`
	Payloads       []string          `json:"payloads"`
	
	// Test-specific configuration
	MaxRequests    int               `json:"max_requests"`
	DelayMS        int               `json:"delay_ms"`
	SuccessCode    int               `json:"success_code"`
	FailureCodes   []int             `json:"failure_codes"`
	ValidateFunc   string            `json:"validate_func"`
	
	// Crawl configuration
	MaxCrawlDepth   int               `json:"max_crawl_depth"`
	Domain          string            `json:"domain"`
	ExcludePatterns []string          `json:"exclude_patterns"`
	CustomJS        string            `json:"custom_js"`
	
	// Authentication configuration
	AuthConfig     *AuthConfig        `json:"auth_config"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	LoginURL    string            `json:"login_url"`
	Credentials map[string]string `json:"credentials"`
	Selectors   map[string]string `json:"selectors"`
}

// TestStatus represents the current state of a test
type TestStatus struct {
	State     string    `json:"state"` // PENDING, RUNNING, COMPLETED, FAILED
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// TestResults holds the results of a test workflow
type TestResults struct {
	Findings     []TestFinding `json:"findings"`
	TotalTests   int          `json:"total_tests"`
	PassedTests  int          `json:"passed_tests"`
	FailedTests  int          `json:"failed_tests"`
	ElapsedTime  float64      `json:"elapsed_time"`
}

// TestFinding represents a single security finding
type TestFinding struct {
	ID          uint         `json:"id" gorm:"primaryKey"`
	WorkflowID  uint         `json:"workflow_id"`
	Type        TestType     `json:"type"`
	Severity    TestSeverity `json:"severity"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Evidence    Evidence     `json:"evidence"`
	CreatedAt   time.Time    `json:"created_at"`
}

// Evidence holds proof of a security finding
type Evidence struct {
	Request     string            `json:"request"`
	Response    string            `json:"response"`
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	Payload     string           `json:"payload"`
	Screenshot  string           `json:"screenshot,omitempty"`
}

// WorkflowManager handles test workflow execution
type WorkflowManager struct {
	db     *models.DB
	ctx    context.Context
	cancel context.CancelFunc
}

// NewWorkflowManager creates a new workflow manager
func NewWorkflowManager(db *models.DB) *WorkflowManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkflowManager{
		db:     db,
		ctx:    ctx,
		cancel: cancel,
	}
}

// CreateWorkflow creates a new test workflow
func (wm *WorkflowManager) CreateWorkflow(workflow *TestWorkflow) error {
	workflow.CreatedAt = time.Now()
	workflow.Status = TestStatus{
		State: "PENDING",
	}
	return wm.db.Create(workflow).Error
}

// ExecuteWorkflow runs a test workflow
func (wm *WorkflowManager) ExecuteWorkflow(workflowID uint) error {
	workflow := &TestWorkflow{}
	if err := wm.db.First(workflow, workflowID).Error; err != nil {
		return err
	}

	// Get global settings
	settings, err := wm.db.GetSettings()
	if err != nil {
		return err
	}

	// Update status to running
	workflow.Status.State = "RUNNING"
	workflow.Status.StartTime = time.Now()
	if err := wm.db.Save(workflow).Error; err != nil {
		return err
	}

	// Execute test based on type
	var execErr error
	switch workflow.Type {
	case TestTypeBOLA:
		execErr = wm.executeBOLATest(workflow)
	case TestTypeIDOR:
		execErr = wm.executeIDORTest(workflow)
	case TestTypeXSS:
		execErr = wm.executeXSSTest(workflow)
	case TestTypeSQLI:
		execErr = wm.executeSQLITest(workflow)
	case TestTypeRateLimits:
		execErr = wm.executeRateLimitTest(workflow)
	case TestTypeJWT:
		execErr = wm.executeJWTTest(workflow)
	case TestTypeCrawl:
		if settings.HeadlessBrowser {
			execErr = wm.executeCrawlTest(workflow, settings)
		} else {
			execErr = fmt.Errorf("headless browser mode is disabled in settings")
		}
	default:
		execErr = fmt.Errorf("unsupported test type: %s", workflow.Type)
	}

	// Update workflow status
	workflow.Status.EndTime = time.Now()
	if execErr != nil {
		workflow.Status.State = "FAILED"
		workflow.Status.Error = execErr.Error()
	} else {
		workflow.Status.State = "COMPLETED"
	}

	return wm.db.Save(workflow).Error
}

// executeCrawlTest performs automated crawling using Playwright
func (wm *WorkflowManager) executeCrawlTest(workflow *TestWorkflow, settings *models.Settings) error {
	proxyURL := fmt.Sprintf("http://%s:%d", settings.ProxyHost, settings.ProxyPort)
	
	// Initialize Playwright
	pw, err := browser.GetPlaywrightManager(proxyURL)
	if err != nil {
		return fmt.Errorf("failed to initialize playwright: %v", err)
	}

	// Create crawl config
	config := browser.CrawlConfig{
		Domain:            workflow.Config.Domain,
		MaxDepth:          workflow.Config.MaxCrawlDepth,
		ScreenshotEnabled: settings.ScreenshotEnabled,
		ScreenshotPath:    settings.ScreenshotPath,
		FormFillEnabled:   settings.FormFillEnabled,
		JSInjectionEnabled: settings.JSInjectionEnabled,
		ExcludePatterns:   workflow.Config.ExcludePatterns,
		CustomJS:          workflow.Config.CustomJS,
	}

	// Add authentication config if present
	if workflow.Config.AuthConfig != nil {
		config.AuthConfig = &browser.AuthConfig{
			LoginURL:    workflow.Config.AuthConfig.LoginURL,
			Credentials: workflow.Config.AuthConfig.Credentials,
			Selectors:  workflow.Config.AuthConfig.Selectors,
		}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Start crawling
	if err := pw.CrawlDomain(ctx, config); err != nil {
		return fmt.Errorf("crawl failed: %v", err)
	}

	return nil
}

// AddFinding adds a new security finding to a workflow
func (wm *WorkflowManager) AddFinding(finding *TestFinding) error {
	finding.CreatedAt = time.Now()
	return wm.db.Create(finding).Error
}

// GetWorkflow retrieves a workflow by ID
func (wm *WorkflowManager) GetWorkflow(id uint) (*TestWorkflow, error) {
	workflow := &TestWorkflow{}
	err := wm.db.First(workflow, id).Error
	return workflow, err
}

// GetFindings retrieves all findings for a workflow
func (wm *WorkflowManager) GetFindings(workflowID uint) ([]TestFinding, error) {
	var findings []TestFinding
	err := wm.db.Where("workflow_id = ?", workflowID).Find(&findings).Error
	return findings, err
}

// Stop stops all running workflows
func (wm *WorkflowManager) Stop() {
	wm.cancel()
}
