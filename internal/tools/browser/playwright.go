package browser

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"
)

// PlaywrightManager manages browser automation
type PlaywrightManager struct {
	pw          *playwright.Playwright
	browser     playwright.Browser
	proxyURL    string
	isInitialized bool
	mu           sync.Mutex
}

var (
	instance *PlaywrightManager
	once     sync.Once
)

// GetPlaywrightManager returns a singleton instance of PlaywrightManager
func GetPlaywrightManager(proxyURL string) (*PlaywrightManager, error) {
	once.Do(func() {
		instance = &PlaywrightManager{
			proxyURL: proxyURL,
		}
	})
	return instance, nil
}

// Initialize sets up the Playwright environment
func (pm *PlaywrightManager) Initialize() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.isInitialized {
		return nil
	}

	pw, err := playwright.Run()
	if err != nil {
		return fmt.Errorf("could not start playwright: %v", err)
	}

	browserOptions := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Proxy: &playwright.Proxy{
			Server: pm.proxyURL,
		},
	}

	browser, err := pw.Chromium.Launch(browserOptions)
	if err != nil {
		return fmt.Errorf("could not launch browser: %v", err)
	}

	pm.pw = pw
	pm.browser = browser
	pm.isInitialized = true

	return nil
}

// CrawlConfig holds configuration for crawling
type CrawlConfig struct {
	Domain            string
	MaxDepth          int
	ScreenshotEnabled bool
	ScreenshotPath    string
	FormFillEnabled   bool
	JSInjectionEnabled bool
	ExcludePatterns   []string
	CustomJS          string
	AuthConfig        *AuthConfig
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	LoginURL    string
	Credentials map[string]string
	Selectors   map[string]string
}

// CrawlDomain performs an automated crawl of a domain
func (pm *PlaywrightManager) CrawlDomain(ctx context.Context, config CrawlConfig) error {
	if !pm.isInitialized {
		if err := pm.Initialize(); err != nil {
			return err
		}
	}

	// Create a new browser context for isolation
	context, err := pm.browser.NewContext()
	if err != nil {
		return fmt.Errorf("could not create browser context: %v", err)
	}
	defer context.Close()

	// Create a new page
	page, err := context.NewPage()
	if err != nil {
		return fmt.Errorf("could not create page: %v", err)
	}

	// Set up event handlers
	page.On("request", func(req playwright.Request) {
		slog.Info("browser request",
			"url", req.URL(),
			"method", req.Method(),
			"headers", req.Headers(),
		)
	})

	page.On("response", func(res playwright.Response) {
		slog.Info("browser response",
			"url", res.URL(),
			"status", res.Status(),
		)
	})

	// Handle authentication if configured
	if config.AuthConfig != nil {
		if err := pm.handleAuthentication(page, config.AuthConfig); err != nil {
			return fmt.Errorf("authentication failed: %v", err)
		}
	}

	// Navigate to the domain
	if _, err = page.Goto("https://" + config.Domain, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(30000),
	}); err != nil {
		return fmt.Errorf("could not navigate to domain: %v", err)
	}

	// Start crawling
	visitedURLs := make(map[string]bool)
	return pm.crawl(ctx, page, config, 0, visitedURLs)
}

// crawl recursively crawls links on the page
func (pm *PlaywrightManager) crawl(ctx context.Context, page playwright.Page, config CrawlConfig, currentDepth int, visitedURLs map[string]bool) error {
	if currentDepth >= config.MaxDepth {
		return nil
	}

	currentURL := page.URL()

	// Take screenshot if enabled
	if config.ScreenshotEnabled {
		screenshotPath := filepath.Join(config.ScreenshotPath, fmt.Sprintf("%d_%s.png", time.Now().Unix(), sanitizeFilename(currentURL)))
		screenshot, err := page.Screenshot(playwright.PageScreenshotOptions{
			Path: playwright.String(screenshotPath),
			FullPage: playwright.Bool(true),
		})
		if err != nil {
			slog.Error("screenshot failed", "error", err)
		}
		_ = screenshot // Ignore the returned bytes since we're saving to file
	}

	// Inject custom JavaScript if enabled
	if config.JSInjectionEnabled && config.CustomJS != "" {
		if _, err := page.Evaluate(config.CustomJS); err != nil {
			slog.Error("JS injection failed", "error", err)
		}
	}

	// Handle forms if enabled
	if config.FormFillEnabled {
		if err := pm.handleForms(page); err != nil {
			slog.Error("form filling failed", "error", err)
		}
	}

	// Get all links on the page
	links, err := page.Locator("a[href]").All()
	if err != nil {
		return fmt.Errorf("could not get links: %v", err)
	}

	for _, link := range links {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			href, err := link.GetAttribute("href")
			if err != nil {
				continue
			}

			// Skip if already visited, external link, or matches exclude patterns
			if visitedURLs[href] || !isInternalLink(href, config.Domain) || matchesExcludePatterns(href, config.ExcludePatterns) {
				continue
			}

			visitedURLs[href] = true

			// Create a new page for each link
			newPage, err := page.Context().NewPage()
			if err != nil {
				continue
			}

			if _, err = newPage.Goto(href, playwright.PageGotoOptions{
				WaitUntil: playwright.WaitUntilStateNetworkidle,
				Timeout:   playwright.Float(30000),
			}); err != nil {
				newPage.Close()
				continue
			}

			if err := pm.crawl(ctx, newPage, config, currentDepth+1, visitedURLs); err != nil {
				newPage.Close()
				continue
			}

			newPage.Close()
		}

		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

// handleAuthentication performs login if configured
func (pm *PlaywrightManager) handleAuthentication(page playwright.Page, config *AuthConfig) error {
	// Navigate to login page
	if _, err := page.Goto(config.LoginURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	}); err != nil {
		return err
	}

	// Fill in credentials
	for field, selector := range config.Selectors {
		if value, ok := config.Credentials[field]; ok {
			if err := page.Fill(selector, value); err != nil {
				return fmt.Errorf("failed to fill %s: %v", field, err)
			}
		}
	}

	// Submit form
	if submitSelector, ok := config.Selectors["submit"]; ok {
		if err := page.Click(submitSelector); err != nil {
			return fmt.Errorf("failed to click submit: %v", err)
		}
	}

	// Wait for navigation
	opts := playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	}
	if err := page.WaitForLoadState(opts); err != nil {
		return fmt.Errorf("failed to wait for navigation: %v", err)
	}

	return nil
}

// handleForms attempts to fill and submit forms on the page
func (pm *PlaywrightManager) handleForms(page playwright.Page) error {
	forms, err := page.Locator("form").All()
	if err != nil {
		return err
	}

	for _, form := range forms {
		// Find input fields
		inputs, err := form.Locator("input").All()
		if err != nil {
			continue
		}

		// Fill inputs with test data
		for _, input := range inputs {
			inputType, err := input.GetAttribute("type")
			if err != nil {
				continue
			}

			// Fill based on input type
			switch inputType {
			case "text":
				input.Fill("test")
			case "email":
				input.Fill("test@example.com")
			case "password":
				input.Fill("password123")
			case "number":
				input.Fill("123")
			}
		}

		// Submit form
		submitLocator := form.Locator("button[type=submit]")
		submitButton, err := submitLocator.First()
		if err != nil {
			continue
		}

		if err := submitButton.Click(); err != nil {
			continue
		}
		opts := playwright.PageWaitForLoadStateOptions{
			State: playwright.LoadStateNetworkidle,
		}
		if err := page.WaitForLoadState(opts); err != nil {
			continue
		}
	}

	return nil
}

// Helper functions

func sanitizeFilename(url string) string {
	// Implement URL sanitization for filenames
	return url // Simplified for example
}

func matchesExcludePatterns(url string, patterns []string) bool {
	for _, pattern := range patterns {
		// Implement pattern matching
		if strings.Contains(url, pattern) {
			return true
		}
	}
	return false
}

// isInternalLink checks if a URL belongs to the same domain
func isInternalLink(url, domain string) bool {
	// Add proper URL validation logic
	return strings.Contains(url, domain)
}

// Close cleans up Playwright resources
func (pm *PlaywrightManager) Close() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.isInitialized {
		return nil
	}

	if err := pm.browser.Close(); err != nil {
		return fmt.Errorf("could not close browser: %v", err)
	}

	if err := pm.pw.Stop(); err != nil {
		return fmt.Errorf("could not stop playwright: %v", err)
	}

	pm.isInitialized = false
	return nil
}
