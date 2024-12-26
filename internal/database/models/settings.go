package models

import (
	"time"

	"gorm.io/gorm"
)

// DB represents the database connection
type DB struct {
	*gorm.DB
}

// Settings represents global application settings
type Settings struct {
	ID                uint      `json:"id" gorm:"primaryKey"`
	HeadlessBrowser   bool      `json:"headless_browser" gorm:"default:false"`
	ProxyHost         string    `json:"proxy_host" gorm:"default:'127.0.0.1'"`
	ProxyPort         int       `json:"proxy_port" gorm:"default:8080"`
	MaxCrawlDepth     int       `json:"max_crawl_depth" gorm:"default:3"`
	CrawlDelayMS      int       `json:"crawl_delay_ms" gorm:"default:100"`
	ScreenshotEnabled bool      `json:"screenshot_enabled" gorm:"default:true"`
	ScreenshotPath    string    `json:"screenshot_path" gorm:"default:'screenshots'"`
	FormFillEnabled   bool      `json:"form_fill_enabled" gorm:"default:false"`
	JSInjectionEnabled bool     `json:"js_injection_enabled" gorm:"default:false"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// GetSettings retrieves the global settings
func (db *DB) GetSettings() (*Settings, error) {
	var settings Settings
	result := db.First(&settings)
	if result.Error != nil {
		// If no settings exist, create default settings
		if result.Error == gorm.ErrRecordNotFound {
			settings = Settings{
				HeadlessBrowser:   false,
				ProxyHost:         "127.0.0.1",
				ProxyPort:         8080,
				MaxCrawlDepth:     3,
				CrawlDelayMS:      100,
				ScreenshotEnabled: true,
				ScreenshotPath:    "screenshots",
				FormFillEnabled:   false,
				JSInjectionEnabled: false,
			}
			if err := db.Create(&settings).Error; err != nil {
				return nil, err
			}
		} else {
			return nil, result.Error
		}
	}
	return &settings, nil
}

// UpdateSettings updates the global settings
func (db *DB) UpdateSettings(settings *Settings) error {
	settings.UpdatedAt = time.Now()
	return db.Save(settings).Error
}
