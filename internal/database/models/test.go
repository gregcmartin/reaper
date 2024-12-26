package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

// TestWorkflow represents a security test workflow in the database
type TestWorkflow struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        string    `json:"type"`
	Config      JSON      `json:"config" gorm:"type:jsonb"`
	Status      JSON      `json:"status" gorm:"type:jsonb"`
	Results     JSON      `json:"results" gorm:"type:jsonb"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TestFinding represents a security finding in the database
type TestFinding struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	WorkflowID  uint      `json:"workflow_id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Evidence    JSON      `json:"evidence" gorm:"type:jsonb"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// JSON is a wrapper for handling JSON data in GORM
type JSON []byte

// Scan implements the sql.Scanner interface
func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	s, ok := value.([]byte)
	if !ok {
		return errors.New("Invalid scan source")
	}
	*j = append((*j)[0:0], s...)
	return nil
}

// Value implements the driver.Valuer interface
func (j JSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return string(j), nil
}
