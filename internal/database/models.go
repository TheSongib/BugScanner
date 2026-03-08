package database

import (
	"encoding/json"
	"net"
	"time"
)

type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Scan struct {
	ID          string          `json:"id" db:"id"`
	Status      ScanStatus      `json:"status" db:"status"`
	Target      string          `json:"target" db:"target"`
	ScopeIn     []string        `json:"scope_in" db:"scope_in"`
	ScopeOut    []string        `json:"scope_out" db:"scope_out"`
	Config      json.RawMessage `json:"config" db:"config"`
	StartedAt   *time.Time      `json:"started_at,omitempty" db:"started_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at" db:"updated_at"`
}

type ScanJob struct {
	ID           string     `json:"id" db:"id"`
	ScanID       string     `json:"scan_id" db:"scan_id"`
	Stage        string     `json:"stage" db:"stage"`
	Status       ScanStatus `json:"status" db:"status"`
	WorkerID     string     `json:"worker_id,omitempty" db:"worker_id"`
	InputCount   int        `json:"input_count" db:"input_count"`
	OutputCount  int        `json:"output_count" db:"output_count"`
	ErrorMessage string     `json:"error_message,omitempty" db:"error_message"`
	StartedAt    *time.Time `json:"started_at,omitempty" db:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

type Domain struct {
	ID        string    `json:"id" db:"id"`
	ScanID    string    `json:"scan_id" db:"scan_id"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type Subdomain struct {
	ID        string    `json:"id" db:"id"`
	DomainID  string    `json:"domain_id" db:"domain_id"`
	Name      string    `json:"name" db:"name"`
	Source    string    `json:"source,omitempty" db:"source"`
	IsAlive   bool      `json:"is_alive" db:"is_alive"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type IP struct {
	ID        string    `json:"id" db:"id"`
	Address   net.IP    `json:"address" db:"address"`
	IsCDN     bool      `json:"is_cdn" db:"is_cdn"`
	CDNName   string    `json:"cdn_name,omitempty" db:"cdn_name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type Port struct {
	ID        string    `json:"id" db:"id"`
	IPID      string    `json:"ip_id" db:"ip_id"`
	Port      int       `json:"port" db:"port"`
	Protocol  string    `json:"protocol" db:"protocol"`
	Service   string    `json:"service,omitempty" db:"service"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type HTTPService struct {
	ID            string    `json:"id" db:"id"`
	SubdomainID   string    `json:"subdomain_id" db:"subdomain_id"`
	PortID        string    `json:"port_id,omitempty" db:"port_id"`
	URL           string    `json:"url" db:"url"`
	StatusCode    int       `json:"status_code" db:"status_code"`
	Title         string    `json:"title,omitempty" db:"title"`
	ContentLength int64     `json:"content_length" db:"content_length"`
	ContentType   string    `json:"content_type,omitempty" db:"content_type"`
	ResponseTime  int       `json:"response_time" db:"response_time"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type Technology struct {
	ID            string    `json:"id" db:"id"`
	HTTPServiceID string    `json:"http_service_id" db:"http_service_id"`
	Name          string    `json:"name" db:"name"`
	Version       string    `json:"version,omitempty" db:"version"`
	Category      string    `json:"category,omitempty" db:"category"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type CrawlResult struct {
	ID            string    `json:"id" db:"id"`
	HTTPServiceID string    `json:"http_service_id" db:"http_service_id"`
	URL           string    `json:"url" db:"url"`
	Method        string    `json:"method" db:"method"`
	SourceURL     string    `json:"source_url,omitempty" db:"source_url"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type Vulnerability struct {
	ID              string          `json:"id" db:"id"`
	ScanID          string          `json:"scan_id" db:"scan_id"`
	SubdomainID     string          `json:"subdomain_id,omitempty" db:"subdomain_id"`
	TemplateID      string          `json:"template_id" db:"template_id"`
	TemplateName    string          `json:"template_name,omitempty" db:"template_name"`
	Severity        Severity        `json:"severity" db:"severity"`
	MatchedURL      string          `json:"matched_url" db:"matched_url"`
	MatchedAt       string          `json:"matched_at,omitempty" db:"matched_at"`
	ExtractedData   json.RawMessage `json:"extracted_data,omitempty" db:"extracted_data"`
	CurlCommand     string          `json:"curl_command,omitempty" db:"curl_command"`
	Reference       []string        `json:"reference,omitempty" db:"reference"`
	IsFalsePositive bool            `json:"is_false_positive" db:"is_false_positive"`
	IsTriaged       bool            `json:"is_triaged" db:"is_triaged"`
	Notes           string          `json:"notes,omitempty" db:"notes"`
	CreatedAt       time.Time       `json:"created_at" db:"created_at"`
}
