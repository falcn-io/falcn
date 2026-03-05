package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/falcn-io/falcn/pkg/events"
	"github.com/falcn-io/falcn/pkg/integrations"
	"github.com/falcn-io/falcn/pkg/logger"
)

// JiraConnector creates Jira issues for critical security findings.
type JiraConnector struct {
	name   string
	config JiraConfig
	client *http.Client
	logger logger.Logger
	health integrations.HealthStatus
}

// JiraConfig holds Atlassian Jira configuration.
type JiraConfig struct {
	// BaseURL is the root of the Jira instance, e.g. https://acme.atlassian.net
	BaseURL     string `json:"base_url"`
	Email       string `json:"email"`       // account email for Basic Auth
	APIToken    string `json:"api_token"`   // API token (not password)
	Project     string `json:"project"`     // project key, e.g. "SEC"
	IssueType   string `json:"issue_type"`  // default "Bug"
	MinSeverity string `json:"min_severity"` // low|medium|high|critical (default: high)
	// Labels added to every created issue.
	Labels []string `json:"labels"`
	// PriorityMap maps Falcn severity to Jira priority name.
	// Defaults: critical→Critical, high→High, medium→Medium, low→Low.
	PriorityMap map[string]string `json:"priority_map"`
}

// jiraIssueRequest is the payload for POST /rest/api/3/issue.
type jiraIssueRequest struct {
	Fields jiraFields `json:"fields"`
}

type jiraFields struct {
	Project     jiraProject   `json:"project"`
	Summary     string        `json:"summary"`
	Description jiraContent   `json:"description"`
	IssueType   jiraNamedItem `json:"issuetype"`
	Priority    jiraNamedItem `json:"priority"`
	Labels      []string      `json:"labels,omitempty"`
}

type jiraProject struct {
	Key string `json:"key"`
}

type jiraNamedItem struct {
	Name string `json:"name"`
}

// jiraContent is the Atlassian Document Format (ADF) for the description field.
type jiraContent struct {
	Version int            `json:"version"`
	Type    string         `json:"type"`
	Content []jiraADFNode  `json:"content"`
}

type jiraADFNode struct {
	Type    string         `json:"type"`
	Content []jiraADFNode  `json:"content,omitempty"`
	Text    string         `json:"text,omitempty"`
	Marks   []jiraADFMark  `json:"marks,omitempty"`
}

type jiraADFMark struct {
	Type string `json:"type"`
}

type jiraIssueResponse struct {
	ID  string `json:"id"`
	Key string `json:"key"`
	Self string `json:"self"`
}

// NewJiraConnector creates a JiraConnector from a settings map.
func NewJiraConnector(name string, settings map[string]interface{}, log logger.Logger) (*JiraConnector, error) {
	cfg := JiraConfig{
		IssueType:   "Bug",
		MinSeverity: "high",
		PriorityMap: map[string]string{
			"critical": "Critical",
			"high":     "High",
			"medium":   "Medium",
			"low":      "Low",
		},
	}

	if v, ok := settings["base_url"].(string); ok {
		cfg.BaseURL = strings.TrimRight(v, "/")
	}
	if v, ok := settings["email"].(string); ok {
		cfg.Email = v
	}
	if v, ok := settings["api_token"].(string); ok {
		cfg.APIToken = v
	}
	if v, ok := settings["project"].(string); ok {
		cfg.Project = v
	}
	if v, ok := settings["issue_type"].(string); ok && v != "" {
		cfg.IssueType = v
	}
	if v, ok := settings["min_severity"].(string); ok && v != "" {
		cfg.MinSeverity = v
	}
	if v, ok := settings["labels"].([]interface{}); ok {
		for _, l := range v {
			if s, ok := l.(string); ok {
				cfg.Labels = append(cfg.Labels, s)
			}
		}
	}
	if v, ok := settings["priority_map"].(map[string]interface{}); ok {
		for k, val := range v {
			if s, ok := val.(string); ok {
				cfg.PriorityMap[k] = s
			}
		}
	}

	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("jira connector %q: base_url is required", name)
	}
	if cfg.Email == "" || cfg.APIToken == "" {
		return nil, fmt.Errorf("jira connector %q: email and api_token are required", name)
	}
	if cfg.Project == "" {
		return nil, fmt.Errorf("jira connector %q: project is required", name)
	}

	return &JiraConnector{
		name:   name,
		config: cfg,
		client: &http.Client{Timeout: 15 * time.Second},
		logger: log,
	}, nil
}

func (c *JiraConnector) GetName() string { return c.name }
func (c *JiraConnector) GetType() string { return "jira" }
func (c *JiraConnector) Health() integrations.HealthStatus {
	return c.health
}

func (c *JiraConnector) Close() error {
	c.health = integrations.HealthStatus{Healthy: false}
	return nil
}

// Connect validates credentials by calling GET /rest/api/3/myself.
func (c *JiraConnector) Connect(ctx context.Context) error {
	url := c.config.BaseURL + "/rest/api/3/myself"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("jira: connect: build request: %w", err)
	}
	req.SetBasicAuth(c.config.Email, c.config.APIToken)
	req.Header.Set("Accept", "application/json")

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		c.health = integrations.HealthStatus{
			Healthy:   false,
			LastCheck: time.Now(),
			LastError: err.Error(),
		}
		return fmt.Errorf("jira: connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		c.health = integrations.HealthStatus{
			Healthy:   false,
			LastCheck: time.Now(),
			LastError: "invalid credentials",
		}
		return fmt.Errorf("jira: connect: authentication failed (check email and api_token)")
	}
	if resp.StatusCode >= 400 {
		c.health = integrations.HealthStatus{
			Healthy:   false,
			LastCheck: time.Now(),
			LastError: fmt.Sprintf("HTTP %d", resp.StatusCode),
		}
		return fmt.Errorf("jira: connect: HTTP %d", resp.StatusCode)
	}

	c.health = integrations.HealthStatus{
		Healthy:     true,
		LastCheck:   time.Now(),
		Latency:     time.Since(start),
		ConnectedAt: time.Now(),
	}
	c.logger.Info("Jira connector connected", map[string]interface{}{
		"base_url": c.config.BaseURL,
		"project":  c.config.Project,
	})
	return nil
}

// Send creates a Jira issue for the given security event.
func (c *JiraConnector) Send(ctx context.Context, event *events.SecurityEvent) error {
	if event == nil {
		return nil
	}

	severity := strings.ToLower(string(event.Severity))
	if !c.jiraMeetsMinSeverity(severity) {
		return nil
	}

	priority := c.config.PriorityMap[severity]
	if priority == "" {
		priority = "Medium"
	}

	summary := fmt.Sprintf("[Falcn] %s: %s threat in %s",
		strings.ToUpper(severity), event.Threat.Type, event.Package.Name)
	if len(summary) > 255 {
		summary = summary[:252] + "..."
	}

	description := c.buildDescription(event, severity)
	labels := append([]string{"falcn", "supply-chain", severity}, c.config.Labels...)

	issue := jiraIssueRequest{
		Fields: jiraFields{
			Project:     jiraProject{Key: c.config.Project},
			Summary:     summary,
			Description: description,
			IssueType:   jiraNamedItem{Name: c.config.IssueType},
			Priority:    jiraNamedItem{Name: priority},
			Labels:      labels,
		},
	}

	body, err := json.Marshal(issue)
	if err != nil {
		return fmt.Errorf("jira: marshal issue: %w", err)
	}

	url := c.config.BaseURL + "/rest/api/3/issue"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("jira: create issue: build request: %w", err)
	}
	req.SetBasicAuth(c.config.Email, c.config.APIToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		c.health.ErrorCount++
		c.health.LastError = err.Error()
		c.health.LastCheck = time.Now()
		return fmt.Errorf("jira: create issue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		c.health.ErrorCount++
		c.health.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
		c.health.LastCheck = time.Now()
		return fmt.Errorf("jira: create issue: HTTP %d", resp.StatusCode)
	}

	var created jiraIssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err == nil && created.Key != "" {
		c.logger.Info("Jira issue created", map[string]interface{}{
			"issue_key": created.Key,
			"package":   event.Package.Name,
			"severity":  severity,
		})
	}

	c.health.EventsSent++
	c.health.LastCheck = time.Now()
	return nil
}

// buildDescription constructs an ADF document for the issue body.
func (c *JiraConnector) buildDescription(event *events.SecurityEvent, severity string) jiraContent {
	bold := func(text string) jiraADFNode {
		return jiraADFNode{
			Type: "text",
			Text: text,
			Marks: []jiraADFMark{{Type: "strong"}},
		}
	}
	text := func(t string) jiraADFNode {
		return jiraADFNode{Type: "text", Text: t}
	}
	para := func(nodes ...jiraADFNode) jiraADFNode {
		return jiraADFNode{Type: "paragraph", Content: nodes}
	}

	rows := []struct{ label, value string }{
		{"Package", event.Package.Name},
		{"Registry", event.Package.Registry},
		{"Severity", strings.ToUpper(severity)},
		{"Threat Type", event.Threat.Type},
		{"Detected At", event.Timestamp.Format(time.RFC3339)},
		{"Description", event.Threat.Description},
	}

	var paragraphs []jiraADFNode
	for _, row := range rows {
		paragraphs = append(paragraphs, para(bold(row.label+": "), text(row.value)))
	}

	return jiraContent{
		Version: 1,
		Type:    "doc",
		Content: paragraphs,
	}
}

func (c *JiraConnector) jiraMeetsMinSeverity(severity string) bool {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	return rank[severity] >= rank[c.config.MinSeverity]
}
