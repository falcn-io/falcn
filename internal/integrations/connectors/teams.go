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

// TeamsConnector sends threat notifications to Microsoft Teams via Incoming Webhooks.
type TeamsConnector struct {
	name   string
	config TeamsConfig
	client *http.Client
	logger logger.Logger
	health integrations.HealthStatus
}

// TeamsConfig holds Microsoft Teams configuration.
type TeamsConfig struct {
	WebhookURL   string   `json:"webhook_url"`
	Title        string   `json:"title"`         // card title prefix
	MinSeverity  string   `json:"min_severity"`  // low|medium|high|critical (default: high)
	MentionUsers []string `json:"mention_users"` // Teams user IDs to @mention on critical
}

// teamsAdaptiveCard is the O365 Connector card payload.
type teamsAdaptiveCard struct {
	Type       string         `json:"@type"`
	Context    string         `json:"@context"`
	Summary    string         `json:"summary"`
	ThemeColor string         `json:"themeColor"`
	Title      string         `json:"title"`
	Sections   []teamsSection `json:"sections"`
	Actions    []teamsAction  `json:"potentialAction,omitempty"`
}

type teamsSection struct {
	Facts    []teamsFact `json:"facts,omitempty"`
	Text     string      `json:"text,omitempty"`
	Markdown bool        `json:"markdown"`
}

type teamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type teamsAction struct {
	Type    string        `json:"@type"`
	Name    string        `json:"name"`
	Targets []teamsTarget `json:"targets,omitempty"`
}

type teamsTarget struct {
	OS  string `json:"os"`
	URI string `json:"uri"`
}

// NewTeamsConnector creates a TeamsConnector from a settings map.
func NewTeamsConnector(name string, settings map[string]interface{}, log logger.Logger) (*TeamsConnector, error) {
	cfg := TeamsConfig{
		Title:       "Falcn Security Alert",
		MinSeverity: "high",
	}
	if v, ok := settings["webhook_url"].(string); ok {
		cfg.WebhookURL = v
	}
	if v, ok := settings["title"].(string); ok && v != "" {
		cfg.Title = v
	}
	if v, ok := settings["min_severity"].(string); ok && v != "" {
		cfg.MinSeverity = v
	}
	if v, ok := settings["mention_users"].([]interface{}); ok {
		for _, u := range v {
			if s, ok := u.(string); ok {
				cfg.MentionUsers = append(cfg.MentionUsers, s)
			}
		}
	}
	if cfg.WebhookURL == "" {
		return nil, fmt.Errorf("teams connector %q: webhook_url is required", name)
	}
	return &TeamsConnector{
		name:   name,
		config: cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: log,
	}, nil
}

func (c *TeamsConnector) GetName() string { return c.name }
func (c *TeamsConnector) GetType() string { return "teams" }
func (c *TeamsConnector) Health() integrations.HealthStatus {
	return c.health
}

func (c *TeamsConnector) Close() error {
	c.health = integrations.HealthStatus{Healthy: false}
	return nil
}

func (c *TeamsConnector) Connect(ctx context.Context) error {
	// Validate webhook by sending a silent ping
	card := teamsAdaptiveCard{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		Summary:    "Falcn connector test",
		Title:      c.config.Title + " — Connected",
		ThemeColor: "0076D7",
		Sections:   []teamsSection{{Text: "Falcn is now connected and will send threat alerts here.", Markdown: true}},
	}
	start := time.Now()
	if err := c.sendCard(ctx, card); err != nil {
		c.health = integrations.HealthStatus{
			Healthy:   false,
			LastCheck: time.Now(),
			LastError: err.Error(),
		}
		return fmt.Errorf("teams: connect: %w", err)
	}
	c.health = integrations.HealthStatus{
		Healthy:     true,
		LastCheck:   time.Now(),
		Latency:     time.Since(start),
		ConnectedAt: time.Now(),
	}
	return nil
}

func (c *TeamsConnector) Send(ctx context.Context, event *events.SecurityEvent) error {
	if event == nil {
		return nil
	}
	severity := strings.ToLower(string(event.Severity))
	if !c.meetsMinSeverity(severity) {
		return nil
	}

	color := teamsColorBySeverity(severity)
	facts := []teamsFact{
		{Name: "Package", Value: event.Package.Name},
		{Name: "Severity", Value: strings.ToUpper(severity)},
		{Name: "Type", Value: event.Threat.Type},
		{Name: "Registry", Value: event.Package.Registry},
		{Name: "Detected At", Value: event.Timestamp.Format(time.RFC3339)},
	}

	var mentions string
	if severity == "critical" && len(c.config.MentionUsers) > 0 {
		mentions = "<at>" + strings.Join(c.config.MentionUsers, "</at> <at>") + "</at>"
	}

	card := teamsAdaptiveCard{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		Summary:    fmt.Sprintf("Falcn: %s threat in %s", strings.ToUpper(severity), event.Package.Name),
		ThemeColor: color,
		Title:      fmt.Sprintf("%s — %s Threat Detected", c.config.Title, strings.ToUpper(severity)),
		Sections: []teamsSection{
			{Facts: facts, Markdown: true},
			{Text: "**Description:** " + event.Threat.Description + "\n\n" + mentions, Markdown: true},
		},
	}

	err := c.sendCard(ctx, card)
	if err != nil {
		c.health.ErrorCount++
		c.health.LastError = err.Error()
	} else {
		c.health.EventsSent++
	}
	c.health.LastCheck = time.Now()
	return err
}

func (c *TeamsConnector) sendCard(ctx context.Context, card teamsAdaptiveCard) error {
	body, err := json.Marshal(card)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("teams: send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("teams: HTTP %d from webhook", resp.StatusCode)
	}
	return nil
}

func (c *TeamsConnector) meetsMinSeverity(severity string) bool {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	return rank[severity] >= rank[c.config.MinSeverity]
}

func teamsColorBySeverity(severity string) string {
	switch severity {
	case "critical":
		return "B10000" // deep red
	case "high":
		return "FF6200" // orange
	case "medium":
		return "FFD700" // yellow
	default:
		return "0076D7" // blue
	}
}
