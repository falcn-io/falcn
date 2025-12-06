// Edge Algorithm Registry
// Central registry for managing all edge detection algorithms
package edge

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/falcn-io/falcn/pkg/types"
)

// AlgorithmTier represents the tier/level of an algorithm
type AlgorithmTier string

const (
	TierCore AlgorithmTier = "core" // Core algorithms (AICC, GTR, DIRT, RUNT)
	TierX    AlgorithmTier = "x"    // Experimental algorithms (QUANTUM, NEURAL, ADAPTIVE)
	TierPro  AlgorithmTier = "pro"  // Professional algorithms
	TierDev  AlgorithmTier = "dev"  // Development algorithms
)

// Algorithm interface that all edge algorithms must implement
type Algorithm interface {
	Name() string
	Tier() AlgorithmTier
	Description() string
	Analyze(ctx context.Context, packages []string) (*types.AlgorithmResult, error)
	Configure(config map[string]interface{}) error
	GetMetrics() *types.AlgorithmMetrics
	Reset() error
}

// AlgorithmResult, Finding, Evidence, AlgorithmMetrics moved to pkg/types

// AlgorithmInfo contains metadata about an algorithm
type AlgorithmInfo struct {
	Name        string        `json:"name"`
	Tier        AlgorithmTier `json:"tier"`
	Description string        `json:"description"`
	Version     string        `json:"version"`
	Enabled     bool          `json:"enabled"`
	Registered  time.Time     `json:"registered"`
	LastUsed    time.Time     `json:"last_used"`
	UsageCount  int           `json:"usage_count"`
}

// Registry manages all edge algorithms
type Registry struct {
	algorithms map[string]Algorithm
	info       map[string]*AlgorithmInfo
	mu         sync.RWMutex
}

// NewRegistry creates a new algorithm registry
func NewRegistry() *Registry {
	return &Registry{
		algorithms: make(map[string]Algorithm),
		info:       make(map[string]*AlgorithmInfo),
	}
}

// Register registers a new algorithm
func (r *Registry) Register(algorithm Algorithm) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := algorithm.Name()
	if _, exists := r.algorithms[name]; exists {
		return fmt.Errorf("algorithm %s already registered", name)
	}

	r.algorithms[name] = algorithm
	r.info[name] = &AlgorithmInfo{
		Name:        name,
		Tier:        algorithm.Tier(),
		Description: algorithm.Description(),
		Version:     "1.0.0",
		Enabled:     true,
		Registered:  time.Now(),
		UsageCount:  0,
	}

	return nil
}

// Unregister removes an algorithm from the registry
func (r *Registry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.algorithms[name]; !exists {
		return fmt.Errorf("algorithm %s not found", name)
	}

	delete(r.algorithms, name)
	delete(r.info, name)

	return nil
}

// Get retrieves an algorithm by name
func (r *Registry) Get(name string) (Algorithm, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	algorithm, exists := r.algorithms[name]
	if !exists {
		return nil, fmt.Errorf("algorithm %s not found", name)
	}

	info := r.info[name]
	if !info.Enabled {
		return nil, fmt.Errorf("algorithm %s is disabled", name)
	}

	// Update usage statistics
	info.LastUsed = time.Now()
	info.UsageCount++

	return algorithm, nil
}

// List returns all registered algorithms
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.algorithms))
	for name := range r.algorithms {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// ListByTier returns algorithms filtered by tier
func (r *Registry) ListByTier(tier AlgorithmTier) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0)
	for name, info := range r.info {
		if info.Tier == tier && info.Enabled {
			names = append(names, name)
		}
	}

	sort.Strings(names)
	return names
}

// GetInfo returns information about an algorithm
func (r *Registry) GetInfo(name string) (*AlgorithmInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, exists := r.info[name]
	if !exists {
		return nil, fmt.Errorf("algorithm %s not found", name)
	}

	// Return a copy to prevent external modification
	infoCopy := *info
	return &infoCopy, nil
}

// GetAllInfo returns information about all algorithms
func (r *Registry) GetAllInfo() map[string]*AlgorithmInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]*AlgorithmInfo)
	for name, info := range r.info {
		// Return copies to prevent external modification
		infoCopy := *info
		result[name] = &infoCopy
	}

	return result
}

// Enable enables an algorithm
func (r *Registry) Enable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, exists := r.info[name]
	if !exists {
		return fmt.Errorf("algorithm %s not found", name)
	}

	info.Enabled = true
	return nil
}

// Disable disables an algorithm
func (r *Registry) Disable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, exists := r.info[name]
	if !exists {
		return fmt.Errorf("algorithm %s not found", name)
	}

	info.Enabled = false
	return nil
}

// Configure configures an algorithm
func (r *Registry) Configure(name string, config map[string]interface{}) error {
	r.mu.RLock()
	algorithm, exists := r.algorithms[name]
	r.mu.RUnlock()

	if !exists {
		return fmt.Errorf("algorithm %s not found", name)
	}

	return algorithm.Configure(config)
}

// Analyze runs analysis using a specific algorithm
func (r *Registry) Analyze(ctx context.Context, algorithmName string, packages []string) (*types.AlgorithmResult, error) {
	algorithm, err := r.Get(algorithmName)
	if err != nil {
		return nil, err
	}

	return algorithm.Analyze(ctx, packages)
}

// AnalyzeMultiple runs analysis using multiple algorithms
func (r *Registry) AnalyzeMultiple(ctx context.Context, algorithmNames []string, packages []string) (map[string]*types.AlgorithmResult, error) {
	results := make(map[string]*types.AlgorithmResult)
	errors := make(map[string]error)

	for _, name := range algorithmNames {
		result, err := r.Analyze(ctx, name, packages)
		if err != nil {
			errors[name] = err
			continue
		}
		results[name] = result
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("all algorithms failed: %v", errors)
	}

	return results, nil
}

// AnalyzeByTier runs analysis using all algorithms in a specific tier
func (r *Registry) AnalyzeByTier(ctx context.Context, tier AlgorithmTier, packages []string) (map[string]*types.AlgorithmResult, error) {
	algorithmNames := r.ListByTier(tier)
	if len(algorithmNames) == 0 {
		return nil, fmt.Errorf("no enabled algorithms found for tier %s", tier)
	}

	return r.AnalyzeMultiple(ctx, algorithmNames, packages)
}

// GetMetrics returns metrics for an algorithm
func (r *Registry) GetMetrics(name string) (*types.AlgorithmMetrics, error) {
	r.mu.RLock()
	algorithm, exists := r.algorithms[name]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("algorithm %s not found", name)
	}

	return algorithm.GetMetrics(), nil
}

// GetAllMetrics returns metrics for all algorithms
func (r *Registry) GetAllMetrics() map[string]*types.AlgorithmMetrics {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]*types.AlgorithmMetrics)
	for name, algorithm := range r.algorithms {
		result[name] = algorithm.GetMetrics()
	}

	return result
}

// Reset resets an algorithm
func (r *Registry) Reset(name string) error {
	r.mu.RLock()
	algorithm, exists := r.algorithms[name]
	r.mu.RUnlock()

	if !exists {
		return fmt.Errorf("algorithm %s not found", name)
	}

	return algorithm.Reset()
}

// ResetAll resets all algorithms
func (r *Registry) ResetAll() error {
	r.mu.RLock()
	algorithms := make([]Algorithm, 0, len(r.algorithms))
	for _, algorithm := range r.algorithms {
		algorithms = append(algorithms, algorithm)
	}
	r.mu.RUnlock()

	for _, algorithm := range algorithms {
		if err := algorithm.Reset(); err != nil {
			return fmt.Errorf("failed to reset algorithm %s: %w", algorithm.Name(), err)
		}
	}

	return nil
}

// Global registry instance
var globalRegistry = NewRegistry()

// RegisterAlgorithm registers an algorithm in the global registry
func RegisterAlgorithm(algorithm Algorithm) error {
	return globalRegistry.Register(algorithm)
}

// GetAlgorithm retrieves an algorithm from the global registry
func GetAlgorithm(name string) (Algorithm, error) {
	return globalRegistry.Get(name)
}

// ListAlgorithms returns all registered algorithms
func ListAlgorithms() []string {
	return globalRegistry.List()
}

// ListAlgorithmsByTier returns algorithms filtered by tier
func ListAlgorithmsByTier(tier AlgorithmTier) []string {
	return globalRegistry.ListByTier(tier)
}

// GetGlobalRegistry returns the global registry instance
func GetGlobalRegistry() *Registry {
	return globalRegistry
}

// InitializeDefaultAlgorithms initializes all default algorithms
func InitializeDefaultAlgorithms() error {
	// Register core algorithms
	if err := RegisterAlgorithm(NewAICCAlgorithm(nil)); err != nil {
		return fmt.Errorf("failed to register AICC: %w", err)
	}

	if err := RegisterAlgorithm(NewGTRAlgorithm(nil)); err != nil {
		return fmt.Errorf("failed to register GTR: %w", err)
	}

	if err := RegisterAlgorithm(NewDIRTAlgorithm(nil)); err != nil {
		return fmt.Errorf("failed to register DIRT: %w", err)
	}

	if err := RegisterAlgorithm(NewRUNTAlgorithm(nil)); err != nil {
		return fmt.Errorf("failed to register RUNT: %w", err)
	}

	// Experimental algorithms removed for cleanup - keeping only core functional algorithms

	return nil
}
