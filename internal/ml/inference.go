package ml

import (
	"fmt"
	"os"

	"github.com/owulveryck/onnx-go"
	"github.com/owulveryck/onnx-go/backend/x/gorgonnx"
	"gorgonia.org/tensor"
)

// InferenceEngine handles ML model inference
type InferenceEngine struct {
	model   *onnx.Model
	backend *gorgonnx.Graph
	loaded  bool
}

// NewInferenceEngine creates a new inference engine
func NewInferenceEngine() *InferenceEngine {
	backend := gorgonnx.NewGraph()
	model := onnx.NewModel(backend)
	return &InferenceEngine{
		model:   model,
		backend: backend,
		loaded:  false,
	}
}

// LoadModel loads the ONNX model from the specified path
func (ie *InferenceEngine) LoadModel(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read model file: %w", err)
	}

	if err := ie.model.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("failed to unmarshal ONNX model: %w", err)
	}

	ie.loaded = true
	return nil
}

// Predict calculates the probability of the package being malicious
// Returns a score between 0.0 (safe) and 1.0 (malicious)
func (ie *InferenceEngine) Predict(features []float32) (float64, error) {
	if !ie.loaded {
		return 0, fmt.Errorf("model not loaded")
	}

	// Prepare input tensor
	// Shape should match the model input: [1, 7]
	inputTensor := tensor.New(tensor.WithShape(1, 7), tensor.WithBacking(features))

	if err := ie.model.SetInput(0, inputTensor); err != nil {
		return 0, fmt.Errorf("failed to set input: %w", err)
	}

	// Run inference
	if err := ie.backend.Run(); err != nil {
		return 0, fmt.Errorf("inference failed: %w", err)
	}

	// Get output
	// RandomForestClassifier typically outputs [label, probabilities]
	outputs, err := ie.model.GetOutputTensors()
	if err != nil {
		return 0, fmt.Errorf("failed to get outputs: %w", err)
	}

	if len(outputs) < 2 {
		// Maybe only labels returned?
		return 0, fmt.Errorf("unexpected output size: %d", len(outputs))
	}

	// Usually outputs[1] is the probabilities map or tensor
	probs := outputs[1]

	switch t := probs.(type) {
	case tensor.Tensor:
		// For now, let's assume we get a [1, 2] float32 tensor
		if t.Shape()[0] == 1 && t.Shape()[1] == 2 {
			data := t.Data().([]float32)
			return float64(data[1]), nil
		}
	}

	return 0, fmt.Errorf("could not parse output tensor")
}
