package ml

// tree_inference.go — Pure-Go ONNX TreeEnsembleClassifier inference.
//
// The Falcn reputation model (resources/models/reputation_model.onnx) is a
// scikit-learn RandomForest/GradientBoosting ensemble exported via skl2onnx.
// Its graph has a single TreeEnsembleClassifier node whose attribute arrays
// fully describe 300 decision trees.
//
// Rather than requiring a CGO ONNX runtime, we pre-export those arrays to
// resources/models/tree_params.json (scripts/export_tree_params.py) and load
// them here at startup. The traversal algorithm is O(depth) per tree and
// typically runs in <1 ms for the full ensemble.
//
// Re-export tree_params.json whenever the model is retrained:
//
//	python3 scripts/export_tree_params.py

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const treeParamsFilename = "tree_params.json"

// treeParamsJSON is the serialised form of tree_params.json.
// All arrays are parallel and indexed 0 .. len(NodesNodeIDs)-1.
type treeParamsJSON struct {
	NTrees        int       `json:"n_trees"`
	NClasses      int       `json:"n_classes"`
	PostTransform string    `json:"post_transform"`
	Classlabels   []int64   `json:"classlabels"`

	// Node arrays (one entry per node, in order of treeID then nodeID)
	NodesTreeIDs     []int64   `json:"nodes_treeids"`
	NodesNodeIDs     []int64   `json:"nodes_nodeids"`
	NodesFeatureIDs  []int64   `json:"nodes_featureids"`
	NodesValues      []float64 `json:"nodes_values"`
	NodesTrueNodeIDs []int64   `json:"nodes_truenodeids"`
	NodesFalseNodeIDs []int64  `json:"nodes_falsenodeids"`
	NodesModes       []string  `json:"nodes_modes"` // "BRANCH_LEQ" | "LEAF"

	// Leaf weight arrays
	ClassTreeIDs []int64   `json:"class_treeids"`
	ClassNodeIDs []int64   `json:"class_nodeids"`
	ClassIDs     []int64   `json:"class_ids"`
	ClassWeights []float64 `json:"class_weights"`
}

// treeNode is the in-memory representation built for fast traversal.
type treeNode struct {
	featureID    int
	threshold    float64
	trueChildIdx int // index into the per-tree node slice
	falseChildIdx int
	isLeaf       bool
	// classWeights[c] is the weight contribution to class c when this leaf is hit.
	classWeights []float64
}

// TreeParams holds the fully-parsed ensemble ready for inference.
type TreeParams struct {
	nTrees   int
	nClasses int
	// trees[t] is a map from nodeID → index in nodes[t], plus the root index.
	trees [][]treeNode // trees[treeIdx][nodeSliceIdx]
	roots []int        // roots[treeIdx] = index into trees[treeIdx] for root node
}

// LoadTreeParams reads tree_params.json from modelDir and parses it into a
// TreeParams ready for inference. Returns nil, nil if the file does not exist
// (caller should fall back to the heuristic scorer).
func LoadTreeParams(modelDir string) (*TreeParams, error) {
	path := filepath.Join(modelDir, treeParamsFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // graceful: heuristic fallback
		}
		return nil, fmt.Errorf("tree_params: read %s: %w", path, err)
	}

	var raw treeParamsJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("tree_params: parse %s: %w", path, err)
	}

	if err := validateRaw(&raw); err != nil {
		return nil, fmt.Errorf("tree_params: %w", err)
	}

	return buildTrees(&raw)
}

func validateRaw(raw *treeParamsJSON) error {
	n := len(raw.NodesNodeIDs)
	if n == 0 {
		return fmt.Errorf("nodes_nodeids is empty")
	}
	for _, arr := range []struct {
		name string
		got  int
	}{
		{"nodes_treeids", len(raw.NodesTreeIDs)},
		{"nodes_featureids", len(raw.NodesFeatureIDs)},
		{"nodes_values", len(raw.NodesValues)},
		{"nodes_truenodeids", len(raw.NodesTrueNodeIDs)},
		{"nodes_falsenodeids", len(raw.NodesFalseNodeIDs)},
		{"nodes_modes", len(raw.NodesModes)},
	} {
		if arr.got != n {
			return fmt.Errorf("length mismatch: %s has %d entries, expected %d", arr.name, arr.got, n)
		}
	}
	return nil
}

// buildTrees converts the flat parallel arrays into the per-tree slice structure
// used by Predict.
func buildTrees(raw *treeParamsJSON) (*TreeParams, error) {
	nTrees := raw.NTrees
	nClasses := raw.NClasses
	if nTrees <= 0 || nClasses <= 0 {
		return nil, fmt.Errorf("invalid n_trees=%d or n_classes=%d", nTrees, nClasses)
	}

	// ── Step 1: build the leaf weight map: (treeID, nodeID) → []float64 weights
	leafWeights := make(map[[2]int64][]float64) // key: [treeID, nodeID]
	for i, tw := range raw.ClassWeights {
		key := [2]int64{raw.ClassTreeIDs[i], raw.ClassNodeIDs[i]}
		cid := int(raw.ClassIDs[i])
		if _, ok := leafWeights[key]; !ok {
			leafWeights[key] = make([]float64, nClasses)
		}
		if cid < nClasses {
			leafWeights[key][cid] += tw
		}
	}

	// ── Step 2: group node entries by treeID, collect (nodeID → slice index) maps
	// treeNodeLists[t] is the list of raw node entries for tree t, in order of
	// appearance in the arrays.
	type rawNode struct {
		nodeID, trueNodeID, falseNodeID int64
		featureID                       int64
		value                           float64
		mode                            string
	}
	treeNodeLists := make([][]rawNode, nTrees)
	treeNodeIndex := make([]map[int64]int, nTrees) // nodeID → slice position
	for i := 0; i < nTrees; i++ {
		treeNodeIndex[i] = make(map[int64]int)
	}

	for i, tid := range raw.NodesTreeIDs {
		t := int(tid)
		if t < 0 || t >= nTrees {
			return nil, fmt.Errorf("invalid treeID %d at index %d", t, i)
		}
		idx := len(treeNodeLists[t])
		treeNodeIndex[t][raw.NodesNodeIDs[i]] = idx
		treeNodeLists[t] = append(treeNodeLists[t], rawNode{
			nodeID:      raw.NodesNodeIDs[i],
			trueNodeID:  raw.NodesTrueNodeIDs[i],
			falseNodeID: raw.NodesFalseNodeIDs[i],
			featureID:   raw.NodesFeatureIDs[i],
			value:       raw.NodesValues[i],
			mode:        raw.NodesModes[i],
		})
	}

	// ── Step 3: convert rawNode slices to treeNode slices with resolved child indices
	trees := make([][]treeNode, nTrees)
	roots := make([]int, nTrees)

	for t := 0; t < nTrees; t++ {
		list := treeNodeLists[t]
		nodes := make([]treeNode, len(list))
		for i, rn := range list {
			isLeaf := rn.mode == "LEAF"
			var weights []float64
			if isLeaf {
				key := [2]int64{int64(t), rn.nodeID}
				weights = leafWeights[key]
			}
			trueIdx, falseIdx := 0, 0
			if !isLeaf {
				ti, ok1 := treeNodeIndex[t][rn.trueNodeID]
				fi, ok2 := treeNodeIndex[t][rn.falseNodeID]
				if !ok1 || !ok2 {
					return nil, fmt.Errorf("tree %d node %d: child node not found", t, rn.nodeID)
				}
				trueIdx, falseIdx = ti, fi
			}
			nodes[i] = treeNode{
				featureID:     int(rn.featureID),
				threshold:     rn.value,
				trueChildIdx:  trueIdx,
				falseChildIdx: falseIdx,
				isLeaf:        isLeaf,
				classWeights:  weights,
			}
		}
		trees[t] = nodes
		// Root is always node with nodeID == 0.
		rootIdx, ok := treeNodeIndex[t][0]
		if !ok {
			return nil, fmt.Errorf("tree %d: no root node (nodeID=0)", t)
		}
		roots[t] = rootIdx
	}

	return &TreeParams{
		nTrees:   nTrees,
		nClasses: nClasses,
		trees:    trees,
		roots:    roots,
	}, nil
}

// Predict runs the full ensemble for a single feature vector and returns the
// probability that the sample belongs to class 1 (malicious), in [0, 1].
//
// features must have at least FeatureVectorSize elements (extra elements are
// ignored). Panics if features is shorter than the deepest feature index used
// by any tree — callers should ensure len(features) >= FeatureVectorSize.
func (tp *TreeParams) Predict(features []float32) float64 {
	totalWeight := make([]float64, tp.nClasses)

	for t := 0; t < tp.nTrees; t++ {
		nodes := tp.trees[t]
		idx := tp.roots[t]
		for {
			n := &nodes[idx]
			if n.isLeaf {
				for c, w := range n.classWeights {
					totalWeight[c] += w
				}
				break
			}
			// BRANCH_LEQ: go left (true child) if feature <= threshold.
			if float64(features[n.featureID]) <= n.threshold {
				idx = n.trueChildIdx
			} else {
				idx = n.falseChildIdx
			}
		}
	}

	// The raw sum of leaf weights across all trees gives the un-normalised score.
	// Normalise by n_trees to obtain a probability in [0, 1].
	if tp.nClasses < 2 {
		return 0
	}
	sum := 0.0
	for _, w := range totalWeight {
		sum += w
	}
	if sum == 0 {
		return 0
	}
	return totalWeight[1] / sum
}
