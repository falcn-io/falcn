#!/usr/bin/env python3
"""
export_tree_params.py — Extract the TreeEnsembleClassifier from the Falcn
reputation ONNX model and write it to resources/models/tree_params.json.

The JSON is consumed by internal/ml/tree_inference.go at runtime to run
pure-Go inference with no CGO or external dependencies.

Usage:
    python3 scripts/export_tree_params.py [--model PATH] [--out PATH]

Requirements:
    pip install onnx
"""
import argparse
import json
import os
import sys

try:
    import onnx
except ImportError:
    print("ERROR: onnx Python package not found. Install with: pip install onnx", file=sys.stderr)
    sys.exit(1)


def extract(model_path: str) -> dict:
    model = onnx.load(model_path)
    # Locate the TreeEnsembleClassifier node.
    tec_node = None
    for node in model.graph.node:
        if node.op_type == "TreeEnsembleClassifier":
            tec_node = node
            break
    if tec_node is None:
        raise ValueError("No TreeEnsembleClassifier node found in model graph")

    attrs = {}
    for attr in tec_node.attribute:
        if attr.floats:
            attrs[attr.name] = list(attr.floats)
        elif attr.ints:
            attrs[attr.name] = list(attr.ints)
        elif attr.strings:
            attrs[attr.name] = [s.decode() for s in attr.strings]
        elif attr.f != 0.0:
            attrs[attr.name] = attr.f
        elif attr.i != 0:
            attrs[attr.name] = attr.i
        elif attr.s:
            attrs[attr.name] = attr.s.decode()

    # Validate required keys are present.
    required = [
        "nodes_treeids", "nodes_nodeids", "nodes_featureids", "nodes_values",
        "nodes_truenodeids", "nodes_falsenodeids", "nodes_modes",
        "class_treeids", "class_nodeids", "class_ids", "class_weights",
        "classlabels_int64s",
    ]
    for key in required:
        if key not in attrs:
            raise ValueError(f"Missing required attribute: {key}")

    n_trees = len(set(attrs["nodes_treeids"]))
    n_nodes = len(attrs["nodes_nodeids"])
    n_leaves = len(attrs["class_nodeids"])
    n_classes = len(set(attrs["classlabels_int64s"]))
    post_transform = attrs.get("post_transform", "NONE")

    print(f"  Trees         : {n_trees}")
    print(f"  Total nodes   : {n_nodes}")
    print(f"  Leaf weights  : {n_leaves}")
    print(f"  Classes       : {n_classes}  {attrs['classlabels_int64s']}")
    print(f"  post_transform: {post_transform}")

    return {
        "n_trees":        n_trees,
        "n_classes":      n_classes,
        "post_transform": post_transform,
        "classlabels":    attrs["classlabels_int64s"],
        # Node arrays (parallel, indexed 0..n_nodes-1)
        "nodes_treeids":     attrs["nodes_treeids"],
        "nodes_nodeids":     attrs["nodes_nodeids"],
        "nodes_featureids":  attrs["nodes_featureids"],
        "nodes_values":      attrs["nodes_values"],
        "nodes_truenodeids": attrs["nodes_truenodeids"],
        "nodes_falsenodeids":attrs["nodes_falsenodeids"],
        "nodes_modes":       attrs["nodes_modes"],   # "BRANCH_LEQ" or "LEAF"
        # Leaf weight arrays (parallel, indexed 0..n_leaves-1)
        "class_treeids":  attrs["class_treeids"],
        "class_nodeids":  attrs["class_nodeids"],
        "class_ids":      attrs["class_ids"],
        "class_weights":  attrs["class_weights"],
    }


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_model = os.path.join(repo_root, "resources", "models", "reputation_model.onnx")
    default_out   = os.path.join(repo_root, "resources", "models", "tree_params.json")

    parser = argparse.ArgumentParser(description="Export ONNX tree params to JSON for pure-Go inference")
    parser.add_argument("--model", default=default_model, help="Path to reputation_model.onnx")
    parser.add_argument("--out",   default=default_out,   help="Output JSON path")
    args = parser.parse_args()

    print(f"Loading model : {args.model}")
    params = extract(args.model)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(params, f, separators=(",", ":"))  # compact — no whitespace

    size_kb = os.path.getsize(args.out) / 1024
    print(f"Written       : {args.out}  ({size_kb:.0f} KB)")
    print("Done.")


if __name__ == "__main__":
    main()
