package falcn.policy

violations[{"message": sprintf("binary in legitimate path for %s", [input["package"].name]), "severity": "medium"}] {
  t := input["package"].threats[_]
  t.type == "binary_detection"
  e := t.evidence[_]
  contains(e.value, "node_modules")
}

violations[{"message": sprintf("binary in build path for %s", [input["package"].name]), "severity": "medium"}] {
  t := input["package"].threats[_]
  t.type == "binary_detection"
  e := t.evidence[_]
  contains(e.value, "build/")
}

# High severity when binary detection without legitimate paths
violations[{"message": sprintf("binary in non-legitimate path for %s", [input["package"].name]), "severity": "high"}] {
  t := input["package"].threats[_]
  t.type == "binary_detection"
  # Check if NO evidence contains node_modules or build/
  count({e | e := t.evidence[_]; contains(e.value, "node_modules")}) == 0
  count({e | e := t.evidence[_]; contains(e.value, "build/")}) == 0
}
