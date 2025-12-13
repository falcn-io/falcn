package falcn.policy

violations[{"message": sprintf("suspicious patterns found in %s", [input["package"].name])}] {
  t := input["package"].threats[_]
  t.type == "suspicious_pattern"
}
