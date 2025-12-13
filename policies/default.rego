package falcn.policy

violations[{"message": sprintf("embedded secrets detected in %s", [input["package"].name])}] {
  t := input["package"].threats[_]
  t.type == "embedded_secret"
}

violations[{"message": sprintf("install scripts present in %s", [input["package"].name])}] {
  t := input["package"].threats[_]
  t.type == "install_script"
}
