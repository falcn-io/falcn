package falcn.policy

violations[{"message": sprintf("typosquat requires multi-signal gating for %s", [input["package"].name])}] {
  t := input["package"].threats[_]
  t.type == "typosquatting"
}
