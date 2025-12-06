package falcn.policy

violations[{"message": msg, "severity": "critical"}] {
    input.package.name == "xz"
    input.package.version == "5.6.0"
    msg = "CRITICAL: Detected xz backdoor (CVE-2024-3094) in version 5.6.0"
}

violations[{"message": msg, "severity": "critical"}] {
    input.package.name == "xz"
    input.package.version == "5.6.1"
    msg = "CRITICAL: Detected xz backdoor (CVE-2024-3094) in version 5.6.1"
}
