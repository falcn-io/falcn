#!/bin/bash

# 1. LLM Scan
export FALCN_LLM_ENABLED=true
export FALCN_LLM_PROVIDER=ollama
../falcn.exe scan ./falcn-magic-demo

# 2. Vulnerability Scan
#../falcn.exe scan ./falcn-magic-demo --check-vulnerabilities
