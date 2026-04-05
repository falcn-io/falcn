package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/falcn-io/falcn/pkg/types"
)

func TestCICDScanner_ActionPinning(t *testing.T) {
	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	tests := []struct {
		name        string
		content     string
		wantThreats bool
		desc        string
	}{
		{
			name: "Unpinned third-party action on main branch",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: malicious-org/deploy-action@main
      - run: echo "deployed"
`,
			wantThreats: true,
			desc:        "Third-party action @main should be flagged",
		},
		{
			name: "SHA-pinned action is safe",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: echo "built"
`,
			wantThreats: false,
			desc:        "SHA-pinned actions should not be flagged",
		},
		{
			name: "Third-party with semver tag",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/risky-action@v2
      - run: echo "done"
`,
			wantThreats: true,
			desc:        "Third-party action with @v2 tag should be flagged (tags can be force-pushed)",
		},
		{
			name: "Official actions with semver tag",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm test
`,
			wantThreats: false,
			desc:        "Official actions/* with semver tags are acceptable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wfFile := filepath.Join(workflowDir, "test.yml")
			os.WriteFile(wfFile, []byte(tt.content), 0644)
			defer os.Remove(wfFile)

			scanner := NewCICDScanner(tmpDir)
			threats, err := scanner.ScanProject()
			if err != nil {
				t.Fatalf("ScanProject failed: %v", err)
			}

			hasPinningThreat := false
			for _, th := range threats {
				if th.Description != "" && (strings.Contains(th.Description, "unpinned") || strings.Contains(th.Description, "Unpinned")) {
					hasPinningThreat = true
				}
			}

			if tt.wantThreats && !hasPinningThreat {
				t.Errorf("%s: expected pinning threat but got none (threats: %d)", tt.desc, len(threats))
			}
			if !tt.wantThreats && hasPinningThreat {
				t.Errorf("%s: unexpected pinning threat", tt.desc)
			}
		})
	}
}

func TestCICDScanner_HeadCommitInjection(t *testing.T) {
	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	content := `name: Auto-deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Deploying commit ${{ github.event.head_commit.message }}"
`
	wfFile := filepath.Join(workflowDir, "deploy.yml")
	os.WriteFile(wfFile, []byte(content), 0644)

	scanner := NewCICDScanner(tmpDir)
	threats, err := scanner.ScanProject()
	if err != nil {
		t.Fatalf("ScanProject failed: %v", err)
	}

	hasInjection := false
	for _, th := range threats {
		if strings.Contains(th.Description, "injection") || strings.Contains(th.Description, "Injection") {
			hasInjection = true
			break
		}
	}
	if !hasInjection {
		t.Error("head_commit.message injection should be detected")
	}
}

func TestCICDScanner_HeadRefInjection(t *testing.T) {
	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	content := `name: PR Build
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Building branch ${{ github.head_ref }}"
`
	wfFile := filepath.Join(workflowDir, "pr.yml")
	os.WriteFile(wfFile, []byte(content), 0644)

	scanner := NewCICDScanner(tmpDir)
	threats, err := scanner.ScanProject()
	if err != nil {
		t.Fatalf("ScanProject failed: %v", err)
	}

	hasInjection := false
	for _, th := range threats {
		if strings.Contains(th.Description, "injection") || strings.Contains(th.Description, "head_ref") {
			hasInjection = true
			break
		}
	}
	if !hasInjection {
		t.Error("github.head_ref branch name injection should be detected")
	}
}

func TestCICDScanner_GitLabCI_SafeVaultRef(t *testing.T) {
	tmpDir := t.TempDir()
	content := `stages:
  - deploy

deploy:
  stage: deploy
  script:
    - deploy.sh
  variables:
    PASSWORD: $CI_DEPLOY_PASSWORD
    TOKEN: $CI_JOB_TOKEN
`
	os.WriteFile(filepath.Join(tmpDir, ".gitlab-ci.yml"), []byte(content), 0644)

	scanner := NewCICDScanner(tmpDir)
	threats, err := scanner.ScanProject()
	if err != nil {
		t.Fatalf("ScanProject failed: %v", err)
	}

	for _, th := range threats {
		if strings.Contains(th.Description, "secrets") || strings.Contains(th.Description, "hardcoded") {
			t.Errorf("GitLab CI with $CI_VARIABLE references should NOT trigger secrets detection; got: %s", th.Description)
		}
	}
}

func TestPullRequestTargetCheckout_Dangerous(t *testing.T) {
	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	content := `name: PR Target
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`
	wfFile := filepath.Join(workflowDir, "pr.yml")
	os.WriteFile(wfFile, []byte(content), 0644)

	scanner := NewCICDScanner(tmpDir)
	threats, err := scanner.ScanProject()
	if err != nil {
		t.Fatalf("ScanProject failed: %v", err)
	}

	found := false
	for _, th := range threats {
		if strings.Contains(th.Description, "pull_request_target") {
			found = true
			if th.Severity != types.SeverityCritical {
				t.Errorf("expected critical severity, got %s", th.Severity)
			}
		}
	}
	if !found {
		t.Error("Should detect pull_request_target + checkout of PR head")
	}
}

func TestPullRequestTargetCheckout_MapTrigger(t *testing.T) {
	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	content := `name: PR Target Map
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - run: make test
`
	wfFile := filepath.Join(workflowDir, "pr-map.yml")
	os.WriteFile(wfFile, []byte(content), 0644)

	scanner := NewCICDScanner(tmpDir)
	threats, err := scanner.ScanProject()
	if err != nil {
		t.Fatalf("ScanProject failed: %v", err)
	}

	found := false
	for _, th := range threats {
		if strings.Contains(th.Description, "pull_request_target") {
			found = true
		}
	}
	if !found {
		t.Error("Should detect pull_request_target (map trigger) + checkout of PR head.ref")
	}
}

func TestPullRequestTargetCheckout_Safe(t *testing.T) {
	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	// pull_request_target WITHOUT checking out the PR head — should be safe.
	content := `name: PR Target Safe
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "labeling PR"
`
	wfFile := filepath.Join(workflowDir, "pr-safe.yml")
	os.WriteFile(wfFile, []byte(content), 0644)

	scanner := NewCICDScanner(tmpDir)
	threats, err := scanner.ScanProject()
	if err != nil {
		t.Fatalf("ScanProject failed: %v", err)
	}

	for _, th := range threats {
		if strings.Contains(th.Description, "pull_request_target") {
			t.Errorf("pull_request_target WITHOUT PR head checkout should NOT be flagged; got: %s", th.Description)
		}
	}
}

func TestPullRequestTargetCheckout_NoPRTarget(t *testing.T) {
	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)

	// Regular pull_request trigger with checkout of head — safe because
	// pull_request runs with read-only permissions.
	content := `name: Regular PR
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`
	wfFile := filepath.Join(workflowDir, "pr-regular.yml")
	os.WriteFile(wfFile, []byte(content), 0644)

	scanner := NewCICDScanner(tmpDir)
	threats, err := scanner.ScanProject()
	if err != nil {
		t.Fatalf("ScanProject failed: %v", err)
	}

	for _, th := range threats {
		if strings.Contains(th.Description, "pull_request_target") {
			t.Errorf("regular pull_request trigger should NOT trigger pull_request_target detection; got: %s", th.Description)
		}
	}
}

// helper reuses strings.Contains — no custom func needed to avoid name clash
// with install_script_test.go
