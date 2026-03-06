package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// registryClient is an OCI Distribution-spec v1.1 client.
// It handles authentication for Docker Hub (token service), GHCR, Quay.io,
// GCR, ECR, and ACR using the WWW-Authenticate challenge/response flow.
type registryClient struct {
	ref    ImageRef
	opts   ScanOptions
	http   *http.Client
	token  string // bearer token, populated after auth()
}

// newClient constructs a registry client for the given image reference.
func newClient(ref ImageRef, opts ScanOptions) *registryClient {
	transport := http.DefaultTransport
	if opts.Insecure {
		transport = &http.Transport{} // plain HTTP
	}
	return &registryClient{
		ref:  ref,
		opts: opts,
		http: &http.Client{Timeout: 60 * time.Second, Transport: transport},
	}
}

// ─── Authentication ───────────────────────────────────────────────────────────

// authenticate performs the WWW-Authenticate challenge flow to obtain a bearer
// token. It is called lazily on the first request that returns 401.
func (c *registryClient) authenticate(ctx context.Context, wwwAuth string) error {
	// Parse: Bearer realm="...",service="...",scope="..."
	params := parseWWWAuthenticate(wwwAuth)
	realm := params["realm"]
	if realm == "" {
		return fmt.Errorf("no realm in WWW-Authenticate: %s", wwwAuth)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm, nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	if sc := params["scope"]; sc != "" {
		q.Set("scope", sc)
	}
	req.URL.RawQuery = q.Encode()

	// Supply credentials if provided.
	if c.opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.opts.Token)
	} else if c.opts.Username != "" {
		req.SetBasicAuth(c.opts.Username, c.opts.Password)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth service returned %d", resp.StatusCode)
	}

	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	if body.Token != "" {
		c.token = body.Token
	} else {
		c.token = body.AccessToken
	}
	return nil
}

// parseWWWAuthenticate parses a WWW-Authenticate header value into a key=value map.
// Example: `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`
func parseWWWAuthenticate(s string) map[string]string {
	out := make(map[string]string)
	// Strip leading scheme word (e.g. "Bearer ")
	if idx := strings.Index(s, " "); idx != -1 {
		s = s[idx+1:]
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		out[key] = val
	}
	return out
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

// do executes an HTTP request, handling authentication challenges transparently.
// On a 401, it reads the WWW-Authenticate header, obtains a token, and retries.
func (c *registryClient) do(ctx context.Context, method, url string, accept ...string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	if len(accept) > 0 {
		req.Header.Set("Accept", strings.Join(accept, ", "))
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else if c.opts.Username != "" {
		req.SetBasicAuth(c.opts.Username, c.opts.Password)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}

	// Handle 401: authenticate and retry once.
	if resp.StatusCode == http.StatusUnauthorized {
		_ = resp.Body.Close()
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth == "" {
			return nil, fmt.Errorf("registry requires authentication but no WWW-Authenticate header was returned")
		}
		if err := c.authenticate(ctx, wwwAuth); err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
		// Retry with the new token.
		req2, _ := http.NewRequestWithContext(ctx, method, url, nil)
		if len(accept) > 0 {
			req2.Header.Set("Accept", strings.Join(accept, ", "))
		}
		req2.Header.Set("Authorization", "Bearer "+c.token)
		return c.http.Do(req2)
	}

	return resp, nil
}

// ─── Manifest ─────────────────────────────────────────────────────────────────

// knownManifestMediaTypes lists the OCI and Docker manifest media types that
// registries may return. The order is intentional: OCI v1 is preferred.
var knownManifestMediaTypes = []string{
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.distribution.manifest.v1+prettyjws",
}

// GetManifest fetches the image manifest for the configured reference.
// It returns the parsed manifest and the content-digest header value.
func (c *registryClient) GetManifest(ctx context.Context) (*ImageManifest, string, error) {
	ref := c.ref.Tag
	if ref == "" {
		ref = c.ref.Digest
	}
	if ref == "" {
		ref = "latest"
	}

	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", c.ref.Registry, c.ref.Name, ref)
	resp, err := c.do(ctx, http.MethodGet, url, knownManifestMediaTypes...)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", fmt.Errorf("manifest fetch returned %d: %s", resp.StatusCode, body)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	contentType := resp.Header.Get("Content-Type")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MB max
	if err != nil {
		return nil, "", err
	}

	// Handle OCI/Docker index (fat manifest) – pick the first amd64/linux entry.
	if strings.Contains(contentType, "manifest.list") || strings.Contains(contentType, "index") {
		body, digest, err = c.resolveIndex(ctx, body)
		if err != nil {
			return nil, "", err
		}
	}

	var m ImageManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, "", fmt.Errorf("manifest JSON parse: %w", err)
	}
	m.ResolvedDigest = digest
	return &m, digest, nil
}

// resolveIndex picks the amd64/linux manifest from a fat manifest (image index).
func (c *registryClient) resolveIndex(ctx context.Context, body []byte) ([]byte, string, error) {
	var idx struct {
		Manifests []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
			Platform  struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, "", fmt.Errorf("manifest index parse: %w", err)
	}

	// Prefer linux/amd64; fall back to first entry.
	target := ""
	for _, m := range idx.Manifests {
		if m.Platform.OS == "linux" && m.Platform.Architecture == "amd64" {
			target = m.Digest
			break
		}
	}
	if target == "" && len(idx.Manifests) > 0 {
		target = idx.Manifests[0].Digest
	}
	if target == "" {
		return nil, "", fmt.Errorf("manifest index has no entries")
	}

	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", c.ref.Registry, c.ref.Name, target)
	resp, err := c.do(ctx, http.MethodGet, url, knownManifestMediaTypes...)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("platform manifest fetch returned %d", resp.StatusCode)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return data, digest, err
}

// ─── Config blob ──────────────────────────────────────────────────────────────

// GetConfig fetches and parses the image configuration blob.
func (c *registryClient) GetConfig(ctx context.Context, digest string) (*ImageConfig, error) {
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", c.ref.Registry, c.ref.Name, digest)
	resp, err := c.do(ctx, http.MethodGet, url,
		"application/vnd.oci.image.config.v1+json",
		"application/vnd.docker.container.image.v1+json",
		"application/json",
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config fetch returned %d", resp.StatusCode)
	}

	var cfg ImageConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config JSON parse: %w", err)
	}
	return &cfg, nil
}

// ─── Layer blob ───────────────────────────────────────────────────────────────

// GetLayerStream returns a ReadCloser for the compressed layer blob.
// The caller is responsible for closing it.
// Returns nil, nil when the layer exceeds maxBytes.
func (c *registryClient) GetLayerStream(ctx context.Context, digest string, maxBytes int64) (io.ReadCloser, error) {
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", c.ref.Registry, c.ref.Name, digest)
	resp, err := c.do(ctx, http.MethodGet, url,
		"application/vnd.oci.image.layer.v1.tar+gzip",
		"application/vnd.docker.image.rootfs.diff.tar.gzip",
		"application/octet-stream",
	)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("layer fetch returned %d", resp.StatusCode)
	}

	// Enforce size limit based on Content-Length (when available).
	if cl := resp.ContentLength; cl > 0 && maxBytes > 0 && cl > maxBytes {
		_ = resp.Body.Close()
		return nil, nil // signal: skip this layer
	}

	return resp.Body, nil
}

// ─── Image reference parser ───────────────────────────────────────────────────

// ParseImageRef parses a Docker/OCI image reference string into an ImageRef.
//
// Supported formats:
//
//	nginx                          → docker.io/library/nginx:latest
//	nginx:1.27                     → docker.io/library/nginx:1.27
//	myorg/myapp:v2                 → docker.io/myorg/myapp:v2
//	ghcr.io/owner/repo:sha-abc     → ghcr.io/owner/repo:sha-abc
//	quay.io/fedora/fedora:40       → quay.io/fedora/fedora:40
//	gcr.io/google-containers/pause → gcr.io/google-containers/pause:latest
//	img@sha256:deadbeef            → docker.io/library/img (digest)
func ParseImageRef(s string) (ImageRef, error) {
	ref := ImageRef{Original: s}

	// Separate digest if present.
	if idx := strings.Index(s, "@"); idx != -1 {
		ref.Digest = s[idx+1:]
		s = s[:idx]
	}

	// Determine registry vs repository/tag.
	// A registry host contains a "." or ":" or is "localhost".
	parts := strings.SplitN(s, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		ref.Registry = parts[0]
		s = parts[1]
	} else {
		ref.Registry = "index.docker.io"
	}

	// Normalise Docker Hub registry host.
	if ref.Registry == "docker.io" {
		ref.Registry = "index.docker.io"
	}

	// Separate tag from name.
	if idx := strings.LastIndex(s, ":"); idx != -1 && ref.Digest == "" {
		ref.Tag = s[idx+1:]
		s = s[:idx]
	}
	if ref.Tag == "" && ref.Digest == "" {
		ref.Tag = "latest"
	}

	// Reject empty name before applying any prefix.
	if s == "" {
		return ref, fmt.Errorf("empty image name in reference %q", ref.Original)
	}

	// Docker Hub images without an explicit org get "library/" prefix.
	if ref.Registry == "index.docker.io" && !strings.Contains(s, "/") {
		s = "library/" + s
	}
	ref.Name = s
	return ref, nil
}
