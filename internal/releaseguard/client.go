package releaseguard

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	githubAPIOrigin    = "https://api.github.com"
	githubUploadOrigin = "https://uploads.github.com"
	apiVersion         = "2026-03-10"
	maxResponseBody    = 2 << 20
	maxRequestJSON     = 64 << 10
)

type service struct {
	client     *http.Client
	apiBase    *url.URL
	uploadBase *url.URL
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func newGitHubService() *service {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}).DialContext,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	result, err := newService(client, githubAPIOrigin, githubUploadOrigin)
	if err != nil {
		panic(err)
	}
	return result
}

func newService(client *http.Client, apiOrigin, uploadOrigin string) (*service, error) {
	if client == nil {
		return nil, errors.New("HTTP client is required")
	}
	apiBase, err := parseOrigin(apiOrigin)
	if err != nil {
		return nil, fmt.Errorf("invalid API origin: %w", err)
	}
	uploadBase, err := parseOrigin(uploadOrigin)
	if err != nil {
		return nil, fmt.Errorf("invalid upload origin: %w", err)
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirect rejected")
	}
	if clientCopy.Timeout <= 0 || clientCopy.Timeout > 30*time.Second {
		clientCopy.Timeout = 30 * time.Second
	}
	return &service{client: &clientCopy, apiBase: apiBase, uploadBase: uploadBase}, nil
}

func parseOrigin(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("origin must be an absolute HTTP URL")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("unsupported URL scheme")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed, nil
}

func (s *service) apiJSON(ctx context.Context, token, method, path string, query url.Values, input any, statuses ...int) (response, error) {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return response{}, errors.New("encode GitHub request")
		}
		if len(encoded) > maxRequestJSON {
			return response{}, errors.New("GitHub request body exceeds the safety bound")
		}
		body = bytes.NewReader(encoded)
	}
	return s.request(ctx, token, method, s.apiBase, path, query, body, "application/json", statuses...)
}

func (s *service) upload(ctx context.Context, token, path string, query url.Values, data []byte) (response, error) {
	return s.request(ctx, token, http.MethodPost, s.uploadBase, path, query, bytes.NewReader(data), "application/octet-stream", http.StatusCreated)
}

func (s *service) request(ctx context.Context, token, method string, base *url.URL, path string, query url.Values, body io.Reader, contentType string, statuses ...int) (response, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") || hasTraversalSegment(path) {
		return response{}, errors.New("invalid GitHub API path")
	}
	target := *base
	target.Path = strings.TrimSuffix(base.Path, "/") + path
	target.RawPath = ""
	target.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return response{}, errors.New("create GitHub request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	request.Header.Set("User-Agent", "n2u-releaseguard")
	if body != nil {
		request.Header.Set("Content-Type", contentType)
	}

	httpResponse, err := s.client.Do(request)
	if err != nil {
		return response{}, errors.New("GitHub request failed")
	}
	defer httpResponse.Body.Close()
	if httpResponse.ContentLength > maxResponseBody {
		return response{}, errors.New("GitHub response exceeds the safety bound")
	}
	payload, err := io.ReadAll(io.LimitReader(httpResponse.Body, maxResponseBody+1))
	if err != nil {
		return response{}, errors.New("read GitHub response")
	}
	if len(payload) > maxResponseBody {
		return response{}, errors.New("GitHub response exceeds the safety bound")
	}
	allowed := false
	for _, status := range statuses {
		if httpResponse.StatusCode == status {
			allowed = true
			break
		}
	}
	if !allowed {
		return response{}, fmt.Errorf("GitHub %s %s returned HTTP %d", method, path, httpResponse.StatusCode)
	}
	return response{status: httpResponse.StatusCode, header: httpResponse.Header.Clone(), body: payload}, nil
}

func hasTraversalSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func decodeJSON(payload []byte, destination any) error {
	if len(payload) == 0 {
		return errors.New("GitHub returned an empty JSON response")
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return errors.New("GitHub returned malformed JSON")
	}
	if err := json.Unmarshal(payload, destination); err != nil {
		return errors.New("GitHub returned malformed JSON")
	}
	return nil
}

// rejectDuplicateJSONKeys avoids ambiguous security decisions caused by the
// encoding/json last-key-wins behavior.
func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate object key")
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("malformed object")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("malformed array")
			}
		default:
			return errors.New("unexpected delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}
