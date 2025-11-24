package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kjanat/gpg-signing-service/client/pkg/api"
)

// Client wraps the auto-generated API client with a cleaner interface.
//
// A Client is safe for concurrent use by multiple goroutines. It maintains
// an internal HTTP connection pool that is shared across requests.
//
// Do not copy a Client after first use.
type Client struct {
	raw     *api.ClientWithResponses
	opts    *Options
	retrier *Retrier
}

// New creates a new GPG Signing Service client.
func New(baseURL string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("baseURL cannot be empty")
	}

	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	// Validate options
	if options.timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}
	if options.maxRetries < 0 {
		return nil, errors.New("maxRetries cannot be negative")
	}
	if options.retryWaitMin >= options.retryWaitMax {
		return nil, errors.New("retryWaitMin must be less than retryWaitMax")
	}

	httpClient := &http.Client{
		Timeout: options.timeout,
	}

	clientOpts := []api.ClientOption{
		api.WithHTTPClient(httpClient),
	}

	if options.authToken != "" {
		// Pre-allocate auth header to avoid allocation on every request
		authHeader := "Bearer " + options.authToken
		clientOpts = append(clientOpts, api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Authorization", authHeader)
			return nil
		}))
	}

	rawClient, err := api.NewClientWithResponses(baseURL, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	return &Client{
		raw:     rawClient,
		opts:    options,
		retrier: newRetrier(options),
	}, nil
}

// Health checks service health.
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	var resp *api.GetHealthResponse
	err := c.retrier.Do(ctx, func() error {
		var execErr error
		resp, execErr = c.raw.GetHealthWithResponse(ctx)
		return execErr
	})
	if err != nil {
		return nil, err
	}

	if resp.JSON200 != nil {
		return &HealthStatus{
			Status:     string(resp.JSON200.Status),
			Version:    resp.JSON200.Version,
			Timestamp:  resp.JSON200.Timestamp,
			KeyStorage: resp.JSON200.Checks.KeyStorage,
			Database:   resp.JSON200.Checks.Database,
		}, nil
	}

	if resp.JSON503 != nil {
		return &HealthStatus{
				Status:     string(resp.JSON503.Status),
				Version:    resp.JSON503.Version,
				Timestamp:  resp.JSON503.Timestamp,
				KeyStorage: resp.JSON503.Checks.KeyStorage,
				Database:   resp.JSON503.Checks.Database,
			}, &ServiceError{
				Code:       ErrCodeDegraded,
				Message:    "service degraded",
				StatusCode: 503,
			}
	}

	return nil, newUnexpectedStatusError(resp.StatusCode())
}

// PublicKey retrieves the public signing key.
// Pass an empty string for keyID to use the default key.
func (c *Client) PublicKey(ctx context.Context, keyID string) (string, error) {
	var keyIDPtr *string
	if keyID != "" {
		keyIDPtr = &keyID
	}

	var resp *api.GetPublicKeyResponse
	err := c.retrier.Do(ctx, func() error {
		var execErr error
		resp, execErr = c.raw.GetPublicKeyWithResponse(ctx, &api.GetPublicKeyParams{
			KeyId: keyIDPtr,
		})
		return execErr
	})
	if err != nil {
		return "", err
	}

	if resp.StatusCode() == 200 {
		publicKey := string(resp.Body)
		if !strings.HasPrefix(publicKey, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
			return "", fmt.Errorf("invalid PGP key format")
		}
		return publicKey, nil
	}

	if resp.JSON404 != nil {
		return "", &ServiceError{
			Code:       string(resp.JSON404.Code),
			Message:    resp.JSON404.Error,
			StatusCode: 404,
		}
	}

	if resp.JSON500 != nil {
		return "", &ServiceError{
			Code:       string(resp.JSON500.Code),
			Message:    resp.JSON500.Error,
			StatusCode: 500,
		}
	}

	return "", newUnexpectedStatusError(resp.StatusCode())
}

// Sign signs commit data and returns the signature.
// Pass an empty string for keyID to use the default key.
func (c *Client) Sign(ctx context.Context, commitData string, keyID string) (*SignResult, error) {
	if commitData == "" {
		return nil, &ValidationError{
			Code:    "INVALID_REQUEST",
			Message: "commitData cannot be empty",
		}
	}

	var keyIDPtr *string
	if keyID != "" {
		keyIDPtr = &keyID
	}

	params := &api.PostSignParams{KeyId: keyIDPtr}

	var resp *api.PostSignResponse
	err := c.retrier.Do(ctx, func() error {
		var execErr error
		resp, execErr = c.raw.PostSignWithBodyWithResponse(ctx, params, "text/plain", strings.NewReader(commitData))
		return execErr
	})
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() == 200 {
		result := &SignResult{
			Signature: string(resp.Body),
		}

		// Extract rate limit headers
		if remaining := resp.HTTPResponse.Header.Get("X-RateLimit-Remaining"); remaining != "" {
			if val, err := strconv.Atoi(remaining); err == nil {
				result.RateLimitRemaining = &val
			}
		}
		if reset := resp.HTTPResponse.Header.Get("X-RateLimit-Reset"); reset != "" {
			if val, err := strconv.ParseInt(reset, 10, 64); err == nil {
				t := time.Unix(val, 0)
				result.RateLimitReset = &t
			}
		}

		return result, nil
	}

	if resp.JSON400 != nil {
		return nil, &ValidationError{
			Code:    string(resp.JSON400.Code),
			Message: resp.JSON400.Error,
		}
	}

	if resp.JSON404 != nil {
		return nil, &ServiceError{
			Code:       string(resp.JSON404.Code),
			Message:    resp.JSON404.Error,
			StatusCode: 404,
		}
	}

	if resp.JSON429 != nil {
		retryAfter := int(resp.JSON429.RetryAfter)
		message := resp.JSON429.Error
		return nil, &RateLimitError{
			Message:    message,
			RetryAfter: time.Duration(retryAfter) * time.Second,
		}
	}

	if resp.JSON500 != nil || resp.JSON503 != nil {
		errResp := resp.JSON500
		statusCode := 500
		if errResp == nil {
			errResp = resp.JSON503
			statusCode = 503
		}
		return nil, &ServiceError{
			Code:       string(errResp.Code),
			Message:    errResp.Error,
			StatusCode: statusCode,
		}
	}

	return nil, newUnexpectedStatusError(resp.StatusCode())
}

// UploadKey uploads a new signing key (admin operation).
func (c *Client) UploadKey(ctx context.Context, keyID string, armoredPrivateKey string) (*KeyInfo, error) {
	if keyID == "" {
		return nil, &ValidationError{
			Code:    "INVALID_REQUEST",
			Message: "keyID cannot be empty",
		}
	}
	if armoredPrivateKey == "" {
		return nil, &ValidationError{
			Code:    "INVALID_REQUEST",
			Message: "armoredPrivateKey cannot be empty",
		}
	}

	body := api.PostAdminKeysJSONRequestBody{
		ArmoredPrivateKey: armoredPrivateKey,
	}

	var resp *api.PostAdminKeysResponse
	err := c.retrier.Do(ctx, func() error {
		var execErr error
		resp, execErr = c.raw.PostAdminKeysWithResponse(ctx, body)
		return execErr
	})
	if err != nil {
		return nil, err
	}

	if resp.JSON201 != nil {
		return &KeyInfo{
			KeyID:       resp.JSON201.KeyId,
			Fingerprint: resp.JSON201.Fingerprint,
		}, nil
	}

	if resp.JSON400 != nil || resp.JSON500 != nil {
		errResp := resp.JSON400
		statusCode := 400
		if errResp == nil {
			errResp = resp.JSON500
			statusCode = 500
		}
		return nil, &ServiceError{
			Code:       string(errResp.Code),
			Message:    errResp.Error,
			StatusCode: statusCode,
		}
	}

	return nil, newUnexpectedStatusError(resp.StatusCode())
}

// ListKeys lists all signing keys (admin operation).
func (c *Client) ListKeys(ctx context.Context) ([]KeyMetadata, error) {
	var resp *api.GetAdminKeysResponse
	err := c.retrier.Do(ctx, func() error {
		var execErr error
		resp, execErr = c.raw.GetAdminKeysWithResponse(ctx)
		return execErr
	})
	if err != nil {
		return nil, err
	}

	if resp.JSON200 != nil {
		keys := make([]KeyMetadata, len(resp.JSON200.Keys))
		for i, k := range resp.JSON200.Keys {
			keys[i] = KeyMetadata{
				KeyID:       k.KeyId,
				Fingerprint: k.Fingerprint,
				Algorithm:   k.Algorithm,
				CreatedAt:   parseTimestamp(k.CreatedAt),
			}
		}
		return keys, nil
	}

	if resp.JSON500 != nil {
		return nil, &ServiceError{
			Code:       string(resp.JSON500.Code),
			Message:    resp.JSON500.Error,
			StatusCode: 500,
		}
	}

	return nil, newUnexpectedStatusError(resp.StatusCode())
}

// DeleteKey deletes a signing key (admin operation).
func (c *Client) DeleteKey(ctx context.Context, keyID string) error {
	var resp *api.DeleteAdminKeysKeyIdResponse
	err := c.retrier.Do(ctx, func() error {
		var execErr error
		resp, execErr = c.raw.DeleteAdminKeysKeyIdWithResponse(ctx, keyID)
		return execErr
	})
	if err != nil {
		return err
	}

	if resp.JSON200 != nil {
		if resp.JSON200.Deleted {
			return nil
		}
		return &ServiceError{
			Code:       ErrCodeKeyNotFound,
			Message:    fmt.Sprintf("key %s not found", keyID),
			StatusCode: 200,
		}
	}

	if resp.JSON500 != nil {
		return &ServiceError{
			Code:       string(resp.JSON500.Code),
			Message:    resp.JSON500.Error,
			StatusCode: 500,
		}
	}

	return newUnexpectedStatusError(resp.StatusCode())
}

// AuditLogs queries audit logs (admin operation).
func (c *Client) AuditLogs(ctx context.Context, filter AuditFilter) (*AuditResult, error) {
	params := &api.GetAdminAuditParams{}

	if filter.Limit > 0 {
		limit := filter.Limit
		params.Limit = &limit
	}
	if filter.Offset > 0 {
		offset := filter.Offset
		params.Offset = &offset
	}
	if filter.Action != "" {
		params.Action = &filter.Action
	}
	if filter.Subject != "" {
		params.Subject = &filter.Subject
	}
	if !filter.StartDate.IsZero() {
		params.StartDate = &filter.StartDate
	}
	if !filter.EndDate.IsZero() {
		params.EndDate = &filter.EndDate
	}

	var resp *api.GetAdminAuditResponse
	err := c.retrier.Do(ctx, func() error {
		var execErr error
		resp, execErr = c.raw.GetAdminAuditWithResponse(ctx, params)
		return execErr
	})
	if err != nil {
		return nil, err
	}

	if resp.JSON200 != nil {
		logs := make([]AuditLog, len(resp.JSON200.Logs))
		for i, l := range resp.JSON200.Logs {
			var metadata json.RawMessage
			if l.Metadata != nil {
				metadata = json.RawMessage(*l.Metadata)
			}
			var errorCode *string
			if l.ErrorCode != nil {
				code := string(*l.ErrorCode)
				errorCode = &code
			}
			logs[i] = AuditLog{
				ID:        l.Id,
				Timestamp: parseTimestamp(l.Timestamp),
				RequestID: l.RequestId,
				Action:    l.Action,
				Issuer:    l.Issuer,
				Subject:   l.Subject,
				KeyID:     l.KeyId,
				Success:   l.Success,
				ErrorCode: errorCode,
				Metadata:  metadata,
			}
		}
		count := int(resp.JSON200.Count)
		return &AuditResult{
			Logs:  logs,
			Count: count,
		}, nil
	}

	if resp.JSON400 != nil || resp.JSON500 != nil {
		errResp := resp.JSON400
		statusCode := 400
		if errResp == nil {
			errResp = resp.JSON500
			statusCode = 500
		}
		return nil, &ServiceError{
			Code:       string(errResp.Code),
			Message:    errResp.Error,
			StatusCode: statusCode,
		}
	}

	return nil, newUnexpectedStatusError(resp.StatusCode())
}

// AdminPublicKey retrieves the public key via the admin endpoint.
func (c *Client) AdminPublicKey(ctx context.Context, keyID string) (string, error) {
	if keyID == "" {
		return "", &ValidationError{
			Code:    "INVALID_REQUEST",
			Message: "keyID cannot be empty",
		}
	}

	var resp *api.GetAdminKeysKeyIdPublicResponse
	err := c.retrier.Do(ctx, func() error {
		var execErr error
		resp, execErr = c.raw.GetAdminKeysKeyIdPublicWithResponse(ctx, keyID)
		return execErr
	})
	if err != nil {
		return "", err
	}

	if resp.StatusCode() == 200 {
		return string(resp.Body), nil
	}

	if resp.JSON404 != nil {
		return "", &ServiceError{
			Code:       string(resp.JSON404.Code),
			Message:    resp.JSON404.Error,
			StatusCode: 404,
		}
	}

	if resp.JSON500 != nil {
		return "", &ServiceError{
			Code:       string(resp.JSON500.Code),
			Message:    resp.JSON500.Error,
			StatusCode: 500,
		}
	}

	return "", newUnexpectedStatusError(resp.StatusCode())
}
