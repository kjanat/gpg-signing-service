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
	openapiTypes "github.com/oapi-codegen/runtime/types"
)

// Client wraps the auto-generated API client with a cleaner interface.
//
// A Client is safe for concurrent use by multiple goroutines. It maintains
// an internal HTTP connection pool, shared across requests.
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
	if options.retryWaitMin <= 0 {
		return nil, errors.New("retryWaitMin must be positive")
	}
	if options.retryWaitMax <= 0 {
		return nil, errors.New("retryWaitMax must be positive")
	}
	if options.retryWaitMin >= options.retryWaitMax {
		return nil, errors.New("retryWaitMin must be less than retryWaitMax")
	}

	httpClient := &http.Client{
		Timeout: options.timeout,
		// See errorBodyTransport: an error body that will not decode must not
		// take the response down with it inside the generated parser.
		Transport: &errorBodyTransport{base: http.DefaultTransport},
	}

	clientOpts := []api.ClientOption{
		api.WithHTTPClient(httpClient),
	}

	if options.authToken != "" {
		// Pre-allocate auth header to avoid allocation on every request
		authHeader := "Bearer " + options.authToken
		clientOpts = append(clientOpts, api.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
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
//
// For degraded services (503), both HealthStatus and error are returned,
// allowing callers to inspect partial health data while being informed of degradation.
// Callers should check both return values when handling degraded states.
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	// Deliberately not executeWithRetry: this is the one operation whose 503 is
	// an answer rather than a failure. `degraded` is a documented state carrying
	// a body the caller is meant to read, and re-asking three times with backoff
	// would delay that report to learn nothing — a probe wants the current
	// status, not an eventually healthy one. Transport faults still retry: a
	// dial that never connected is not an answer about anything.
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
		// The error is built above the return rather than inline. Two multi-line
		// composite literals in one multi-value return is the single construct
		// gofmt and goimports indent differently, and each reverts the other: with
		// both formatters in the chain (.golangci.yml enables gofumpt and
		// goimports) `task format` rewrote this file on every run and any editor
		// running gofmt put it straight back.
		degraded := &ServiceError{
			Code:       ErrCodeDegraded,
			Message:    "service degraded",
			StatusCode: 503,
			// Envelope-less by construction: HealthResponse declares no requestId,
			// so the echoed header is not a fallback here but the only source
			// there is. Left off, the one 503 a caller is told to report — "the
			// service says it is degraded" — arrived with nothing to correlate it
			// against, which is the same hole the mapped statuses just closed.
			RequestID: requestIDFrom("", resp.HTTPResponse.Header),
		}
		return &HealthStatus{
			Status:     string(resp.JSON503.Status),
			Version:    resp.JSON503.Version,
			Timestamp:  resp.JSON503.Timestamp,
			KeyStorage: resp.JSON503.Checks.KeyStorage,
			Database:   resp.JSON503.Checks.Database,
		}, degraded
	}

	return nil, newStatusError(resp.StatusCode(), resp.Body, resp.HTTPResponse.Header)
}

// PublicKey retrieves the public signing key.
// Pass an empty string for keyID to use the default key.
func (c *Client) PublicKey(ctx context.Context, keyID string) (string, error) {
	var keyIDPtr *string
	if keyID != "" {
		keyIDPtr = &keyID
	}

	resp, err := executeWithRetry(ctx, c.retrier, func(ctx context.Context) (*api.GetPublicKeyResponse, error) {
		return c.raw.GetPublicKeyWithResponse(ctx, &api.GetPublicKeyParams{
			KeyId: keyIDPtr,
		})
	})
	if err != nil {
		return "", err
	}

	if resp.StatusCode() == 200 {
		if len(resp.Body) == 0 {
			return "", fmt.Errorf("empty response body")
		}
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
			RequestID:  requestIDFrom(envelopeRequestID(resp.JSON404), resp.HTTPResponse.Header),
		}
	}

	if resp.JSON500 != nil {
		return "", &ServiceError{
			Code:       string(resp.JSON500.Code),
			Message:    resp.JSON500.Error,
			StatusCode: 500,
			RequestID:  requestIDFrom(envelopeRequestID(resp.JSON500), resp.HTTPResponse.Header),
		}
	}

	return "", newStatusError(resp.StatusCode(), resp.Body, resp.HTTPResponse.Header)
}

// Sign signs commit data and returns the signature.
// Pass an empty string for keyID to use the default key.
func (c *Client) Sign(ctx context.Context, commitData string, keyID string) (*SignResult, error) {
	if err := validateSignInput(commitData); err != nil {
		return nil, err
	}

	params := buildSignParams(keyID)

	resp, err := executeWithRetry(ctx, c.retrier, func(ctx context.Context) (*api.PostSignResponse, error) {
		// The reader is built per attempt on purpose: one hoisted out of the
		// closure is drained by the first request and every retry after it
		// POSTs an empty body.
		return c.raw.PostSignWithBodyWithResponse(ctx, params, "text/plain", strings.NewReader(commitData))
	})
	if err != nil {
		return nil, err
	}

	if result, ok := parseSignSuccess(resp); ok {
		return result, nil
	}

	if mappedErr := mapSignResponseError(resp); mappedErr != nil {
		return nil, mappedErr
	}

	return nil, newStatusError(resp.StatusCode(), resp.Body, resp.HTTPResponse.Header)
}

// UploadKey uploads a new signing key (admin operation).
func (c *Client) UploadKey(ctx context.Context, keyID string, armoredPrivateKey string) (*KeyInfo, error) {
	if keyID == "" {
		return nil, &ValidationError{
			Code:    ErrCodeInvalidRequest,
			Message: "keyID cannot be empty",
		}
	}
	if armoredPrivateKey == "" {
		return nil, &ValidationError{
			Code:    ErrCodeInvalidRequest,
			Message: "armoredPrivateKey cannot be empty",
		}
	}

	body := api.PostAdminKeysJSONRequestBody{
		ArmoredPrivateKey: armoredPrivateKey,
		KeyId:             keyID,
	}

	resp, err := executeWithRetry(ctx, c.retrier, func(ctx context.Context) (*api.PostAdminKeysResponse, error) {
		return c.raw.PostAdminKeysWithResponse(ctx, body)
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

	if resp.JSON401 != nil {
		return nil, newAuthErrorFromResponse(resp.JSON401, resp.HTTPResponse.Header)
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
			RequestID:  requestIDFrom(envelopeRequestID(errResp), resp.HTTPResponse.Header),
		}
	}

	return nil, newStatusError(resp.StatusCode(), resp.Body, resp.HTTPResponse.Header)
}

// ListKeys lists all signing keys (admin operation).
func (c *Client) ListKeys(ctx context.Context) ([]KeyMetadata, error) {
	resp, err := executeWithRetry(ctx, c.retrier, func(ctx context.Context) (*api.GetAdminKeysResponse, error) {
		return c.raw.GetAdminKeysWithResponse(ctx)
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

	if resp.JSON401 != nil {
		return nil, newAuthErrorFromResponse(resp.JSON401, resp.HTTPResponse.Header)
	}

	if resp.JSON500 != nil {
		return nil, &ServiceError{
			Code:       string(resp.JSON500.Code),
			Message:    resp.JSON500.Error,
			StatusCode: 500,
			RequestID:  requestIDFrom(envelopeRequestID(resp.JSON500), resp.HTTPResponse.Header),
		}
	}

	return nil, newStatusError(resp.StatusCode(), resp.Body, resp.HTTPResponse.Header)
}

// DeleteKey deletes a signing key (admin operation).
//
// Returns KEY_NOT_FOUND error (with StatusCode 200) when the API indicates
// the key was not deleted (deleted=false), typically meaning the key doesn't exist.
// Callers should use IsKeyNotFound() to detect this case.
//
// That report is only trustworthy on the first attempt. `deleted` describes
// the attempt that answered, not the call — see the attempts check below.
func (c *Client) DeleteKey(ctx context.Context, keyID string) error {
	attempts := 0
	resp, err := executeWithRetry(ctx, c.retrier, func(ctx context.Context) (*api.DeleteAdminKeysKeyIdResponse, error) {
		attempts++
		return c.raw.DeleteAdminKeysKeyIdWithResponse(ctx, keyID)
	})
	if err != nil {
		return err
	}

	if resp.JSON200 != nil {
		// Sign and UploadKey converge under a retry because their state does;
		// this one's state converges but its *answer* does not. The handler
		// reports whether the key was there when this attempt ran, so a delete
		// that committed and then lost its response — a 500 raised by the audit
		// write that follows it, a connection dropped mid-body — is answered
		// `deleted:false` by the next attempt, and mapped to KEY_NOT_FOUND for
		// a key this call removed a moment earlier. The CLI prints
		// {"deleted":false} and exits 0 for work it did do.
		//
		// Once an attempt has already run, "it was not there" and "I removed it
		// a moment ago" are the same response and the postcondition holds
		// either way, so the call succeeds. Nothing changes before a retry: the
		// first attempt's `deleted:false` is still a not-found, which is the
		// only reading a single round trip supports.
		if resp.JSON200.Deleted || attempts > 1 {
			return nil
		}
		return &ServiceError{
			Code:       ErrCodeKeyNotFound,
			Message:    fmt.Sprintf("key %s not found", keyID),
			StatusCode: 200,
			// Synthesized from a 200 whose body says nothing happened, so there is
			// no error envelope to read and the echoed header is the only source.
			// It is still a real response with a real id behind it, and "delete
			// reported the key was not there" is a report an operator files.
			RequestID: requestIDFrom("", resp.HTTPResponse.Header),
		}
	}

	if resp.JSON401 != nil {
		return newAuthErrorFromResponse(resp.JSON401, resp.HTTPResponse.Header)
	}

	if resp.JSON500 != nil {
		return &ServiceError{
			Code:       string(resp.JSON500.Code),
			Message:    resp.JSON500.Error,
			StatusCode: 500,
			RequestID:  requestIDFrom(envelopeRequestID(resp.JSON500), resp.HTTPResponse.Header),
		}
	}

	return newStatusError(resp.StatusCode(), resp.Body, resp.HTTPResponse.Header)
}

// AuditLogs queries audit logs (admin operation).
func (c *Client) AuditLogs(ctx context.Context, filter AuditFilter) (*AuditResult, error) {
	params := buildAuditParams(filter)

	resp, err := executeWithRetry(ctx, c.retrier, func(ctx context.Context) (*api.GetAdminAuditResponse, error) {
		return c.raw.GetAdminAuditWithResponse(ctx, params)
	})
	if err != nil {
		return nil, err
	}

	if result, ok := parseAuditSuccess(resp); ok {
		return result, nil
	}

	if mappedErr := mapAuditResponseError(resp); mappedErr != nil {
		return nil, mappedErr
	}

	return nil, newStatusError(resp.StatusCode(), resp.Body, resp.HTTPResponse.Header)
}

// AdminPublicKey retrieves the public key via the admin endpoint.
func (c *Client) AdminPublicKey(ctx context.Context, keyID string) (string, error) {
	if keyID == "" {
		return "", &ValidationError{
			Code:    ErrCodeInvalidRequest,
			Message: "keyID cannot be empty",
		}
	}

	resp, err := executeWithRetry(ctx, c.retrier, func(ctx context.Context) (*api.GetAdminKeysKeyIdPublicResponse, error) {
		return c.raw.GetAdminKeysKeyIdPublicWithResponse(ctx, keyID)
	})
	if err != nil {
		return "", err
	}

	if resp.StatusCode() == 200 {
		return string(resp.Body), nil
	}

	if resp.JSON401 != nil {
		return "", newAuthErrorFromResponse(resp.JSON401, resp.HTTPResponse.Header)
	}

	if resp.JSON404 != nil {
		return "", &ServiceError{
			Code:       string(resp.JSON404.Code),
			Message:    resp.JSON404.Error,
			StatusCode: 404,
			RequestID:  requestIDFrom(envelopeRequestID(resp.JSON404), resp.HTTPResponse.Header),
		}
	}

	if resp.JSON500 != nil {
		return "", &ServiceError{
			Code:       string(resp.JSON500.Code),
			Message:    resp.JSON500.Error,
			StatusCode: 500,
			RequestID:  requestIDFrom(envelopeRequestID(resp.JSON500), resp.HTTPResponse.Header),
		}
	}

	return "", newStatusError(resp.StatusCode(), resp.Body, resp.HTTPResponse.Header)
}

func mapAuditResponseError(resp *api.GetAdminAuditResponse) error {
	if resp.JSON401 != nil {
		return newAuthErrorFromResponse(resp.JSON401, resp.HTTPResponse.Header)
	}

	if resp.JSON400 == nil && resp.JSON500 == nil {
		return nil
	}

	errResp := resp.JSON400
	statusCode := 400
	if errResp == nil {
		errResp = resp.JSON500
		statusCode = 500
	}

	// Envelope first, echoed header second, the same two sources every other
	// mapped status here reads. This branch used to read the envelope alone,
	// which is the shape the typed sign 403 also had: correct against this
	// service, and empty against a deployment older than the release that put
	// requestId in error bodies, or any intermediary that answers with the
	// envelope's shape and none of its optional fields.
	return &ServiceError{
		Code:       string(errResp.Code),
		Message:    errResp.Error,
		StatusCode: statusCode,
		RequestID:  requestIDFrom(envelopeRequestID(errResp), resp.HTTPResponse.Header),
	}
}

func parseAuditSuccess(resp *api.GetAdminAuditResponse) (*AuditResult, bool) {
	if resp.JSON200 == nil {
		return nil, false
	}

	return &AuditResult{
		Logs:  mapAuditLogs(resp.JSON200),
		Count: resp.JSON200.Count,
	}, true
}

func mapAuditLogs(response *api.AuditLogsResponse) []AuditLog {
	logs := make([]AuditLog, len(response.Logs))
	for i, entry := range response.Logs {
		logs[i] = mapAuditLog(entry)
	}
	return logs
}

// revive:disable:var-naming // keep field names aligned with API schema and JSON tags
func mapAuditLog(entry struct {
	Action    api.AuditAction   `json:"action"`
	ErrorCode *api.ErrorCode    `json:"errorCode,omitempty"`
	Id        openapiTypes.UUID `json:"id"`
	Issuer    string            `json:"issuer"`
	KeyId     string            `json:"keyId"`
	Metadata  *string           `json:"metadata,omitempty"`
	RequestId openapiTypes.UUID `json:"requestId"`
	Subject   string            `json:"subject"`
	Success   bool              `json:"success"`
	Timestamp time.Time         `json:"timestamp"`
},
) AuditLog {
	var metadata json.RawMessage
	if entry.Metadata != nil {
		metadata = json.RawMessage(*entry.Metadata)
	}

	var errorCode *string
	if entry.ErrorCode != nil {
		code := string(*entry.ErrorCode)
		errorCode = &code
	}

	return AuditLog{
		ID:        entry.Id.String(),
		Timestamp: entry.Timestamp,
		RequestID: entry.RequestId.String(),
		Action:    string(entry.Action),
		Issuer:    entry.Issuer,
		Subject:   entry.Subject,
		KeyID:     entry.KeyId,
		Success:   entry.Success,
		ErrorCode: errorCode,
		Metadata:  metadata,
	}
}

// revive:enable:var-naming

func buildAuditParams(filter AuditFilter) *api.GetAdminAuditParams {
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

	return params
}

func mapSignResponseError(resp *api.PostSignResponse) error {
	switch {
	case resp.JSON400 != nil:
		return &ValidationError{
			Guidance:  guidanceFromResponse(resp.JSON400),
			Code:      string(resp.JSON400.Code),
			Message:   resp.JSON400.Error,
			RequestID: requestIDFrom(envelopeRequestID(resp.JSON400), resp.HTTPResponse.Header),
		}
	case resp.JSON401 != nil:
		// The refusal a first-time caller actually hits: an unregistered subject
		// answers `Subject is not trusted for signing`, and no amount of correct
		// issuer or audience configuration changes it. Carrying the code through
		// is what separates it from a missing header or an unlisted issuer.
		return newAuthErrorFromResponse(resp.JSON401, resp.HTTPResponse.Header)
	case resp.JSON403 != nil:
		// Without this case the 403 falls through to a bare "unexpected status
		// code", discarding both the server's message and the KEY_NOT_ALLOWED code
		// that exists so a scope denial is distinguishable from any other refusal.
		//
		// The id comes through requestIDFrom, as it does on the 400 above: the
		// envelope is preferred and is what this service sends, and the echoed
		// X-Request-ID header is the fallback that covers a deployment older than
		// the release that put requestId in error bodies. Reading the envelope
		// alone dropped the id on exactly the responses an operator is most likely
		// to open a ticket about.
		return &ServiceError{
			Guidance:   guidanceFromResponse(resp.JSON403),
			Code:       string(resp.JSON403.Code),
			Message:    resp.JSON403.Error,
			StatusCode: 403,
			RequestID:  requestIDFrom(envelopeRequestID(resp.JSON403), resp.HTTPResponse.Header),
		}
	case resp.JSON404 != nil:
		// Same two sources as the 403, and previously neither: a KEY_NOT_FOUND
		// reached the caller with no id at all, typed or echoed.
		return &ServiceError{
			Guidance:   guidanceFromResponse(resp.JSON404),
			Code:       string(resp.JSON404.Code),
			Message:    resp.JSON404.Error,
			StatusCode: 404,
			RequestID:  requestIDFrom(envelopeRequestID(resp.JSON404), resp.HTTPResponse.Header),
		}
	case resp.JSON429 != nil:
		// Through the shared constructor rather than inline: this is the declared
		// path, and it had neither fallback the undeclared one grew. A 429 that
		// decodes into the typed body without filling it — an edge throttle's own
		// JSON, which is the only responder that reaches here without the
		// service's envelope — printed as a bare "rate limited: " and dropped the
		// Retry-After header sitting beside it.
		// No envelope id to prefer: RateLimitErrorSchema declares no
		// `requestId`, so the echoed header is the only source there is. Its
		// `hint` and `docs` are spelled as they are everywhere else, so the
		// guidance comes off the typed body directly.
		return newRateLimitError(
			resp.JSON429.Error,
			resp.JSON429.RetryAfter,
			"",
			Guidance{Hint: deref(resp.JSON429.Hint), Docs: deref(resp.JSON429.Docs)},
			resp.HTTPResponse.Header,
		)
	case resp.JSON500 != nil || resp.JSON503 != nil:
		return mapServerError(resp)
	default:
		return nil
	}
}

func parseSignSuccess(resp *api.PostSignResponse) (*SignResult, bool) {
	if resp.StatusCode() != 200 {
		return nil, false
	}

	signature := string(resp.Body)
	if !strings.HasPrefix(signature, "-----BEGIN PGP SIGNATURE-----") {
		return nil, false
	}

	result := &SignResult{
		Signature: signature,
	}
	parseRateLimitHeaders(resp, result)

	return result, true
}

func mapServerError(resp *api.PostSignResponse) *ServiceError {
	errResp := resp.JSON500
	statusCode := 500
	if errResp == nil {
		errResp = resp.JSON503
		statusCode = 503
	}

	return &ServiceError{
		Guidance:   guidanceFromResponse(errResp),
		Code:       string(errResp.Code),
		Message:    errResp.Error,
		StatusCode: statusCode,
		// Through requestIDFrom rather than off the envelope alone, which is how
		// every other constructor here reads it. The envelope is preferred and is
		// what this service sends; the echoed X-Request-ID header is the fallback,
		// and it is the only source for the responder this branch also has to
		// handle — a 5xx that decodes into the typed body without filling it, or a
		// deployment older than the release that put requestId in that envelope.
		// Dropping it there loses the one value docs/troubleshooting.md asks an
		// operator to quote, on the status where they are most likely to need it.
		RequestID: requestIDFrom(envelopeRequestID(errResp), resp.HTTPResponse.Header),
		// A SERVICE_DEGRADED 503 says how long to wait, and this is the only place
		// the typed path could pick it up: ErrorResponse declares no retryAfter
		// field, so the header is the whole source.
		RetryAfter: retryAfterFrom(0, resp.HTTPResponse.Header),
	}
}

func parseRateLimitHeaders(resp *api.PostSignResponse, result *SignResult) {
	remaining := resp.HTTPResponse.Header.Get("X-RateLimit-Remaining")
	if remaining != "" {
		if val, err := strconv.Atoi(remaining); err == nil {
			result.RateLimitRemaining = &val
		}
	}

	reset := resp.HTTPResponse.Header.Get("X-RateLimit-Reset")
	if reset != "" {
		if val, err := strconv.ParseInt(reset, 10, 64); err == nil {
			t := time.Unix(val, 0)
			result.RateLimitReset = &t
		}
	}
}

func buildSignParams(keyID string) *api.PostSignParams {
	var keyIDPtr *string
	if keyID != "" {
		keyIDPtr = &keyID
	}
	return &api.PostSignParams{KeyId: keyIDPtr}
}

func validateSignInput(commitData string) error {
	if commitData != "" {
		return nil
	}
	return &ValidationError{
		Code:    ErrCodeInvalidRequest,
		Message: "commitData cannot be empty",
	}
}
