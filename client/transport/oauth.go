package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuthConfig holds the OAuth configuration for the client
type OAuthConfig struct {
	// ClientID is the OAuth client ID
	ClientID string
	// ClientSecret is the OAuth client secret (for confidential clients)
	ClientSecret string
	// RedirectURI is the redirect URI for the OAuth flow
	RedirectURI string
	// Scopes is the list of OAuth scopes to request
	Scopes []string
	// TokenStore is the storage for OAuth tokens
	TokenStore TokenStore
	// AuthServerMetadataURL is the URL to the OAuth server metadata
	// If empty, the client will attempt to discover it from the base URL
	AuthServerMetadataURL string
	// PKCEEnabled enables PKCE for the OAuth flow (recommended for public clients)
	PKCEEnabled bool
	// MCPResourceEndpoint is the endpoint to probe for resource discovery (default: /mcp/)
	MCPResourceEndpoint string
}

// TokenStore is an interface for storing and retrieving OAuth tokens
type TokenStore interface {
	// GetToken returns the current token
	GetToken() (*Token, error)
	// SaveToken saves a token
	SaveToken(token *Token) error
}

// Token represents an OAuth token
type Token struct {
	// AccessToken is the OAuth access token
	AccessToken string `json:"access_token"`
	// TokenType is the type of token (usually "Bearer")
	TokenType string `json:"token_type"`
	// RefreshToken is the OAuth refresh token
	RefreshToken string `json:"refresh_token,omitempty"`
	// ExpiresIn is the number of seconds until the token expires
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// Scope is the scope of the token
	Scope string `json:"scope,omitempty"`
	// ExpiresAt is the time when the token expires
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// IsExpired returns true if the token is expired
func (t *Token) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(t.ExpiresAt)
}

// MemoryTokenStore is a simple in-memory token store
type MemoryTokenStore struct {
	token *Token
	mu    sync.RWMutex
}

// NewMemoryTokenStore creates a new in-memory token store
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{}
}

// GetToken returns the current token
func (s *MemoryTokenStore) GetToken() (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.token == nil {
		return nil, errors.New("no token available")
	}
	return s.token, nil
}

// SaveToken saves a token
func (s *MemoryTokenStore) SaveToken(token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
	return nil
}

// AuthServerMetadata represents the OAuth 2.0 Authorization Server Metadata
type AuthServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	JwksURI                           string   `json:"jwks_uri,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// OAuthHandler handles OAuth authentication for HTTP requests
type OAuthHandler struct {
	config           OAuthConfig
	httpClient       *http.Client
	serverMetadata   *AuthServerMetadata
	metadataFetchErr error
	metadataOnce     sync.Once
	baseURL          string
	expectedState    string // Expected state value for CSRF protection
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(config OAuthConfig) *OAuthHandler {
	if config.TokenStore == nil {
		config.TokenStore = NewMemoryTokenStore()
	}

	return &OAuthHandler{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// GetAuthorizationHeader returns the Authorization header value for a request
func (h *OAuthHandler) GetAuthorizationHeader(ctx context.Context) (string, error) {

	token, err := h.getValidToken(ctx)
	if err != nil {
		return "", err
	}

	// Some auth implementations are strict about token type
	tokenType := token.TokenType
	if tokenType == "bearer" {
		tokenType = "Bearer"
	}

	authHeader := fmt.Sprintf("%s %s", tokenType, token.AccessToken)

	return authHeader, nil
}

// getValidToken returns a valid token, refreshing if necessary
func (h *OAuthHandler) getValidToken(ctx context.Context) (*Token, error) {

	token, err := h.config.TokenStore.GetToken()
	if err != nil {
		return nil, ErrOAuthAuthorizationRequired
	}

	if !token.IsExpired() && token.AccessToken != "" {
		return token, nil
	}

	// If we have a refresh token, try to use it
	if token.RefreshToken != "" {
		newToken, err := h.refreshToken(ctx, token.RefreshToken)
		if err == nil {
			return newToken, nil
		}
		// If refresh fails, continue to authorization flow
	}

	return nil, ErrOAuthAuthorizationRequired
}

// refreshToken refreshes an OAuth token
func (h *OAuthHandler) refreshToken(ctx context.Context, refreshToken string) (*Token, error) {

	metadata, err := h.getServerMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get server metadata: %w", err)
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", h.config.ClientID)
	if h.config.ClientSecret != "" {
		data.Set("client_secret", h.config.ClientSecret)
	} else {
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		metadata.TokenEndpoint,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send refresh token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, extractOAuthError(body, resp.StatusCode, "refresh token request failed")
	}

	var tokenResp Token
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Set expiration time
	if tokenResp.ExpiresIn > 0 {
		tokenResp.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	// If no new refresh token is provided, keep the old one
	oldToken, _ := h.config.TokenStore.GetToken()
	if tokenResp.RefreshToken == "" && oldToken != nil {
		tokenResp.RefreshToken = oldToken.RefreshToken
	}

	// Save the token
	if err := h.config.TokenStore.SaveToken(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to save token: %w", err)
	}

	return &tokenResp, nil
}

// RefreshToken is a public wrapper for refreshToken
func (h *OAuthHandler) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	return h.refreshToken(ctx, refreshToken)
}

// GetClientID returns the client ID
func (h *OAuthHandler) GetClientID() string {
	return h.config.ClientID
}

// extractOAuthError attempts to parse an OAuth error response from the response body
func extractOAuthError(body []byte, statusCode int, context string) error {
	// Try to parse the error as an OAuth error response
	var oauthErr OAuthError
	if err := json.Unmarshal(body, &oauthErr); err == nil && oauthErr.ErrorCode != "" {
		return fmt.Errorf("%s: %w", context, oauthErr)
	}

	// If not a valid OAuth error, return the raw response
	return fmt.Errorf("%s with status %d: %s", context, statusCode, body)
}

// GetClientSecret returns the client secret
func (h *OAuthHandler) GetClientSecret() string {
	return h.config.ClientSecret
}

// SetBaseURL sets the base URL for the API server
func (h *OAuthHandler) SetBaseURL(baseURL string) {
	h.baseURL = baseURL
}

// GetExpectedState returns the expected state value (for testing purposes)
func (h *OAuthHandler) GetExpectedState() string {
	return h.expectedState
}

// OAuthError represents a standard OAuth 2.0 error response
type OAuthError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// Error implements the error interface
func (e OAuthError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("OAuth error: %s - %s", e.ErrorCode, e.ErrorDescription)
	}
	return fmt.Sprintf("OAuth error: %s", e.ErrorCode)
}

// OAuthProtectedResourceMetadata represents the RFC 9728 resource metadata
type OAuthProtectedResourceMetadata struct {
	ResourceName         string   `json:"resource_name,omitempty"`
	Resource             string   `json:"resource,omitempty"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// parseAuthHeaderParams parses a WWW-Authenticate header into a map
func parseAuthHeaderParams(header string) map[string]string {
	params := map[string]string{}
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			val := strings.Trim(kv[1], `"`)
			params[key] = val
		}
	}
	return params
}

// getServerMetadata fetches the OAuth server metadata
func (h *OAuthHandler) getServerMetadata(ctx context.Context) (*AuthServerMetadata, error) {
	h.metadataOnce.Do(func() {

		// If AuthServerMetadataURL is explicitly provided, use it directly
		if h.config.AuthServerMetadataURL != "" {
			h.fetchMetadataFromURL(ctx, h.config.AuthServerMetadataURL)
			return
		}

		// 1. Make unauthenticated MCP request to discover resource_metadata (https://datatracker.ietf.org/doc/html/rfc9728)
		mcpEndpoint := h.baseURL + "/mcp/"
		if h.config.MCPResourceEndpoint != "" {
			mcpEndpoint = h.baseURL + h.config.MCPResourceEndpoint
		}
		resourceMetadataURL, err := h.discoverResourceMetadataFrom401(ctx, mcpEndpoint)
		if err != nil {
			h.metadataFetchErr = fmt.Errorf("failed to discover resource_metadata from 401: %w", err)
			return
		}

		// 2. Fetch and parse resource metadata from discovered URL
		resourceMetadata, err := h.fetchResourceMetadata(ctx, resourceMetadataURL)
		if err != nil {
			h.metadataFetchErr = fmt.Errorf("failed to fetch resource metadata: %w", err)
			return
		}

		if len(resourceMetadata.ScopesSupported) > 0 {
			// Save to serverMetadata for downstream use
			if h.serverMetadata == nil {
				h.serverMetadata = &AuthServerMetadata{}
			}
			h.serverMetadata.ScopesSupported = resourceMetadata.ScopesSupported
		}

		if len(resourceMetadata.AuthorizationServers) > 0 {
			authServerURL := resourceMetadata.AuthorizationServers[0]

			// Try OpenID Connect discovery first
			h.fetchMetadataFromURL(ctx, authServerURL+"/.well-known/openid-configuration")
			if h.serverMetadata != nil && h.serverMetadata.AuthorizationEndpoint != "" {
				return
			}

			// If OpenID Connect discovery fails, try OAuth Authorization Server Metadata
			h.fetchMetadataFromURL(ctx, authServerURL+"/.well-known/oauth-authorization-server")
			if h.serverMetadata != nil && h.serverMetadata.AuthorizationEndpoint != "" {
				return
			}

			// If both discovery methods fail, use default endpoints based on the authorization server URL
			metadata, err := h.getDefaultEndpoints(authServerURL)
			if err != nil {
				h.metadataFetchErr = fmt.Errorf("failed to get default endpoints: %w", err)
				return
			}
			h.serverMetadata = metadata
			return
		}

		// 4. If no authorization_servers, fallback to legacy fields (for non-RFC9728 servers)
		if h.serverMetadata == nil || h.serverMetadata.AuthorizationEndpoint == "" {
			h.metadataFetchErr = fmt.Errorf("no authorization endpoint in resource metadata and no authorization_servers present")
			return
		}
	})

	if h.metadataFetchErr != nil {
		return nil, h.metadataFetchErr
	}

	return h.serverMetadata, nil
}

// discoverResourceMetadataFrom401 makes an unauthenticated MCP request and extracts resource_metadata from the WWW-Authenticate header on 401
func (h *OAuthHandler) discoverResourceMetadataFrom401(ctx context.Context, mcpEndpoint string) (string, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mcpEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create MCP request: %w", err)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send MCP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
	}

	// Parse WWW-Authenticate header for resource_metadata
	hdr := resp.Header.Get("WWW-Authenticate")
	if hdr == "" {
		return "", fmt.Errorf("no WWW-Authenticate header in 401 response")
	}

	params := parseAuthHeaderParams(hdr)
	resourceMetadata, ok := params["resource_metadata"]
	if !ok || resourceMetadata == "" {
		return "", fmt.Errorf("no resource_metadata in WWW-Authenticate header")
	}
	return resourceMetadata, nil
}

// fetchMetadataFromURL fetches and parses OAuth server metadata from a URL
func (h *OAuthHandler) fetchMetadataFromURL(ctx context.Context, metadataURL string) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		// Don't set metadataFetchErr here - let the caller handle it
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-03-26")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		// Don't set metadataFetchErr here - let the caller handle it
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Don't set metadataFetchErr here - let the caller handle it
		return
	}

	var metadata AuthServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		// Don't set metadataFetchErr here - let the caller handle it
		return
	}

	h.serverMetadata = &metadata
}

// extractBaseURL extracts the base URL from the first request
func (h *OAuthHandler) extractBaseURL() (string, error) {
	// If we have a base URL from a previous request, use it
	if h.baseURL != "" {
		return h.baseURL, nil
	}

	// Otherwise, we need to infer it from the redirect URI
	if h.config.RedirectURI == "" {
		return "", fmt.Errorf("no base URL available and no redirect URI provided")
	}

	// Parse the redirect URI to extract the authority
	parsedURL, err := url.Parse(h.config.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse redirect URI: %w", err)
	}

	// Use the scheme and host from the redirect URI
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	return baseURL, nil
}

// GetServerMetadata is a public wrapper for getServerMetadata
func (h *OAuthHandler) GetServerMetadata(ctx context.Context) (*AuthServerMetadata, error) {
	return h.getServerMetadata(ctx)
}

// getDefaultEndpoints returns default OAuth endpoints based on the base URL
func (h *OAuthHandler) getDefaultEndpoints(baseURL string) (*AuthServerMetadata, error) {

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Use the full path from the baseURL (do not strip it)
	authBaseURL := parsedURL.String()

	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid base URL: missing scheme or host in %q", baseURL)
	}

	return &AuthServerMetadata{
		Issuer:                authBaseURL,
		AuthorizationEndpoint: authBaseURL + "/authorize",
		TokenEndpoint:         authBaseURL + "/token",
		RegistrationEndpoint:  authBaseURL + "/register",
	}, nil
}

// RegisterClient performs dynamic client registration
func (h *OAuthHandler) RegisterClient(ctx context.Context, clientName string) error {
	metadata, err := h.getServerMetadata(ctx)
	if err != nil {
		return fmt.Errorf("failed to get server metadata: %w", err)
	}

	if metadata.RegistrationEndpoint == "" {
		return errors.New("server does not support dynamic client registration")
	}

	// Prepare registration request
	regRequest := map[string]any{
		"client_name":                clientName,
		"redirect_uris":              []string{h.config.RedirectURI},
		"token_endpoint_auth_method": "none", // For public clients
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      strings.Join(h.config.Scopes, " "),
	}

	// Add client_secret if this is a confidential client
	if h.config.ClientSecret != "" {
		regRequest["token_endpoint_auth_method"] = "client_secret_basic"
	}

	reqBody, err := json.Marshal(regRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		metadata.RegistrationEndpoint,
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create registration request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send registration request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return extractOAuthError(body, resp.StatusCode, "registration request failed")
	}

	var regResponse struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&regResponse); err != nil {
		return fmt.Errorf("failed to decode registration response: %w", err)
	}

	// Update the client configuration
	h.config.ClientID = regResponse.ClientID
	if regResponse.ClientSecret != "" {
		h.config.ClientSecret = regResponse.ClientSecret
	}

	return nil
}

// ErrInvalidState is returned when the state parameter doesn't match the expected value
var ErrInvalidState = errors.New("invalid state parameter, possible CSRF attack")

// ProcessAuthorizationResponse processes the authorization response and exchanges the code for a token
func (h *OAuthHandler) ProcessAuthorizationResponse(ctx context.Context, code, state, codeVerifier string) error {
	// Validate the state parameter to prevent CSRF attacks
	if h.expectedState == "" {
		return errors.New("no expected state found, authorization flow may not have been initiated properly")
	}

	if state != h.expectedState {
		return ErrInvalidState
	}

	// Clear the expected state after validation
	defer func() {
		h.expectedState = ""
	}()

	metadata, err := h.getServerMetadata(ctx)
	if err != nil {
		return fmt.Errorf("failed to get server metadata: %w", err)
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", h.config.ClientID)
	data.Set("redirect_uri", h.config.RedirectURI)

	if h.config.ClientSecret != "" {
		data.Set("client_secret", h.config.ClientSecret)
	}

	if h.config.PKCEEnabled && codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		metadata.TokenEndpoint,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return extractOAuthError(body, resp.StatusCode, "token request failed")
	}

	var tokenResp Token
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	// Set expiration time
	if tokenResp.ExpiresIn > 0 {
		tokenResp.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	// Save the token
	if err := h.config.TokenStore.SaveToken(&tokenResp); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}

// GetAuthorizationURL returns the URL for the authorization endpoint
func (h *OAuthHandler) GetAuthorizationURL(ctx context.Context, state, codeChallenge string) (string, error) {
	metadata, err := h.getServerMetadata(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get server metadata: %w", err)
	}

	// Store the state for later validation
	h.expectedState = state

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", h.config.ClientID)
	params.Set("redirect_uri", h.config.RedirectURI)
	params.Set("state", state)

	if len(h.config.Scopes) > 0 {
		params.Set("scope", strings.Join(h.config.Scopes, " "))
	}

	if h.config.PKCEEnabled && codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	return metadata.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// fetchResourceMetadata fetches and parses OAuth protected resource metadata (RFC 9728)
func (h *OAuthHandler) fetchResourceMetadata(ctx context.Context, metadataURL string) (*OAuthProtectedResourceMetadata, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource metadata request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-03-26")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send resource metadata request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("resource metadata request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var metadata OAuthProtectedResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode resource metadata response: %w", err)
	}

	return &metadata, nil
}
