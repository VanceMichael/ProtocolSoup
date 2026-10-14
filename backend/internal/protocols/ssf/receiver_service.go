package ssf

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ReceiverService is a standalone SSF receiver that runs on a separate port
type ReceiverService struct {
	port           int
	transmitterURL string
	bearerToken    string

	// JWKS cache
	jwksCache *JWKSCache

	// Durable SET processing ownership/progress/outcome (RFC 8417 §2.2).
	// When set, jti replay protection and side-effect resume live in SQLite and
	// survive ClearLogs and ReceiverService rebuilds. ownerID identifies this
	// instance so a 'processing' row left by a rebuilt service is resumable while
	// a genuinely concurrent delivery to this instance is rejected as busy.
	storage    *Storage
	ownerID    string
	inflight   map[string]int
	inflightMu sync.Mutex

	// In-memory JTI replay fallback used only when no Storage is attached.
	seenJTIs   map[string]time.Time
	seenJTIsMu sync.RWMutex

	// Event and action logs
	receivedEvents  []ReceivedEvent
	responseActions []ResponseAction
	eventsMu        sync.RWMutex
	actionsMu       sync.RWMutex

	// Callback to execute real actions
	actionExecutor ActionExecutor
	glass          *glassBox

	federationURL   string
	federationToken string
	federationHTTP  *http.Client

	// Event broadcast channels
	eventListeners []chan<- ReceiverEvent
	listenerMu     sync.RWMutex

	// HTTP server
	server *http.Server
}

// ActionExecutor interface for executing real response actions
type ActionExecutor interface {
	RevokeUserSessions(ctx context.Context, email string) error
	DisableUser(ctx context.Context, email string) error
	EnableUser(ctx context.Context, email string) error
	ForcePasswordReset(ctx context.Context, email string) error
	InvalidateTokens(ctx context.Context, email string) error
	// Session-aware methods for isolated sandbox
	RevokeUserSessionsForSession(ctx context.Context, sessionID, email string) error
	DisableUserForSession(ctx context.Context, sessionID, email string) error
	EnableUserForSession(ctx context.Context, sessionID, email string) error
	ForcePasswordResetForSession(ctx context.Context, sessionID, email string) error
	InvalidateTokensForSession(ctx context.Context, sessionID, email string) error
	ApplyDeviceComplianceForSession(ctx context.Context, sessionID, email, deviceID, status string) error
	InitSessionUserStates(sessionID string)
	GetUserStateForSession(sessionID, email string) (*UserSecurityState, error)
}

// JWKSCache caches public keys fetched from the transmitter
type JWKSCache struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
	jwksURL   string
	mu        sync.RWMutex
}

// NewJWKSCache creates a new JWKS cache
func NewJWKSCache(jwksURL string, ttl time.Duration) *JWKSCache {
	return &JWKSCache{
		keys:    make(map[string]*rsa.PublicKey),
		ttl:     ttl,
		jwksURL: jwksURL,
	}
}

// GetKey retrieves a public key by key ID, fetching from JWKS if needed.
// Returns the key, an optional CapturedHTTPExchange (non-nil when a fresh JWKS fetch occurred),
// and any error.
func (c *JWKSCache) GetKey(keyID string) (*rsa.PublicKey, *CapturedHTTPExchange, error) {
	c.mu.RLock()
	if time.Since(c.fetchedAt) < c.ttl {
		if key, ok := c.keys[keyID]; ok {
			c.mu.RUnlock()
			return key, nil, nil // Cache hit, no HTTP exchange
		}
	}
	c.mu.RUnlock()

	// Fetch fresh JWKS (returns captured HTTP exchange)
	exchange, err := c.refresh()
	if err != nil {
		return nil, exchange, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	key, ok := c.keys[keyID]
	if !ok {
		return nil, exchange, fmt.Errorf("key %s not found in JWKS", keyID)
	}
	return key, exchange, nil
}

// refresh fetches the JWKS from the transmitter and returns a CapturedHTTPExchange
// with the full request/response details for Looking Glass wire capture.
func (c *JWKSCache) refresh() (*CapturedHTTPExchange, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	log.Printf("[SSF Receiver] Fetching JWKS from %s", c.jwksURL)

	startTime := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(c.jwksURL)
	duration := time.Since(startTime)

	// Build captured exchange even on error (partial capture)
	exchange := &CapturedHTTPExchange{
		Label:      "JWKS Fetch",
		Timestamp:  startTime,
		DurationMs: duration.Milliseconds(),
		Request: HTTPCapture{
			Method:  "GET",
			URL:     c.jwksURL,
			Headers: map[string]string{"Accept": "application/json"},
		},
		Response: HTTPCapture{
			Headers: make(map[string]string),
		},
	}

	if err != nil {
		exchange.Response.Body = fmt.Sprintf("error: %v", err)
		return exchange, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	exchange.Response.StatusCode = resp.StatusCode
	for k := range resp.Header {
		exchange.Response.Headers[k] = resp.Header.Get(k)
	}

	if resp.StatusCode != http.StatusOK {
		exchange.Response.Body = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return exchange, fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}

	// Read the full body for capture
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return exchange, fmt.Errorf("failed to read JWKS body: %w", err)
	}
	exchange.Response.Body = string(bodyBytes)

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(bodyBytes, &jwks); err != nil {
		return exchange, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Parse each key
	newKeys := make(map[string]*rsa.PublicKey)
	for _, keyData := range jwks.Keys {
		var keyInfo struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		if err := json.Unmarshal(keyData, &keyInfo); err != nil {
			continue
		}

		if keyInfo.Kty != "RSA" {
			continue
		}

		// Parse RSA public key from JWK
		key, err := parseRSAPublicKeyFromJWK(keyInfo.N, keyInfo.E)
		if err != nil {
			log.Printf("[SSF Receiver] Failed to parse key %s: %v", keyInfo.Kid, err)
			continue
		}

		newKeys[keyInfo.Kid] = key
		log.Printf("[SSF Receiver] Cached key: %s", keyInfo.Kid)
	}

	c.keys = newKeys
	c.fetchedAt = time.Now()

	log.Printf("[SSF Receiver] JWKS cache refreshed with %d keys", len(newKeys))
	return exchange, nil
}

// parseRSAPublicKeyFromJWK parses an RSA public key from JWK components
func parseRSAPublicKeyFromJWK(nBase64, eBase64 string) (*rsa.PublicKey, error) {
	// Decode N (modulus) - base64url encoded
	nBytes, err := base64.RawURLEncoding.DecodeString(nBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}

	// Decode E (exponent) - base64url encoded
	eBytes, err := base64.RawURLEncoding.DecodeString(eBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	// Create public key
	n := new(big.Int).SetBytes(nBytes)

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// NewReceiverService creates a new standalone SSF receiver
func NewReceiverService(port int, transmitterURL, bearerToken string, executor ActionExecutor) *ReceiverService {
	jwksURL := transmitterURL + "/ssf/jwks"

	return &ReceiverService{
		port:            port,
		transmitterURL:  transmitterURL,
		bearerToken:     bearerToken,
		jwksCache:       NewJWKSCache(jwksURL, 5*time.Minute),
		ownerID:         "receiver-" + uuid.NewString(),
		inflight:        make(map[string]int),
		seenJTIs:        make(map[string]time.Time),
		receivedEvents:  make([]ReceivedEvent, 0),
		responseActions: make([]ResponseAction, 0),
		actionExecutor:  executor,
		federationHTTP:  &http.Client{Timeout: 5 * time.Second},
	}
}

// SetStorage attaches the shared SSF SQLite lifecycle. Once attached, SET
// processing ownership, per-step progress and the succeeded/failed outcome are
// persisted there: concurrent deliveries get one executor, partial failures
// resume at the unfinished step, and replay protection survives ClearLogs and
// ReceiverService rebuilds. Must be called before Start.
func (rs *ReceiverService) SetStorage(storage *Storage) {
	rs.storage = storage
}

// inflight is a counter (not a set) so that a concurrent caller that loses the
// claim as busy can release its own marker without clearing the real executor's.
func (rs *ReceiverService) markInflight(jti string) {
	rs.inflightMu.Lock()
	rs.inflight[jti]++
	rs.inflightMu.Unlock()
}

func (rs *ReceiverService) clearInflight(jti string) {
	rs.inflightMu.Lock()
	if rs.inflight[jti] > 1 {
		rs.inflight[jti]--
	} else {
		delete(rs.inflight, jti)
	}
	rs.inflightMu.Unlock()
}

func (rs *ReceiverService) isInflight(jti string) bool {
	rs.inflightMu.Lock()
	defer rs.inflightMu.Unlock()
	return rs.inflight[jti] > 0
}

// SetGlass attaches the Looking Glass bus used for stream-lab visibility.
func (rs *ReceiverService) SetGlass(g *glassBox) {
	rs.glass = g
}

// SetFederationCAEP configures the cross-service HTTP call made after a
// verified CAEP session-revoked SET. The hop is always attempted so Looking
// Glass can show success or a real transport/HTTP failure.
func (rs *ReceiverService) SetFederationCAEP(baseURL, token string) {
	rs.federationURL = strings.TrimRight(baseURL, "/")
	rs.federationToken = token
}

// AddEventListener adds a listener for receiver pipeline events
func (rs *ReceiverService) AddEventListener(ch chan<- ReceiverEvent) {
	rs.listenerMu.Lock()
	defer rs.listenerMu.Unlock()
	rs.eventListeners = append(rs.eventListeners, ch)
}

// RemoveEventListener removes an event listener
func (rs *ReceiverService) RemoveEventListener(ch chan<- ReceiverEvent) {
	rs.listenerMu.Lock()
	defer rs.listenerMu.Unlock()
	for i, listener := range rs.eventListeners {
		if listener == ch {
			rs.eventListeners = append(rs.eventListeners[:i], rs.eventListeners[i+1:]...)
			return
		}
	}
}

// broadcast sends an event to all listeners
func (rs *ReceiverService) broadcast(event ReceiverEvent) {
	rs.glass.emitReceiver(event)
	rs.listenerMu.RLock()
	defer rs.listenerMu.RUnlock()
	for _, listener := range rs.eventListeners {
		select {
		case listener <- event:
		default:
			log.Printf("[SSF] WARNING: receiver event channel full, dropping %s event for session %s", event.Type, event.SessionID)
		}
	}
}

// Start starts the receiver service on its own port
func (rs *ReceiverService) Start() error {
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// SSF Receiver endpoints
	router.Post("/ssf/push", rs.handlePush)
	router.Get("/ssf/status", rs.handleStatus)
	router.Get("/ssf/events", rs.handleGetEvents)
	router.Get("/ssf/actions", rs.handleGetActions)
	router.Delete("/ssf/logs", rs.handleClearLogs)

	rs.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", rs.port),
		Handler: router,
	}

	log.Printf("[SSF Receiver] Starting on port %d", rs.port)
	log.Printf("[SSF Receiver] Transmitter URL: %s", rs.transmitterURL)
	log.Printf("[SSF Receiver] Push endpoint: http://localhost:%d/ssf/push", rs.port)

	return rs.server.ListenAndServe()
}

// Stop gracefully stops the receiver service
func (rs *ReceiverService) Stop(ctx context.Context) error {
	if rs.server != nil {
		return rs.server.Shutdown(ctx)
	}
	return nil
}

// handlePush handles incoming push delivery requests per RFC 8935 §2.
// The request body is the raw compact-serialized SET.
func (rs *ReceiverService) handlePush(w http.ResponseWriter, r *http.Request) {
	// Authenticate the request
	authHeader := r.Header.Get("Authorization")
	if rs.bearerToken != "" {
		expectedAuth := "Bearer " + rs.bearerToken
		if authHeader != expectedAuth {
			log.Printf("[SSF Receiver] Authentication failed: invalid bearer token")
			writeReceiverSSFError(w, http.StatusUnauthorized, "authentication_failed", "Invalid bearer token")
			return
		}
	}

	// RFC 8935 §2: Validate Content-Type
	ct := r.Header.Get("Content-Type")
	if ct != "application/secevent+jwt" {
		log.Printf("[SSF Receiver] Invalid Content-Type: %q (expected application/secevent+jwt)", ct)
		writeReceiverSSFError(w, http.StatusBadRequest, "invalid_request",
			"Content-Type must be application/secevent+jwt")
		return
	}

	// Read raw SET token from request body (RFC 8935 §2)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[SSF Receiver] Failed to read request body: %v", err)
		writeReceiverSSFError(w, http.StatusBadRequest, "invalid_request", "Failed to read request body")
		return
	}

	setToken := string(body)
	if setToken == "" {
		writeReceiverSSFError(w, http.StatusBadRequest, "invalid_request", "Empty SET token")
		return
	}

	// Extract session ID from delivery header (not from the SET itself)
	sessionID := r.Header.Get(lookingGlassSessionHeader)

	log.Printf("[SSF Receiver] Received push delivery: %d bytes (session: %s)", len(body), sessionID)

	status := rs.processSET(r.Context(), setToken, sessionID)

	if status.Status == "failed" {
		errCode := status.Err
		if errCode == "" {
			errCode = "invalid_request"
		}
		// Validation failures answer 400; retryable action/federation/storage
		// failures answer their mapped status so the transmitter redelivers
		// instead of treating the SET as accepted.
		httpStatus := http.StatusBadRequest
		if status.HTTPStatus != 0 {
			httpStatus = status.HTTPStatus
		}
		writeReceiverSSFError(w, httpStatus, errCode, status.Description)
		return
	}

	// RFC 8935 §2.2: 202 Accepted only after every side effect completed durably
	w.WriteHeader(http.StatusAccepted)
}

// ProcessPollResponse handles events retrieved via poll delivery (RFC 8936).
// sessionIDs maps JTI -> session ID (from the stored event metadata, not from the SET).
// A failed status means the SET was NOT confirmed and stays unacknowledged at the
// transmitter, so a later poll redelivers it; success/failure per jti is durable.
func (rs *ReceiverService) ProcessPollResponse(ctx context.Context, sets map[string]string, sessionIDs map[string]string) []SetStatus {
	jtis := make([]string, 0, len(sets))
	for jti := range sets {
		jtis = append(jtis, jti)
	}
	sort.Strings(jtis)

	statuses := make([]SetStatus, 0, len(jtis))
	for _, jti := range jtis {
		statuses = append(statuses, rs.processSET(ctx, sets[jti], sessionIDs[jti]))
	}
	return statuses
}

// processSET processes a single raw SET token.
// The JTI is extracted from the decoded token per RFC 8935 (push delivers a single raw SET).
// sessionID is passed via the X-Looking-Glass-Session delivery header, not from the SET itself.
func (rs *ReceiverService) processSET(ctx context.Context, setToken, sessionID string) SetStatus {
	receivedAt := time.Now()
	jtiPeek, eventURIs, claimsPeek := peekSET(setToken)

	// Broadcast: Event Received — carry the SET, not only token_length
	rs.broadcast(ReceiverEvent{
		Type:      ReceiverEventReceived,
		Timestamp: receivedAt,
		EventID:   jtiPeek,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"delivery_method": "push",
			"token_length":    len(setToken),
			"set_token":       setToken,
			"jti":             jtiPeek,
			"event_uris":      eventURIs,
			"claims":          claimsPeek,
			"session_in_set":  false,
			"session_header":  lookingGlassSessionHeader,
		},
	})

	// Decode the SET header to get the key ID
	token, _, err := new(jwt.Parser).ParseUnverified(setToken, jwt.MapClaims{})
	if err != nil {
		log.Printf("[SSF Receiver] Failed to parse SET header: %v", err)
		return failedSET("invalid_request", "Invalid SET format")
	}

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		log.Printf("[SSF Receiver] SET missing kid header")
		return failedSET("invalid_key", "Missing key ID")
	}

	// Fetch the public key from JWKS (may trigger a real HTTP fetch to the transmitter)
	publicKey, jwksExchange, err := rs.jwksCache.GetKey(keyID)
	if err != nil {
		log.Printf("[SSF Receiver] Failed to get public key: %v", err)
		return failedSET("invalid_key", fmt.Sprintf("Key fetch failed: %v", err))
	}

	// Broadcast JWKS fetch as an HTTP exchange if a real fetch occurred
	if jwksExchange != nil {
		jwksExchange.SessionID = sessionID
		rs.broadcast(ReceiverEvent{
			Type:      ReceiverEventHTTPExchange,
			Timestamp: jwksExchange.Timestamp,
			SessionID: sessionID,
			Data:      jwksExchange,
		})
	}

	// Verify the SET signature
	parsedToken, err := jwt.Parse(setToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		log.Printf("[SSF Receiver] SET signature verification failed: %v", err)
		rs.addReceivedEvent(ReceivedEvent{
			ID:             "",
			ReceivedAt:     receivedAt,
			DeliveryMethod: "push",
			Verified:       false,
			VerifyError:    err.Error(),
		})

		// Broadcast: Verify Failed
		rs.broadcast(ReceiverEvent{
			Type:      ReceiverEventVerifyFailed,
			Timestamp: time.Now(),
			SessionID: sessionID,
			Data: map[string]interface{}{
				"error": err.Error(),
			},
		})

		return failedSET("invalid_key", fmt.Sprintf("Signature verification failed: %v", err))
	}

	log.Printf("[SSF Receiver] SET signature verified successfully")

	// Build structured DecodedSET directly from the verified token's claims
	// instead of re-parsing via DecodeWithoutValidation (which would be a redundant third parse).
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return failedSET("invalid_request", "Invalid claims format")
	}

	// ── RFC 7519 §4.1.1: Validate issuer ──────────────────────────────
	if iss, ok := claims["iss"].(string); ok {
		if iss != rs.transmitterURL {
			log.Printf("[SSF Receiver] Issuer mismatch: got %q, expected %q", iss, rs.transmitterURL)
			return failedSET("invalid_issuer", fmt.Sprintf("Issuer mismatch: got %q", iss))
		}
	} else {
		return failedSET("invalid_issuer", "Missing required 'iss' claim")
	}

	// ── RFC 7519 §4.1.3: Validate audience ─────────────────────────────
	audValid := false
	if aud, ok := claims["aud"].([]interface{}); ok {
		for _, a := range aud {
			if s, _ := a.(string); s != "" {
				audValid = true
				break
			}
		}
	} else if _, ok := claims["aud"].(string); ok {
		audValid = true
	}
	if !audValid {
		return failedSET("invalid_audience", "Missing or empty 'aud' claim")
	}

	// ── RFC 7519 §4.1.6: Validate issued-at (reject tokens > 5 min old) ──
	if iatFloat, ok := claims["iat"].(float64); ok {
		iat := time.Unix(int64(iatFloat), 0)
		maxAge := 5 * time.Minute
		if time.Since(iat) > maxAge {
			log.Printf("[SSF Receiver] SET too old: issued at %v (%.0fs ago)", iat, time.Since(iat).Seconds())
			return failedSET("invalid_request", "SET expired: issued-at too old")
		}
	} else {
		return failedSET("invalid_request", "Missing required 'iat' claim")
	}

	decoded := buildDecodedSETFromClaims(claims, parsedToken.Header, setToken)

	// Extract JTI from the decoded token
	jti := decoded.JTI
	log.Printf("[SSF Receiver] Processing SET: %s", jti)

	// Broadcast: Event Verified
	rs.broadcast(ReceiverEvent{
		Type:      ReceiverEventVerified,
		Timestamp: time.Now(),
		EventID:   jti,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"issuer":    decoded.Issuer,
			"subject":   decoded.Subject,
			"events":    len(decoded.Events),
			"algorithm": "RS256",
			"key_id":    keyID,
		},
	})

	// ── Claim exclusive processing ownership (RFC 8935 §2 step 4 / RFC 8417 §2.2) ──
	// Signature and claims have already passed. From here on jti dedup, per-step
	// progress and the final outcome are durable, so concurrent push/poll get one
	// executor and a redelivery can never repeat a succeeded side effect.
	completedSteps := make(map[string]struct{})
	usingStorage := rs.storage != nil
	if jti != "" {
		if usingStorage {
			// Mark local in-flight BEFORE claiming so the claim decision is atomic
			// against concurrent deliveries on this instance (the DB row commit and
			// the in-memory marker would otherwise leave an undecidable gap).
			rs.markInflight(jti)
			outcome, done, err := rs.storage.ClaimSETProcessing(ctx, jti, decoded.Issuer, rs.ownerID, rs.isInflight(jti))
			if err != nil {
				rs.clearInflight(jti)
				log.Printf("[SSF Receiver] Failed to claim SET processing for %s: %v", jti, err)
				// No side effects may run without an exclusive claim; the failure is
				// deterministic: a redelivery starts the plan from scratch.
				return retryableFailedSET(SETErrStorageUnavailable,
					fmt.Sprintf("failed to claim SET processing: %v", err), http.StatusServiceUnavailable)
			}
			switch outcome {
			case SETClaimDuplicate:
				rs.clearInflight(jti)
				log.Printf("[SSF Receiver] Duplicate SET rejected (jti %s already processed)", jti)
				return failedSET("invalid_request", fmt.Sprintf("duplicate SET rejected (jti %s already processed)", jti))
			case SETClaimBusy:
				rs.clearInflight(jti)
				log.Printf("[SSF Receiver] SET %s is already being processed by this receiver", jti)
				return retryableFailedSET(SETErrProcessingInProgress,
					fmt.Sprintf("SET %s is already being processed", jti), http.StatusConflict)
			}
			for _, step := range done {
				completedSteps[step] = struct{}{}
			}
			defer rs.clearInflight(jti)
		} else {
			rs.seenJTIsMu.RLock()
			_, seen := rs.seenJTIs[jti]
			rs.seenJTIsMu.RUnlock()
			if seen {
				log.Printf("[SSF Receiver] Duplicate SET rejected (jti %s already processed)", jti)
				return failedSET("invalid_request", fmt.Sprintf("duplicate SET rejected (jti %s already processed)", jti))
			}
		}
	}

	// Broadcast: Processing
	rs.broadcast(ReceiverEvent{
		Type:      ReceiverEventProcessing,
		Timestamp: time.Now(),
		EventID:   jti,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"event_count": len(decoded.Events),
		},
	})

	// Extract subject email from the decoded SET
	var subjectEmail string
	if decoded.Subject != nil {
		subjectEmail = decoded.Subject.EmailAddress()
	}

	// Session ID comes from X-Looking-Glass-Session delivery header (not the SET)
	if sessionID != "" {
		log.Printf("[SSF Receiver] Session ID from delivery header: %s", sessionID)
	}

	// Initialize session states if this is a session-scoped event
	if sessionID != "" && rs.actionExecutor != nil {
		rs.actionExecutor.InitSessionUserStates(sessionID)
	}

	// Build the full step plan, then execute only steps not already completed by a
	// previous attempt. A step is durably marked immediately after it succeeds, so
	// a mid-plan failure resumes at exactly the first unfinished step on retry.
	type eventPlan struct {
		index int
		event DecodedEvent
		steps []mutationStep
	}
	plans := make([]eventPlan, 0, len(decoded.Events))
	for idx, event := range decoded.Events {
		log.Printf("[SSF Receiver] Processing event: %s for subject: %s (session: %s)", event.Type, subjectEmail, sessionID)
		steps := planMutationSteps(rs.actionExecutor, idx, event, subjectEmail, sessionID, decoded.Subject)
		if event.Type == EventTypeSessionRevoked && subjectEmail != "" && rs.federationURL != "" {
			steps = append(steps, mutationStep{
				Key:     fmt.Sprintf("e%d:federation-revoke", idx),
				Label:   "Federation revoke-subject",
				ErrCode: SETErrFederationRevokeFailed,
				run: func(ctx context.Context) error {
					return rs.revokeFederationSubject(ctx, sessionID, subjectEmail)
				},
			})
		}
		plans = append(plans, eventPlan{index: idx, event: event, steps: steps})
	}

	var failedStep mutationStep
	var stepErr error
planLoop:
	for _, plan := range plans {
		for _, step := range plan.steps {
			if _, done := completedSteps[step.Key]; done {
				log.Printf("[SSF Receiver] Skipping already-completed step %s (jti %s)", step.Key, jti)
				continue
			}
			if err := step.run(ctx); err != nil {
				failedStep, stepErr = step, err
				break planLoop
			}
			if jti != "" && usingStorage {
				if err := rs.storage.CompleteSETProcessingStep(ctx, jti, step.Key); err != nil {
					// The side effect happened but is not durably recorded. Treat it
					// as a retryable failure; ownership is released so the next
					// delivery (same instance included) re-claims and resumes.
					log.Printf("[SSF Receiver] Failed to persist step %s for %s: %v", step.Key, jti, err)
					failedStep = mutationStep{Key: step.Key, Label: step.Label, ErrCode: SETErrStorageUnavailable}
					stepErr = err
					break planLoop
				}
			}
			completedSteps[step.Key] = struct{}{}
		}
	}

	if stepErr != nil {
		description := fmt.Sprintf("SET processing failed at step %q: %v", failedStep.Key, stepErr)
		log.Printf("[SSF Receiver] %s", description)
		errCode := failedStep.ErrCode
		if errCode == "" {
			errCode = SETErrActionExecutionFailed
		}
		if jti != "" && usingStorage {
			if err := rs.storage.FailSETProcessing(ctx, jti, errCode, description); err != nil {
				log.Printf("[SSF Receiver] Failed to persist failure state for %s: %v", jti, err)
			}
		}
		// Not "processed": push answers a retryable error (no 202) and poll leaves
		// the SET unacknowledged so it is redelivered; completed steps are retained.
		return retryableFailedSET(errCode, description, http.StatusServiceUnavailable)
	}

	// All side effects completed. Display rows are written only on the success
	// path (steps completed earlier on a failed attempt are represented too, since
	// their effects are part of the finished SET).
	for _, plan := range plans {
		rs.recordResponseActions(jti, plan.event, subjectEmail, sessionID, len(plan.steps) > 0)
	}

	// Record the received event as processed only after durable completion
	processedAt := time.Now()
	rs.addReceivedEvent(ReceivedEvent{
		ID:             jti,
		ReceivedAt:     receivedAt,
		DeliveryMethod: "push",
		SET:            decoded,
		Verified:       true,
		Processed:      true,
		ProcessedAt:    &processedAt,
	})

	// Lock the jti against replay. Durable when Storage is attached; otherwise the
	// in-memory fallback covers the lifetime of this receiver instance.
	if jti != "" {
		if usingStorage {
			if err := rs.storage.CompleteSETProcessing(ctx, jti); err != nil {
				log.Printf("[SSF Receiver] Failed to persist completion for %s: %v", jti, err)
				return retryableFailedSET(SETErrStorageUnavailable,
					fmt.Sprintf("failed to persist SET completion: %v", err), http.StatusServiceUnavailable)
			}
		} else {
			rs.seenJTIsMu.Lock()
			rs.seenJTIs[jti] = time.Now()
			rs.seenJTIsMu.Unlock()
		}
	}

	// Broadcast: Event Processed
	finalAt := time.Now()
	rs.broadcast(ReceiverEvent{
		Type:      ReceiverEventProcessed,
		Timestamp: finalAt,
		EventID:   jti,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"processing_time_ms": finalAt.Sub(receivedAt).Milliseconds(),
		},
	})

	log.Printf("[SSF Receiver] SET processed successfully: %s", jti)
	return SetStatus{Status: "success", Description: "Event processed and actions executed"}
}

// recordResponseActions appends and broadcasts the display rows of one event.
// It carries no side effects — mutation execution and progress tracking happen
// in processSET before this is called.
func (rs *ReceiverService) recordResponseActions(eventID string, event DecodedEvent, subjectEmail, sessionID string, mutated bool) {
	var before *UserSecurityState
	if rs.actionExecutor != nil && subjectEmail != "" {
		before, _ = rs.actionExecutor.GetUserStateForSession(sessionID, subjectEmail)
	}

	actions := buildResponseActions(eventID, event, sessionID, mutated, nil)
	for _, action := range actions {
		rs.addResponseAction(action)
		log.Printf("[SSF Receiver] Action recorded: %s - %s (session: %s)", action.Action, action.Status, sessionID)

		var after *UserSecurityState
		if rs.actionExecutor != nil && subjectEmail != "" {
			after, _ = rs.actionExecutor.GetUserStateForSession(sessionID, subjectEmail)
		}

		rs.broadcast(ReceiverEvent{
			Type:      ReceiverEventResponseAction,
			Timestamp: action.ExecutedAt,
			EventID:   eventID,
			SessionID: sessionID,
			Data: map[string]interface{}{
				"action":      action.Action,
				"description": action.Description,
				"status":      action.Status,
				"event_type":  event.Metadata.Name,
				"event_uri":   event.Type,
				"category":    event.Metadata.Category,
				"zero_trust":  event.Metadata.ZeroTrustImpact,
				"subject":     subjectEmail,
				"before":      before,
				"after":       after,
			},
		})
		before = after
	}
}

// revokeFederationSubject performs the cross-service CAEP revoke-subject hop and
// returns an error on request-build, transport or non-2xx failure so the caller
// can keep the SET in its retryable failure state instead of marking it processed.
// The Looking Glass exchange is broadcast on every attempt, failures included.
func (rs *ReceiverService) revokeFederationSubject(ctx context.Context, sessionID, email string) error {
	target := rs.federationURL + "/oauth2/demo/caep/revoke-subject"
	payload, _ := json.Marshal(map[string]string{"email": email})

	reqHeaders := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}
	if rs.federationToken != "" {
		reqHeaders["Authorization"] = "Bearer " + rs.federationToken
	}

	exchange := &CapturedHTTPExchange{
		Label:     "CAEP RP revoke-subject (federation)",
		Timestamp: time.Now(),
		SessionID: sessionID,
		Request: HTTPCapture{
			Method:  "POST",
			URL:     target,
			Headers: reqHeaders,
			Body:    string(payload),
		},
		Response: HTTPCapture{
			Headers: make(map[string]string),
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		exchange.Response.Body = fmt.Sprintf("error: %v", err)
		rs.broadcastFederationHop(sessionID, exchange)
		return fmt.Errorf("build federation revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if rs.federationToken != "" {
		req.Header.Set("Authorization", "Bearer "+rs.federationToken)
	}

	client := rs.federationHTTP
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	start := time.Now()
	resp, err := client.Do(req)
	exchange.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		exchange.Response.Body = fmt.Sprintf("error: %v", err)
		rs.broadcastFederationHop(sessionID, exchange)
		return fmt.Errorf("federation revoke-subject request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	exchange.Response.StatusCode = resp.StatusCode
	for k := range resp.Header {
		exchange.Response.Headers[k] = resp.Header.Get(k)
	}
	exchange.Response.Body = string(body)
	rs.broadcastFederationHop(sessionID, exchange)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("federation revoke-subject returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (rs *ReceiverService) broadcastFederationHop(sessionID string, exchange *CapturedHTTPExchange) {
	rs.broadcast(ReceiverEvent{
		Type:      ReceiverEventHTTPExchange,
		Timestamp: exchange.Timestamp,
		SessionID: sessionID,
		Data:      exchange,
	})
}

// addReceivedEvent adds an event to the received log
func (rs *ReceiverService) addReceivedEvent(event ReceivedEvent) {
	rs.eventsMu.Lock()
	defer rs.eventsMu.Unlock()

	if len(rs.receivedEvents) >= 100 {
		rs.receivedEvents = rs.receivedEvents[1:]
	}
	rs.receivedEvents = append(rs.receivedEvents, event)
}

// addResponseAction adds a response action to the log
func (rs *ReceiverService) addResponseAction(action ResponseAction) {
	rs.actionsMu.Lock()
	defer rs.actionsMu.Unlock()

	if len(rs.responseActions) >= 200 {
		rs.responseActions = rs.responseActions[1:]
	}
	rs.responseActions = append(rs.responseActions, action)
}

// HTTP Handlers

func (rs *ReceiverService) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":          "running",
		"port":            rs.port,
		"transmitter_url": rs.transmitterURL,
		"events_received": len(rs.receivedEvents),
		"actions_taken":   len(rs.responseActions),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (rs *ReceiverService) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	rs.eventsMu.RLock()
	defer rs.eventsMu.RUnlock()

	// Return in reverse order (newest first)
	events := make([]ReceivedEvent, len(rs.receivedEvents))
	for i, e := range rs.receivedEvents {
		events[len(rs.receivedEvents)-1-i] = e
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"total":  len(events),
	})
}

func (rs *ReceiverService) handleGetActions(w http.ResponseWriter, r *http.Request) {
	rs.actionsMu.RLock()
	defer rs.actionsMu.RUnlock()

	// Return in reverse order (newest first)
	actions := make([]ResponseAction, len(rs.responseActions))
	for i, a := range rs.responseActions {
		actions[len(rs.responseActions)-1-i] = a
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"actions": actions,
		"total":   len(actions),
	})
}

func (rs *ReceiverService) handleClearLogs(w http.ResponseWriter, r *http.Request) {
	rs.ClearLogs()
	w.WriteHeader(http.StatusNoContent)
}

// ClearLogs clears only the received/actions display records. Replay protection
// is intentionally NOT touched: durable set_processing rows in SQLite (and the
// in-memory fallback) keep rejecting already-processed jtis, so clearing the
// display logs can never make the same SET take effect again.
func (rs *ReceiverService) ClearLogs() {
	rs.eventsMu.Lock()
	rs.receivedEvents = make([]ReceivedEvent, 0)
	rs.eventsMu.Unlock()

	rs.actionsMu.Lock()
	rs.responseActions = make([]ResponseAction, 0)
	rs.actionsMu.Unlock()
}

// writeReceiverSSFError writes an error response per RFC 8935 §2.3.
func writeReceiverSSFError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"err":         errCode,
		"description": description,
	})
}

// GetReceivedEvents returns the received events (for backward compat)
func (rs *ReceiverService) GetReceivedEvents() []ReceivedEvent {
	rs.eventsMu.RLock()
	defer rs.eventsMu.RUnlock()

	result := make([]ReceivedEvent, len(rs.receivedEvents))
	for i, e := range rs.receivedEvents {
		result[len(rs.receivedEvents)-1-i] = e
	}
	return result
}

// buildDecodedSETFromClaims constructs a DecodedSET from already-verified jwt.MapClaims,
// avoiding a redundant re-parse of the raw token string.
func buildDecodedSETFromClaims(claims jwt.MapClaims, header map[string]interface{}, rawToken string) *DecodedSET {
	decoded := &DecodedSET{
		RawToken: rawToken,
		Header:   header,
		Events:   []DecodedEvent{},
	}

	if jti, ok := claims["jti"].(string); ok {
		decoded.JTI = jti
	}
	if iss, ok := claims["iss"].(string); ok {
		decoded.Issuer = iss
	}
	if aud, ok := claims["aud"].([]interface{}); ok {
		for _, a := range aud {
			if s, ok := a.(string); ok {
				decoded.Audience = append(decoded.Audience, s)
			}
		}
	} else if aud, ok := claims["aud"].(string); ok {
		decoded.Audience = []string{aud}
	}
	if iat, ok := claims["iat"].(float64); ok {
		decoded.IssuedAt = time.Unix(int64(iat), 0)
	}
	if txn, ok := claims["txn"].(string); ok {
		decoded.TransactionID = txn
	}

	// Parse sub_id
	if subID, ok := claims["sub_id"].(map[string]interface{}); ok {
		decoded.Subject = setSubjectFromMap(subID)
	}

	// Parse events
	if events, ok := claims["events"].(map[string]interface{}); ok {
		for eventType, payload := range events {
			payloadBytes, err := json.Marshal(payload)
			if err != nil {
				continue
			}
			var eventPayload EventPayload
			if err := json.Unmarshal(payloadBytes, &eventPayload); err != nil {
				continue
			}
			metadata := GetEventMetadata(eventType)
			decoded.Events = append(decoded.Events, DecodedEvent{
				Type:       eventType,
				Metadata:   metadata,
				Payload:    eventPayload,
				RawPayload: payload,
			})
		}
	}

	return decoded
}

// GetResponseActions returns the response actions (for backward compat)
func (rs *ReceiverService) GetResponseActions() []ResponseAction {
	rs.actionsMu.RLock()
	defer rs.actionsMu.RUnlock()

	result := make([]ResponseAction, len(rs.responseActions))
	for i, a := range rs.responseActions {
		result[len(rs.responseActions)-1-i] = a
	}
	return result
}
