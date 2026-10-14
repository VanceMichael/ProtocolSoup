package ssf

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// countingExecutor counts mutation calls and can inject a fixed number of
// failures per method. It implements only the methods used by the step plan;
// the embedded interface covers the rest and panics if ever called.
type countingExecutor struct {
	ActionExecutor
	mu      sync.Mutex
	calls   map[string]int
	failing map[string]int
	delay   time.Duration
}

func newCountingExecutor() *countingExecutor {
	return &countingExecutor{calls: map[string]int{}, failing: map[string]int{}}
}

func (c *countingExecutor) record(method string) error {
	c.mu.Lock()
	c.calls[method]++
	var err error
	if c.failing[method] > 0 {
		c.failing[method]--
		err = fmt.Errorf("injected %s failure", method)
	}
	delay := c.delay
	c.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	return err
}

func (c *countingExecutor) count(method string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[method]
}

func (c *countingExecutor) fail(method string, times int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failing[method] = times
}

func (c *countingExecutor) InitSessionUserStates(sessionID string) {}

func (c *countingExecutor) GetUserStateForSession(sessionID, email string) (*UserSecurityState, error) {
	return &UserSecurityState{Email: email, AccountEnabled: true, TokensValid: true}, nil
}

func (c *countingExecutor) RevokeUserSessionsForSession(ctx context.Context, sessionID, email string) error {
	return c.record("RevokeUserSessionsForSession")
}

func (c *countingExecutor) DisableUserForSession(ctx context.Context, sessionID, email string) error {
	return c.record("DisableUserForSession")
}

func (c *countingExecutor) EnableUserForSession(ctx context.Context, sessionID, email string) error {
	return c.record("EnableUserForSession")
}

func (c *countingExecutor) ForcePasswordResetForSession(ctx context.Context, sessionID, email string) error {
	return c.record("ForcePasswordResetForSession")
}

func (c *countingExecutor) InvalidateTokensForSession(ctx context.Context, sessionID, email string) error {
	return c.record("InvalidateTokensForSession")
}

func (c *countingExecutor) ApplyDeviceComplianceForSession(ctx context.Context, sessionID, email, deviceID, status string) error {
	return c.record("ApplyDeviceComplianceForSession")
}

// receiverHarness wires a ReceiverService to a real SQLite file, a JWKS server
// matching its signing key, and a configurable federation peer.
type receiverHarness struct {
	t       *testing.T
	dir     string
	key     *rsa.PrivateKey
	keyID   string
	storage *Storage
	rs      *ReceiverService
	enc     *SETEncoder
	exec    *countingExecutor
	jwksSrv *httptest.Server

	fedMu   sync.Mutex
	fedCode int
	fedHits int
	fedSrv  *httptest.Server
}

func newReceiverHarness(t *testing.T) *receiverHarness {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyID := "test-key-" + uuid.NewString()
	h := &receiverHarness{
		t:       t,
		dir:     t.TempDir(),
		key:     key,
		keyID:   keyID,
		exec:    newCountingExecutor(),
		fedCode: http.StatusOK,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ssf/jwks", h.serveJWKS)
	h.jwksSrv = httptest.NewServer(mux)
	t.Cleanup(h.jwksSrv.Close)

	h.fedSrv = httptest.NewServer(http.HandlerFunc(h.serveFederation))
	t.Cleanup(h.fedSrv.Close)

	storage, err := NewStorage(h.dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	h.storage = storage
	t.Cleanup(func() { _ = storage.Close() })

	h.rs = NewReceiverService(0, h.jwksSrv.URL, "push-token", h.exec)
	h.rs.SetStorage(storage)
	h.rs.SetFederationCAEP(h.fedSrv.URL, "")
	h.enc = NewSETEncoder(h.jwksSrv.URL, key, keyID)
	return h
}

func (h *receiverHarness) serveJWKS(w http.ResponseWriter, r *http.Request) {
	pub := &h.key.PublicKey
	doc := map[string]interface{}{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": h.keyID,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (h *receiverHarness) serveFederation(w http.ResponseWriter, r *http.Request) {
	h.fedMu.Lock()
	h.fedHits++
	code := h.fedCode
	h.fedMu.Unlock()
	w.WriteHeader(code)
}

func (h *receiverHarness) setFedCode(code int) {
	h.fedMu.Lock()
	h.fedCode = code
	h.fedMu.Unlock()
}

func (h *receiverHarness) federationHits() int {
	h.fedMu.Lock()
	defer h.fedMu.Unlock()
	return h.fedHits
}

func (h *receiverHarness) makeSET(eventType, jti string, issuedAt time.Time) string {
	h.t.Helper()
	token, err := h.enc.Encode(SecurityEvent{
		EventType:      eventType,
		EventTimestamp: time.Now(),
		Subject: SubjectIdentifier{
			Format: SubjectFormatEmail,
			Email:  "alice@example.com",
		},
	}, []string{h.jwksSrv.URL + "/receiver"}, jti)
	if err != nil {
		h.t.Fatalf("encode SET: %v", err)
	}
	if !issuedAt.IsZero() {
		// Re-sign with an explicit iat when the test needs a stale token.
		token = signSETWithClaims(h.key, h.keyID, jwt.MapClaims{
			"iss": h.jwksSrv.URL,
			"aud": []string{h.jwksSrv.URL + "/receiver"},
			"iat": issuedAt.Unix(),
			"jti": jti,
			"sub_id": map[string]interface{}{
				"format": SubjectFormatEmail,
				"email":  "alice@example.com",
			},
			"events": map[string]interface{}{
				eventType: map[string]interface{}{},
			},
		})
	}
	return token
}

func signSETWithClaims(key *rsa.PrivateKey, keyID string, claims jwt.MapClaims) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = keyID
	tok.Header["typ"] = "secevent+jwt"
	signed, err := tok.SignedString(key)
	if err != nil {
		panic(err)
	}
	return signed
}

func (h *receiverHarness) pushSET(token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ssf/push", strings.NewReader(token))
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Authorization", "Bearer push-token")
	rec := httptest.NewRecorder()
	h.rs.handlePush(rec, req)
	return rec
}

func (h *receiverHarness) processingRecord(jti string) *SETProcessing {
	h.t.Helper()
	rec, err := h.storage.GetSETProcessing(context.Background(), jti)
	if err != nil {
		h.t.Fatalf("get processing record for %s: %v", jti, err)
	}
	return rec
}

// Concurrent push and poll delivery of one SET: exactly one executor runs each
// side effect; only one delivery is confirmed (202), the rest are busy/duplicate.
func TestSETConcurrentPushPollSingleExecutor(t *testing.T) {
	h := newReceiverHarness(t)
	h.exec.delay = 8 * time.Millisecond

	jti := uuid.NewString()
	token := h.makeSET(EventTypeCredentialCompromise, jti, time.Time{})

	const deliveries = 12
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successCount, busyCount, dupCount, serverFailCount int
	var pushCodes []int

	for i := 0; i < deliveries; i++ {
		wg.Add(1)
		isPush := i%2 == 0
		go func() {
			defer wg.Done()
			<-start
			if isPush {
				rec := h.pushSET(token)
				mu.Lock()
				defer mu.Unlock()
				pushCodes = append(pushCodes, rec.Code)
				switch rec.Code {
				case http.StatusAccepted:
					successCount++
				case http.StatusConflict:
					busyCount++
				case http.StatusBadRequest:
					dupCount++
				default:
					serverFailCount++
				}
			} else {
				statuses := h.rs.ProcessPollResponse(context.Background(),
					map[string]string{jti: token}, map[string]string{})
				st := statuses[0]
				mu.Lock()
				defer mu.Unlock()
				switch {
				case st.Status == "success":
					successCount++
				case st.Err == SETErrProcessingInProgress:
					busyCount++
				case st.Err == "invalid_request":
					dupCount++
				default:
					serverFailCount++
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("want exactly 1 confirmed delivery, got %d (busy=%d dup=%d 5xx=%d, push=%v)",
			successCount, busyCount, dupCount, serverFailCount, pushCodes)
	}
	if serverFailCount != 0 {
		t.Fatalf("unexpected 5xx/server failures: %d", serverFailCount)
	}
	if got := successCount + busyCount + dupCount; got != deliveries {
		t.Fatalf("accounted deliveries %d, want %d", got, deliveries)
	}

	// Every side effect of the three-step plan executes exactly once.
	for _, method := range []string{
		"ForcePasswordResetForSession",
		"InvalidateTokensForSession",
		"RevokeUserSessionsForSession",
	} {
		if c := h.exec.count(method); c != 1 {
			t.Errorf("%s executed %d times, want exactly 1", method, c)
		}
	}

	rec := h.processingRecord(jti)
	if rec.Status != SETStatusSucceeded {
		t.Fatalf("processing status %q, want succeeded", rec.Status)
	}
	if len(rec.CompletedSteps) != 3 {
		t.Fatalf("completed steps %v, want 3", rec.CompletedSteps)
	}
}

// Mid-plan action failure leaves a deterministic retry point: push does not
// answer 202, the failed SET stays in 'failed' state with only the succeeded
// step durable, and redelivery resumes at the unfinished step.
func TestSETActionFailureResumesPartial(t *testing.T) {
	h := newReceiverHarness(t)
	// The second step (invalidate tokens) fails on its first attempt only.
	h.exec.fail("InvalidateTokensForSession", 1)

	jti := uuid.NewString()
	token := h.makeSET(EventTypeCredentialCompromise, jti, time.Time{})

	rec := h.pushSET(token)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("first push status %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, SETErrActionExecutionFailed) {
		t.Fatalf("error body %q missing %q", body, SETErrActionExecutionFailed)
	}

	if c := h.exec.count("ForcePasswordResetForSession"); c != 1 {
		t.Errorf("password reset ran %d times, want 1", c)
	}
	if c := h.exec.count("InvalidateTokensForSession"); c != 1 {
		t.Errorf("invalidate ran %d times, want 1 (failed)", c)
	}
	if c := h.exec.count("RevokeUserSessionsForSession"); c != 0 {
		t.Errorf("revoke sessions ran %d times, want 0", c)
	}

	pr := h.processingRecord(jti)
	if pr.Status != SETStatusFailed {
		t.Fatalf("status %q, want failed", pr.Status)
	}
	if pr.ErrorCode != SETErrActionExecutionFailed {
		t.Fatalf("error_code %q, want %q", pr.ErrorCode, SETErrActionExecutionFailed)
	}
	if len(pr.CompletedSteps) != 1 || pr.CompletedSteps[0] != "e0:force-password-reset" {
		t.Fatalf("completed steps %v, want only e0:force-password-reset", pr.CompletedSteps)
	}

	// Redelivery resumes: step 1 is skipped, step 2 now succeeds, step 3 runs.
	st := h.rs.processSET(context.Background(), token, "")
	if st.Status != "success" {
		t.Fatalf("retry status %s: %s", st.Status, st.Description)
	}
	if c := h.exec.count("ForcePasswordResetForSession"); c != 1 {
		t.Errorf("password reset re-ran: %d total, want 1", c)
	}
	if c := h.exec.count("InvalidateTokensForSession"); c != 2 {
		t.Errorf("invalidate ran %d times, want 2 (1 failed + 1 success)", c)
	}
	if c := h.exec.count("RevokeUserSessionsForSession"); c != 1 {
		t.Errorf("revoke sessions ran %d times, want 1", c)
	}

	pr = h.processingRecord(jti)
	if pr.Status != SETStatusSucceeded || pr.CompletedAt == nil {
		t.Fatalf("post-retry record status=%q completed_at=%v", pr.Status, pr.CompletedAt)
	}
	if len(pr.CompletedSteps) != 3 {
		t.Fatalf("post-retry steps %v, want 3", pr.CompletedSteps)
	}

	// A third delivery is a replay and changes nothing.
	st = h.rs.processSET(context.Background(), token, "")
	if st.Status != "failed" || st.Err != "invalid_request" {
		t.Fatalf("replay status=%+v, want invalid_request duplicate", st)
	}
	if c := h.exec.count("ForcePasswordResetForSession"); c != 1 {
		t.Errorf("side effect re-ran after completion: %d", c)
	}
}

// Federation revoke failure is a side-effect failure: no 202, resumable, and
// the local revoke-sessions step is never repeated.
func TestSETFederationRevokeFailureResumes(t *testing.T) {
	h := newReceiverHarness(t)
	h.setFedCode(http.StatusInternalServerError)

	jti := uuid.NewString()
	token := h.makeSET(EventTypeSessionRevoked, jti, time.Time{})

	rec := h.pushSET(token)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("push status %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), SETErrFederationRevokeFailed) {
		t.Fatalf("body %q missing federation error code", rec.Body.String())
	}
	if c := h.exec.count("RevokeUserSessionsForSession"); c != 1 {
		t.Fatalf("local revoke ran %d times, want 1", c)
	}
	if hits := h.federationHits(); hits != 1 {
		t.Fatalf("federation hits %d, want 1", hits)
	}
	pr := h.processingRecord(jti)
	if pr.Status != SETStatusFailed {
		t.Fatalf("status %q, want failed", pr.Status)
	}
	if steps := pr.CompletedSteps; len(steps) != 1 || steps[0] != "e0:revoke-sessions" {
		t.Fatalf("steps %v, want only local revoke", steps)
	}

	// Federation recovers; retry completes just the federation step.
	h.setFedCode(http.StatusOK)
	st := h.rs.processSET(context.Background(), token, "")
	if st.Status != "success" {
		t.Fatalf("retry status %s: %s", st.Status, st.Description)
	}
	if c := h.exec.count("RevokeUserSessionsForSession"); c != 1 {
		t.Errorf("local revoke re-ran: %d total, want 1", c)
	}
	if hits := h.federationHits(); hits != 2 {
		t.Errorf("federation hits %d, want 2", hits)
	}

	// Replay must not re-invoke federation either.
	st = h.rs.processSET(context.Background(), token, "")
	if st.Err != "invalid_request" {
		t.Fatalf("replay status %+v, want duplicate", st)
	}
	if hits := h.federationHits(); hits != 2 {
		t.Errorf("federation re-invoked after completion: %d hits", hits)
	}
}

// Poll path: a failed SET is returned as a failed (non-confirmable) status and a
// later poll resumes it; a completed SET is reported as duplicate, not executed.
func TestSETPollFailureNotConfirmedAndResumes(t *testing.T) {
	h := newReceiverHarness(t)
	h.exec.fail("InvalidateTokensForSession", 1)

	jti := uuid.NewString()
	token := h.makeSET(EventTypeCredentialCompromise, jti, time.Time{})

	first := h.rs.ProcessPollResponse(context.Background(),
		map[string]string{jti: token}, map[string]string{})
	if len(first) != 1 || first[0].Status != "failed" || first[0].Err != SETErrActionExecutionFailed {
		t.Fatalf("first poll statuses %+v, want one failed/action_execution_failed", first)
	}

	// Simulated redelivery resumes the unfinished steps and succeeds.
	second := h.rs.ProcessPollResponse(context.Background(),
		map[string]string{jti: token}, map[string]string{})
	if len(second) != 1 || second[0].Status != "success" {
		t.Fatalf("second poll statuses %+v, want one success", second)
	}
	if c := h.exec.count("ForcePasswordResetForSession"); c != 1 {
		t.Errorf("password reset ran %d times, want 1", c)
	}
	if c := h.exec.count("RevokeUserSessionsForSession"); c != 1 {
		t.Errorf("revoke sessions ran %d times, want 1", c)
	}

	third := h.rs.ProcessPollResponse(context.Background(),
		map[string]string{jti: token}, map[string]string{})
	if len(third) != 1 || third[0].Err != "invalid_request" {
		t.Fatalf("third poll statuses %+v, want duplicate rejection", third)
	}
}

// Succeeded and partially-failed processing records both survive a full
// Storage close/reopen and ReceiverService rebuild against the same SQLite file.
func TestSETProcessingSurvivesCloseReopen(t *testing.T) {
	h := newReceiverHarness(t)

	// Case 1: completed jti stays replay-locked after reopen.
	jtiDone := uuid.NewString()
	tokenDone := h.makeSET(EventTypeCredentialCompromise, jtiDone, time.Time{})
	if st := h.rs.processSET(context.Background(), tokenDone, ""); st.Status != "success" {
		t.Fatalf("initial process: %s", st.Description)
	}
	forceBefore := h.exec.count("ForcePasswordResetForSession")

	if err := h.storage.Close(); err != nil {
		t.Fatalf("close storage: %v", err)
	}
	reopened, err := NewStorage(h.dir)
	if err != nil {
		t.Fatalf("reopen storage: %v", err)
	}
	defer reopened.Close()

	rs2 := NewReceiverService(0, h.jwksSrv.URL, "push-token", h.exec)
	rs2.SetStorage(reopened)
	rs2.SetFederationCAEP(h.fedSrv.URL, "")
	if st := rs2.processSET(context.Background(), tokenDone, ""); st.Status != "failed" || st.Err != "invalid_request" {
		t.Fatalf("rebuilt receiver replay status %+v, want duplicate", st)
	}
	if c := h.exec.count("ForcePasswordResetForSession"); c != forceBefore {
		t.Errorf("completed SET re-executed after rebuild: force reset now %d, was %d", c, forceBefore)
	}

	// Case 2: a SET that failed mid-plan resumes from the unfinished step after
	// reopen, and the succeeded step is not repeated.
	jtiPartial := uuid.NewString()
	tokenPartial := h.makeSET(EventTypeCredentialCompromise, jtiPartial, time.Time{})
	// Drive the failed first attempt through the rebuilt service with one failure.
	// Failures are tracked on the shared executor; fail invalidate for its next
	// single call regardless of which receiver instance makes it.
	h.exec.fail("InvalidateTokensForSession", 1)
	if st := rs2.processSET(context.Background(), tokenPartial, ""); st.Err != SETErrActionExecutionFailed {
		t.Fatalf("partial attempt status %+v, want action_execution_failed", st)
	}
	partialForce := h.exec.count("ForcePasswordResetForSession") - forceBefore
	if partialForce != 1 {
		t.Fatalf("partial first step ran %d times, want 1", partialForce)
	}

	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened storage: %v", err)
	}
	reopened2, err := NewStorage(h.dir)
	if err != nil {
		t.Fatalf("second reopen: %v", err)
	}
	defer reopened2.Close()

	rs3 := NewReceiverService(0, h.jwksSrv.URL, "push-token", h.exec)
	rs3.SetStorage(reopened2)
	rs3.SetFederationCAEP(h.fedSrv.URL, "")
	if st := rs3.processSET(context.Background(), tokenPartial, ""); st.Status != "success" {
		t.Fatalf("resume after rebuild status %s: %s", st.Status, st.Description)
	}
	if got := h.exec.count("ForcePasswordResetForSession") - forceBefore; got != 1 {
		t.Errorf("first step re-ran across rebuild: %d total executions for partial SET, want 1", got)
	}
	if c := h.exec.count("RevokeUserSessionsForSession"); c != 2 {
		t.Errorf("revoke sessions total %d, want 2 (one per SET)", c)
	}

	rec, err := reopened2.GetSETProcessing(context.Background(), jtiPartial)
	if err != nil {
		t.Fatalf("get partial record: %v", err)
	}
	if rec.Status != SETStatusSucceeded {
		t.Fatalf("partial SET status %q, want succeeded", rec.Status)
	}
}

// SQLite unavailable at claim time: no side effects may run and push must not
// confirm; once the database is reopened the unchanged SET processes normally.
func TestSETStorageFailureBeforeClaimIsRetryable(t *testing.T) {
	h := newReceiverHarness(t)
	jti := uuid.NewString()
	token := h.makeSET(EventTypeAccountDisabled, jti, time.Time{})

	if err := h.storage.Close(); err != nil {
		t.Fatalf("close storage: %v", err)
	}

	rec := h.pushSET(token)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("push with closed DB status %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), SETErrStorageUnavailable) {
		t.Fatalf("body %q missing %q", rec.Body.String(), SETErrStorageUnavailable)
	}
	if c := h.exec.count("DisableUserForSession"); c != 0 {
		t.Fatalf("action ran despite failed claim: %d times", c)
	}

	reopened, err := NewStorage(h.dir)
	if err != nil {
		t.Fatalf("reopen storage: %v", err)
	}
	defer reopened.Close()
	h.rs.SetStorage(reopened)

	if st := h.rs.processSET(context.Background(), token, ""); st.Status != "success" {
		t.Fatalf("redelivery after DB recovery: %s", st.Description)
	}
	if c := h.exec.count("DisableUserForSession"); c != 1 {
		t.Errorf("disable ran %d times after recovery, want 1", c)
	}
	if st := h.rs.processSET(context.Background(), token, ""); st.Err != "invalid_request" {
		t.Fatalf("replay after recovery status %+v, want duplicate", st)
	}
}

// ClearLogs wipes only display records; durable replay protection is intact and
// the receiver still processes new SETs.
func TestClearLogsPreservesReplayProtection(t *testing.T) {
	h := newReceiverHarness(t)

	jti := uuid.NewString()
	token := h.makeSET(EventTypeAccountDisabled, jti, time.Time{})
	if st := h.rs.processSET(context.Background(), token, ""); st.Status != "success" {
		t.Fatalf("initial process: %s", st.Description)
	}
	if len(h.rs.GetReceivedEvents()) == 0 || len(h.rs.GetResponseActions()) == 0 {
		t.Fatal("expected received/action display records before clear")
	}
	if c := h.exec.count("DisableUserForSession"); c != 1 {
		t.Fatalf("disable ran %d times, want 1", c)
	}

	h.rs.ClearLogs()
	if len(h.rs.GetReceivedEvents()) != 0 || len(h.rs.GetResponseActions()) != 0 {
		t.Fatal("display logs must be empty after ClearLogs")
	}

	// Same jti must still be rejected and must not execute the action again.
	if st := h.rs.processSET(context.Background(), token, ""); st.Err != "invalid_request" {
		t.Fatalf("replay after ClearLogs status %+v, want duplicate", st)
	}
	if c := h.exec.count("DisableUserForSession"); c != 1 {
		t.Errorf("action re-ran after ClearLogs: %d, want 1", c)
	}
	rec := h.processingRecord(jti)
	if rec.Status != SETStatusSucceeded {
		t.Fatalf("durable record status %q, want succeeded", rec.Status)
	}

	// A new, different jti processes normally — the receiver is still usable.
	other := uuid.NewString()
	tokenOther := h.makeSET(EventTypeAccountEnabled, other, time.Time{})
	if st := h.rs.processSET(context.Background(), tokenOther, ""); st.Status != "success" {
		t.Fatalf("new SET after ClearLogs: %s", st.Description)
	}
}

// Signature/issuer/audience/expiry validation errors are unchanged and never
// create a processing claim or execute an action.
func TestSETValidationErrorsUnchanged(t *testing.T) {
	h := newReceiverHarness(t)

	// Tampered signature.
	good := h.makeSET(EventTypeAccountDisabled, uuid.NewString(), time.Time{})
	replacement := byte('A')
	if good[len(good)-1] == 'A' {
		replacement = 'B'
	}
	tampered := good[:len(good)-1] + string(replacement)
	if st := h.rs.processSET(context.Background(), tampered, ""); st.Err != "invalid_key" {
		t.Fatalf("tampered signature err %q, want invalid_key", st.Err)
	}

	// Wrong issuer, signed with the same key so only the iss check can fail.
	wrongIss := NewSETEncoder(h.jwksSrv.URL+"/elsewhere", h.key, h.keyID)
	wrongIssToken, err := wrongIss.Encode(SecurityEvent{
		EventType:      EventTypeAccountDisabled,
		EventTimestamp: time.Now(),
		Subject:        SubjectIdentifier{Format: SubjectFormatEmail, Email: "alice@example.com"},
	}, []string{h.jwksSrv.URL + "/receiver"}, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if st := h.rs.processSET(context.Background(), wrongIssToken, ""); st.Err != "invalid_issuer" {
		t.Fatalf("wrong issuer err %q, want invalid_issuer", st.Err)
	}

	// Empty audience.
	emptyAud := signSETWithClaims(h.key, h.keyID, jwt.MapClaims{
		"iss": h.jwksSrv.URL,
		"aud": []string{},
		"iat": time.Now().Unix(),
		"jti": uuid.NewString(),
		"sub_id": map[string]interface{}{
			"format": SubjectFormatEmail,
			"email":  "alice@example.com",
		},
		"events": map[string]interface{}{EventTypeAccountDisabled: map[string]interface{}{}},
	})
	if st := h.rs.processSET(context.Background(), emptyAud, ""); st.Err != "invalid_audience" {
		t.Fatalf("empty audience err %q, want invalid_audience", st.Err)
	}

	// Expired (iat older than the 5 minute window).
	expiredJTI := uuid.NewString()
	expired := h.makeSET(EventTypeAccountDisabled, expiredJTI, time.Now().Add(-10*time.Minute))
	if st := h.rs.processSET(context.Background(), expired, ""); st.Err != "invalid_request" || !strings.Contains(st.Description, "expired") {
		t.Fatalf("expired SET status %+v, want invalid_request/expired", st)
	}

	if c := h.exec.count("DisableUserForSession"); c != 0 {
		t.Errorf("validation failures executed the action %d times, want 0", c)
	}
	if _, err := h.storage.GetSETProcessing(context.Background(), expiredJTI); err == nil {
		t.Fatal("invalid SET must not create a processing claim row")
	}
}

// flakyReceiverExecutor wraps the real executor: InvalidateTokensForSession fails
// the first `remainingFails` calls; containment calls are counted.
type flakyReceiverExecutor struct {
	ActionExecutor
	mu             sync.Mutex
	remainingFails int
	forceN         int
	invalN         int
	revokeN        int
}

func (f *flakyReceiverExecutor) ForcePasswordResetForSession(ctx context.Context, sessionID, email string) error {
	f.mu.Lock()
	f.forceN++
	f.mu.Unlock()
	return f.ActionExecutor.ForcePasswordResetForSession(ctx, sessionID, email)
}

func (f *flakyReceiverExecutor) InvalidateTokensForSession(ctx context.Context, sessionID, email string) error {
	f.mu.Lock()
	f.invalN++
	fail := f.remainingFails > 0
	if fail {
		f.remainingFails--
	}
	f.mu.Unlock()
	if fail {
		return errors.New("injected invalidate failure")
	}
	return f.ActionExecutor.InvalidateTokensForSession(ctx, sessionID, email)
}

func (f *flakyReceiverExecutor) RevokeUserSessionsForSession(ctx context.Context, sessionID, email string) error {
	f.mu.Lock()
	f.revokeN++
	f.mu.Unlock()
	return f.ActionExecutor.RevokeUserSessionsForSession(ctx, sessionID, email)
}

func (f *flakyReceiverExecutor) snapshot() (force, inval, revoke int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.forceN, f.invalN, f.revokeN
}

// End-to-end poll: a SET whose mid-plan action fails is not confirmed (it is
// retransmitted on the next poll while still unacknowledged) and the retransmit
// resumes only the unfinished steps; the explicit ack then removes it for good.
func TestPollFailureRetransmittedAndResumed(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)

	// Triggering fans events out to every matching stream (default + session), so
	// resolve the session stream and switch ALL streams to poll: a push copy would
	// otherwise consume the injected action failure before the polled copy runs.
	ctx := context.Background()
	sessStream, err := env.plugin.storage.GetSessionStream(ctx, sessionID,
		env.plugin.baseURL, env.plugin.receiverEndpoint, env.plugin.receiverToken)
	if err != nil {
		t.Fatalf("get session stream: %v", err)
	}
	allStreams, err := env.plugin.storage.ListStreams(ctx)
	if err != nil {
		t.Fatalf("list streams: %v", err)
	}
	for i := range allStreams {
		allStreams[i].DeliveryMethod = DeliveryMethodPoll
		if err := env.plugin.storage.UpdateStream(ctx, allStreams[i]); err != nil {
			t.Fatalf("switch stream %s to poll: %v", allStreams[i].ID, err)
		}
	}
	streamID := sessStream.ID

	flaky := &flakyReceiverExecutor{
		ActionExecutor: env.plugin.receiverService.actionExecutor,
		remainingFails: 1,
	}
	env.plugin.receiverService.actionExecutor = flaky
	t.Cleanup(func() { env.plugin.receiverService.actionExecutor = flaky.ActionExecutor })

	status, body := env.doJSON(t, http.MethodPost, "/ssf/actions/credential-compromise", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("trigger %d: %s", status, body)
	}

	poll := func() PollResponse {
		st, raw := env.doJSON(t, http.MethodPost, "/ssf/poll/"+streamID, sessionID, map[string]any{
			"maxEvents":         10,
			"returnImmediately": true,
		})
		if st != http.StatusOK {
			t.Fatalf("poll %d: %s", st, raw)
		}
		var resp PollResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("decode poll: %v", err)
		}
		return resp
	}

	first := poll()
	if len(first.Sets) != 1 {
		t.Fatalf("first poll returned %d sets, want 1", len(first.Sets))
	}
	var jti string
	for k := range first.Sets {
		jti = k
	}

	// The handler auto-processed the polled SET and the mid-plan step failed:
	// the SET must sit at a durable failed retry point, not be marked processed.
	rec, err := env.plugin.storage.GetSETProcessing(context.Background(), jti)
	if err != nil {
		t.Fatalf("processing record: %v", err)
	}
	if rec.Status != SETStatusFailed || rec.ErrorCode != SETErrActionExecutionFailed {
		t.Fatalf("record status=%q code=%q, want failed/action_execution_failed", rec.Status, rec.ErrorCode)
	}
	if len(rec.CompletedSteps) != 1 || rec.CompletedSteps[0] != "e0:force-password-reset" {
		t.Fatalf("steps %v, want only e0:force-password-reset", rec.CompletedSteps)
	}

	// Unacknowledged and failed -> the transmitter MUST retransmit the same jti.
	second := poll()
	if _, ok := second.Sets[jti]; !ok {
		t.Fatalf("failed SET was swallowed: second poll sets=%v, want jti %s retransmitted", second.Sets, jti)
	}

	// The retransmit resumes processing (the handler runs it synchronously):
	// step 1 is not repeated, the failed step now succeeds, the last step runs once.
	force, inval, revoke := flaky.snapshot()
	if force != 1 {
		t.Errorf("force password reset ran %d times, want 1", force)
	}
	if inval != 2 {
		t.Errorf("invalidate tokens ran %d times, want 2 (1 failed + 1 success)", inval)
	}
	if revoke != 1 {
		t.Errorf("revoke sessions ran %d times, want 1", revoke)
	}
	rec, err = env.plugin.storage.GetSETProcessing(context.Background(), jti)
	if err != nil {
		t.Fatalf("reload record: %v", err)
	}
	if rec.Status != SETStatusSucceeded {
		t.Fatalf("post-retransmit status %q, want succeeded", rec.Status)
	}

	// Explicit ack ends retransmission; subsequent polls are empty.
	if st, raw := env.doJSON(t, http.MethodPost, "/ssf/poll/"+streamID, sessionID, map[string]any{
		"ack":               []string{jti},
		"maxEvents":         0,
		"returnImmediately": true,
	}); st != http.StatusOK {
		t.Fatalf("ack %d: %s", st, raw)
	}
	if after := poll(); len(after.Sets) != 0 {
		t.Fatalf("after ack sets=%v, want empty", after.Sets)
	}
}
