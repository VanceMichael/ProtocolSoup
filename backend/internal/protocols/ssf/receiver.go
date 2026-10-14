package ssf

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// ====================
// Shared Types (used by ReceiverService and handlers)
// ====================

// ReceivedEvent represents an event received by the receiver
type ReceivedEvent struct {
	ID             string      `json:"id"`
	ReceivedAt     time.Time   `json:"received_at"`
	DeliveryMethod string      `json:"delivery_method"`
	SET            *DecodedSET `json:"set"`
	Verified       bool        `json:"verified"`
	VerifyError    string      `json:"verify_error,omitempty"`
	Processed      bool        `json:"processed"`
	ProcessedAt    *time.Time  `json:"processed_at,omitempty"`
}

// ResponseAction represents an automated response action taken
type ResponseAction struct {
	ID          string    `json:"id"`
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	ExecutedAt  time.Time `json:"executed_at"`
	SessionID   string    `json:"session_id,omitempty"`
}

// Response action status
const (
	ResponseStatusExecuted      = "executed"
	ResponseStatusPending       = "pending"
	ResponseStatusFailed        = "failed"
	ResponseStatusLogged        = "logged"
	ResponseStatusNotApplicable = "not_applicable"
)

// ReceiverEvent represents events in the receiver pipeline
type ReceiverEvent struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	EventID   string      `json:"event_id"`
	SessionID string      `json:"session_id,omitempty"`
	Data      interface{} `json:"data"`
}

// Receiver event types
const (
	ReceiverEventReceived       = "event_received"
	ReceiverEventVerified       = "event_verified"
	ReceiverEventVerifyFailed   = "event_verify_failed"
	ReceiverEventProcessing     = "event_processing"
	ReceiverEventProcessed      = "event_processed"
	ReceiverEventResponseAction = "response_action"
	ReceiverEventHTTPExchange   = "http_exchange"
)

// SetStatus represents the processing status of a SET
type SetStatus struct {
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
	Err         string `json:"err,omitempty"` // RFC 8935 §2.4 / RFC 8936 §2.4 err keyword
	// HTTPStatus is the push-delivery status a retryable processing failure maps to.
	// Validation failures keep the default 400 via handlePush. Not serialized on poll.
	HTTPStatus int `json:"-"`
}

func failedSET(errCode, description string) SetStatus {
	return SetStatus{Status: "failed", Description: description, Err: errCode}
}

// retryableFailedSET is a failure that preserves the SET for deterministic retry:
// push MUST NOT answer 202 (it answers httpStatus instead) and poll MUST NOT treat
// the SET as confirmable, so it stays unacknowledged and is re-delivered.
func retryableFailedSET(errCode, description string, httpStatus int) SetStatus {
	return SetStatus{Status: "failed", Description: description, Err: errCode, HTTPStatus: httpStatus}
}

// PollRequest represents an SSF poll request (RFC 8936 §2).
// maxEvents 0 is acknowledge-only. Omitted maxEvents defaults at the handler.
type PollRequest struct {
	Ack               []string           `json:"ack,omitempty"`
	SetErrs           map[string]SETError `json:"setErrs,omitempty"`
	MaxEvents         *int               `json:"maxEvents,omitempty"`
	ReturnImmediately *bool              `json:"returnImmediately,omitempty"`
}

// SETError is an RFC 8936 §2.4 setErrs entry.
type SETError struct {
	Err         string `json:"err"`
	Description string `json:"description,omitempty"`
}

// PollResponse represents an SSF poll response (RFC 8936 §2)
type PollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

// ====================
// Shared Event Processing (used by ReceiverService)
// ====================

// Retryable SET processing error codes returned to push/pop deliveries.
const (
	SETErrActionExecutionFailed  = "action_execution_failed"
	SETErrFederationRevokeFailed = "federation_revoke_failed"
	SETErrProcessingInProgress   = "processing_in_progress"
	SETErrStorageUnavailable     = "storage_unavailable"
)

// mutationStep is one side effect of a SET that can be executed, durably marked,
// and individually resumed. Key is stable across retries. Steps run in order and
// stop at the first error.
type mutationStep struct {
	Key     string
	Label   string
	ErrCode string
	run     func(ctx context.Context) error
}

// planMutationSteps builds the ordered, idempotently-retryable mutation plan for
// one decoded event. The federation revoke-subject hop of session-revoked is
// appended separately by the ReceiverService (only when a federation peer is
// configured). Returns nil for events without RP-state mutations.
func planMutationSteps(executor ActionExecutor, eventIndex int, event DecodedEvent, subjectEmail, sessionID string, subject *SETSubject) []mutationStep {
	if executor == nil || subjectEmail == "" {
		return nil
	}

	key := func(name string) string {
		return fmt.Sprintf("e%d:%s", eventIndex, name)
	}

	switch event.Type {
	case EventTypeSessionRevoked:
		return []mutationStep{{
			Key:     key("revoke-sessions"),
			Label:   "Revoke sessions",
			ErrCode: SETErrActionExecutionFailed,
			run: func(ctx context.Context) error {
				log.Printf("[SSF Receiver] Executing: Revoke sessions for %s (session: %s)", subjectEmail, sessionID)
				return executor.RevokeUserSessionsForSession(ctx, sessionID, subjectEmail)
			},
		}}
	case EventTypeAccountDisabled:
		return []mutationStep{{
			Key:     key("disable-user"),
			Label:   "Disable user",
			ErrCode: SETErrActionExecutionFailed,
			run: func(ctx context.Context) error {
				log.Printf("[SSF Receiver] Executing: Disable user %s (session: %s)", subjectEmail, sessionID)
				return executor.DisableUserForSession(ctx, sessionID, subjectEmail)
			},
		}}
	case EventTypeAccountEnabled:
		return []mutationStep{{
			Key:     key("enable-user"),
			Label:   "Enable user",
			ErrCode: SETErrActionExecutionFailed,
			run: func(ctx context.Context) error {
				log.Printf("[SSF Receiver] Executing: Enable user %s (session: %s)", subjectEmail, sessionID)
				return executor.EnableUserForSession(ctx, sessionID, subjectEmail)
			},
		}}
	case EventTypeCredentialCompromise, EventTypeAccountCredentialChangeRequired:
		// Three sequential containment steps; each is its own retry checkpoint.
		return []mutationStep{
			{
				Key:     key("force-password-reset"),
				Label:   "Force password reset",
				ErrCode: SETErrActionExecutionFailed,
				run: func(ctx context.Context) error {
					log.Printf("[SSF Receiver] Executing: Force password reset for %s (session: %s)", subjectEmail, sessionID)
					return executor.ForcePasswordResetForSession(ctx, sessionID, subjectEmail)
				},
			},
			{
				Key:     key("invalidate-tokens"),
				Label:   "Invalidate tokens",
				ErrCode: SETErrActionExecutionFailed,
				run: func(ctx context.Context) error {
					log.Printf("[SSF Receiver] Executing: Invalidate tokens for %s (session: %s)", subjectEmail, sessionID)
					return executor.InvalidateTokensForSession(ctx, sessionID, subjectEmail)
				},
			},
			{
				Key:     key("revoke-sessions"),
				Label:   "Revoke sessions",
				ErrCode: SETErrActionExecutionFailed,
				run: func(ctx context.Context) error {
					log.Printf("[SSF Receiver] Executing: Revoke sessions for %s (session: %s)", subjectEmail, sessionID)
					return executor.RevokeUserSessionsForSession(ctx, sessionID, subjectEmail)
				},
			},
		}
	case EventTypeCredentialChange:
		return []mutationStep{{
			Key:     key("invalidate-tokens"),
			Label:   "Invalidate tokens",
			ErrCode: SETErrActionExecutionFailed,
			run: func(ctx context.Context) error {
				log.Printf("[SSF Receiver] Executing: Invalidate tokens for %s (session: %s)", subjectEmail, sessionID)
				return executor.InvalidateTokensForSession(ctx, sessionID, subjectEmail)
			},
		}}
	case EventTypeAccountPurged:
		return []mutationStep{{
			Key:     key("disable-user"),
			Label:   "Disable and purge user",
			ErrCode: SETErrActionExecutionFailed,
			run: func(ctx context.Context) error {
				log.Printf("[SSF Receiver] Executing: Disable and revoke for purged %s (session: %s)", subjectEmail, sessionID)
				return executor.DisableUserForSession(ctx, sessionID, subjectEmail)
			},
		}}
	case EventTypeDeviceComplianceChange:
		deviceID := ""
		if subject != nil {
			deviceID = subject.DeviceSubject()
		}
		return []mutationStep{{
			Key:     key("device-compliance"),
			Label:   "Apply device compliance",
			ErrCode: SETErrActionExecutionFailed,
			run: func(ctx context.Context) error {
				log.Printf("[SSF Receiver] Executing: Device compliance for %s device=%s (session: %s)", subjectEmail, deviceID, sessionID)
				return executor.ApplyDeviceComplianceForSession(ctx, sessionID, subjectEmail, deviceID, event.Payload.CurrentStatus)
			},
		}}
	default:
		return nil
	}
}

// buildResponseActions builds the display-only action rows for an event from its
// metadata. mutated/mutateErr describe the outcome of the event's mutation plan.
// Generic descriptions (alert security team, re-evaluate policy) are logged or
// not_applicable; only RP-state mutations are marked executed/failed.
func buildResponseActions(eventID string, event DecodedEvent, sessionID string, mutated bool, mutateErr error) []ResponseAction {
	var actions []ResponseAction
	primaryMarked := false
	for i, actionDesc := range event.Metadata.ResponseActions {
		status := actionStatusForDescription(actionDesc)
		if mutated && isPrimaryMutationAction(actionDesc) && !primaryMarked {
			if mutateErr != nil {
				status = ResponseStatusFailed
			} else {
				status = ResponseStatusExecuted
			}
			primaryMarked = true
		}

		actions = append(actions, ResponseAction{
			ID:          fmt.Sprintf("%s-action-%d", eventID, i),
			EventID:     eventID,
			EventType:   event.Type,
			Action:      actionDesc,
			Description: fmt.Sprintf("Automated response: %s (session: %s)", actionDesc, sessionID),
			Status:      status,
			ExecutedAt:  time.Now(),
			SessionID:   sessionID,
		})
	}
	return actions
}

// ExecuteResponseActions executes security response actions for a decoded event
// and returns its display rows. The durable, resumable processing path lives in
// ReceiverService.processSET; this helper is retained for callers that execute a
// plan without SET-processing persistence. Steps stop at the first error.
func ExecuteResponseActions(executor ActionExecutor, eventID string, event DecodedEvent, subjectEmail, sessionID string, subject *SETSubject) []ResponseAction {
	steps := planMutationSteps(executor, 0, event, subjectEmail, sessionID, subject)
	var mutateErr error
	for _, step := range steps {
		if mutateErr = step.run(context.Background()); mutateErr != nil {
			log.Printf("[SSF Receiver] Action failed at step %s: %v", step.Key, mutateErr)
			break
		}
	}
	return buildResponseActions(eventID, event, sessionID, len(steps) > 0, mutateErr)
}

func isPrimaryMutationAction(desc string) bool {
	lower := strings.ToLower(desc)
	return containsAnyOf(lower, "terminate") ||
		containsAnyOf(lower, "disable") ||
		containsAnyOf(lower, "suspend") ||
		containsAnyOf(lower, "enable", "reactivate") ||
		containsAnyOf(lower, "password") ||
		(containsAnyOf(lower, "revoke") && containsAnyOf(lower, "token")) ||
		(containsAnyOf(lower, "invalidate") && containsAnyOf(lower, "token")) ||
		containsAnyOf(lower, "restrict network")
}

func actionStatusForDescription(desc string) string {
	lower := strings.ToLower(desc)
	if containsAnyOf(lower, "alert", "notify", "mfa", "quarantine", "isolate", "archive", "audit") {
		return ResponseStatusNotApplicable
	}
	return ResponseStatusLogged
}

// containsAnyOf checks if the already-lowered string s contains any of the substrings.
func containsAnyOf(sLower string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(sLower, sub) {
			return true
		}
	}
	return false
}

// truncateToken returns a truncated preview of a token
