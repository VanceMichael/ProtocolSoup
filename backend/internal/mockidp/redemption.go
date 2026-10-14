package mockidp

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// GrantKind identifies a one-time grant during a token exchange.
type GrantKind string

const (
	GrantAuthorizationCode GrantKind = "authorization_code"
	GrantRefreshToken      GrantKind = "refresh_token"
	GrantDeviceCode        GrantKind = "device_code"
)

// GrantPhase identifies a point within token exchange where a controllable
// fault can be injected. Fault injection exists to prove that a one-time
// grant is only consumed after the whole response is prepared; production
// code installs no hook, so every Fault call is a no-op there.
type GrantPhase string

const (
	// GrantPhaseBeforeMint fires before any token is signed, modelling a
	// signer failure that leaves no partial artifacts.
	GrantPhaseBeforeMint GrantPhase = "before_mint"
	// GrantPhaseAfterAccessToken fires after the access token has been signed
	// and tracked, but before the refresh token exists.
	GrantPhaseAfterAccessToken GrantPhase = "after_access_token"
	// GrantPhaseAfterRefreshToken fires after the refresh token has been
	// signed and stored.
	GrantPhaseAfterRefreshToken GrantPhase = "after_refresh_token"
	// GrantPhaseAfterIDToken fires after the OIDC ID token has been signed.
	GrantPhaseAfterIDToken GrantPhase = "after_id_token"
	// GrantPhaseAfterAncillary fires after protocol-specific ancillary state
	// (OID4VCI access/refresh grant context, issuer transaction status) has
	// been prepared.
	GrantPhaseAfterAncillary GrantPhase = "after_ancillary_state"
)

// ErrInjectedFault wraps an error returned by an installed FaultHook, letting
// handlers map any injected failure to the same 500 server_error response they
// use for a genuine signing/state-save failure.
var ErrInjectedFault = errors.New("injected token exchange fault")

// ErrRedemptionLost is returned by Commit when the exchange claim was reaped
// before commit (the holder overran inflightGrantTTL). The partial tokens are
// revoked in that case, so no caller treats this as a successful issuance.
var ErrRedemptionLost = errors.New("token exchange claim was lost before commit")

// FaultHook decides whether an in-progress token exchange fails at a given
// phase. Returning nil lets the exchange continue.
type FaultHook func(kind GrantKind, phase GrantPhase) error

// PartialTokens lists the artifacts minted before an exchange failed. Abort
// revokes every access token and deletes every refresh token listed here so a
// recovered grant can never coexist with usable orphaned artifacts.
type PartialTokens struct {
	AccessTokens  []string
	RefreshTokens []string
}

// inflightGrantTTL bounds how long a claimed grant is held before it may be
// reaped. Signing and in-memory state preparation take milliseconds; this is a
// safety net for a holder goroutine that dies without calling Abort/Commit.
const inflightGrantTTL = 2 * time.Minute

// inflightWaitTTL bounds how long a concurrent redemption waits for the
// current holder to finish before re-checking the claim.
const inflightWaitTTL = 30 * time.Second

// inflightGrant is the per-grant exclusivity marker held while a token
// response is being prepared. Closing done releases every waiter.
type inflightGrant struct {
	started time.Time
	done    chan struct{}
}

// Redemption is a claim on a one-time grant held while the complete token
// response (access token and its tracking, refresh/ID token, replay
// association and protocol ancillary state) is being prepared.
//
// The holder MUST end the exchange with exactly one terminal call:
//   - Commit when the whole response is prepared: the grant is finally
//     consumed;
//   - Reject when a deterministic security check fails after the claim: the
//     grant is consumed without issuing tokens (preserving the prior
//     burn-on-rejection behaviour);
//   - Abort when a transient signing/state-save failure occurs: partial
//     artifacts are revoked/deleted and the grant is restored so a legal
//     retry can succeed.
type Redemption struct {
	idp    *MockIdP
	kind   GrantKind
	key    string
	value  string
	flight *inflightGrant
	once   sync.Once
}

func grantKey(kind GrantKind, value string) string {
	return string(kind) + ":" + value
}

// SetFaultHook installs (or clears, with nil) the test-only fault hook used to
// simulate transient signer/state-save failures at defined exchange phases.
func (idp *MockIdP) SetFaultHook(hook FaultHook) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.faultHook = hook
}

// Fault runs the installed fault hook for an exchange phase. It is a no-op in
// production when no hook is installed.
func (idp *MockIdP) Fault(kind GrantKind, phase GrantPhase) error {
	idp.mu.RLock()
	hook := idp.faultHook
	idp.mu.RUnlock()
	if hook == nil {
		return nil
	}
	if err := hook(kind, phase); err != nil {
		return fmt.Errorf("%w: %s/%s: %v", ErrInjectedFault, kind, phase, err)
	}
	return nil
}

// acquireGrant serializes exchanges of one grant value: it claims key or waits
// for the current holder to finish, then tries again.
func (idp *MockIdP) acquireGrant(key string) *inflightGrant {
	for {
		idp.mu.Lock()
		flight, holder := idp.tryAcquireGrantLocked(key)
		idp.mu.Unlock()
		if flight != nil {
			return flight
		}
		timer := time.NewTimer(inflightWaitTTL)
		select {
		case <-holder.done:
		case <-timer.C:
			// Re-check under lock; an expired claim is reaped there.
		}
		timer.Stop()
	}
}

// tryAcquireGrantLocked claims key and returns the fresh marker, or returns
// the live holder to wait on. The caller must hold idp.mu.
func (idp *MockIdP) tryAcquireGrantLocked(key string) (*inflightGrant, *inflightGrant) {
	if holder, busy := idp.inflight[key]; busy {
		if time.Since(holder.started) <= inflightGrantTTL {
			return nil, holder
		}
		// Previous holder is presumed dead; reap its stale claim.
		close(holder.done)
	}
	fresh := &inflightGrant{started: time.Now(), done: make(chan struct{})}
	idp.inflight[key] = fresh
	return fresh, nil
}

func (idp *MockIdP) ownsGrant(key string, flight *inflightGrant) bool {
	return idp.inflight[key] == flight
}

// finishGrantLocked releases the claim and wakes waiters. The caller must hold
// idp.mu. The grant's own record is untouched here; callers mutate it first.
func (idp *MockIdP) finishGrantLocked(key string, flight *inflightGrant) {
	if idp.inflight[key] != flight {
		return
	}
	delete(idp.inflight, key)
	close(flight.done)
}

func (idp *MockIdP) newRedemption(kind GrantKind, value string, flight *inflightGrant) *Redemption {
	return &Redemption{idp: idp, kind: kind, key: grantKey(kind, value), value: value, flight: flight}
}

// accessJTIsOf resolves the JTI of each supplied access token. ValidateToken
// touches no IdP state, so it is safe to call without idp.mu held.
func (idp *MockIdP) accessJTIsOf(tokens []string) []string {
	jtis := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if strings.TrimSpace(token) == "" {
			continue
		}
		jti := token
		if claims, err := idp.jwtService.ValidateToken(token); err == nil {
			if v, ok := claims["jti"].(string); ok && v != "" {
				jti = v
			}
		}
		jtis = append(jtis, jti)
	}
	return jtis
}

// revokePartialTokensLocked revokes partial access tokens (both the RFC 7009
// revocation set and CAEP subject tracking) and deletes partial refresh
// tokens, leaving no orphaned usable state. The caller must hold idp.mu.
func (idp *MockIdP) revokePartialTokensLocked(accessJTIs, refreshTokens []string) {
	now := time.Now()
	for _, jti := range accessJTIs {
		if jti == "" {
			continue
		}
		idp.revokedTokens[jti] = now
		for userID, tracked := range idp.accessJTIsByUser {
			kept := tracked[:0]
			for _, trackedJTI := range tracked {
				if trackedJTI != jti {
					kept = append(kept, trackedJTI)
				}
			}
			if len(kept) == 0 {
				delete(idp.accessJTIsByUser, userID)
			} else {
				idp.accessJTIsByUser[userID] = kept
			}
		}
	}
	for _, refreshToken := range refreshTokens {
		if refreshToken != "" {
			delete(idp.refreshTokens, refreshToken)
		}
	}
}

// Commit finally consumes the grant only after the complete response is
// prepared: an authorization code is deleted and its replay association
// records the exact tokens minted (RFC 6749 Section 4.1.2), a rotating refresh
// token is deleted, a device authorization is marked consumed.
//
// If the claim was reaped before commit, the supplied tokens are revoked
// instead and ErrRedemptionLost is returned so the caller cannot report a
// successful issuance.
func (r *Redemption) Commit(tokens PartialTokens) error {
	accessJTIs := r.idp.accessJTIsOf(tokens.AccessTokens)
	committed := false
	r.once.Do(func() {
		idp := r.idp
		idp.mu.Lock()
		defer idp.mu.Unlock()
		if !idp.ownsGrant(r.key, r.flight) {
			idp.revokePartialTokensLocked(accessJTIs, tokens.RefreshTokens)
			return
		}
		switch r.kind {
		case GrantAuthorizationCode:
			delete(idp.authCodes, r.value)
			idp.usedCodes[r.value] = &usedAuthorizationCode{
				accessTokenJTIs: append([]string(nil), accessJTIs...),
				refreshTokens:   append([]string(nil), tokens.RefreshTokens...),
				usedAt:          time.Now(),
			}
		case GrantRefreshToken:
			delete(idp.refreshTokens, r.value)
		case GrantDeviceCode:
			if auth := idp.deviceAuthByCode[r.value]; auth != nil {
				auth.Status = DeviceAuthConsumed
			}
		}
		idp.finishGrantLocked(r.key, r.flight)
		committed = true
	})
	if !committed {
		return ErrRedemptionLost
	}
	return nil
}

// Reject consumes the grant without issuing any tokens after a deterministic
// security rejection (for example a code bound to a different DPoP key, or a
// credential subset that exceeds authorization). This preserves the previous
// behaviour where such rejections burn the presented grant; it is distinct
// from Abort, which restores the grant for a legal retry after a transient
// failure.
func (r *Redemption) Reject() {
	r.once.Do(func() {
		idp := r.idp
		idp.mu.Lock()
		defer idp.mu.Unlock()
		if !idp.ownsGrant(r.key, r.flight) {
			return
		}
		switch r.kind {
		case GrantAuthorizationCode:
			delete(idp.authCodes, r.value)
			idp.usedCodes[r.value] = &usedAuthorizationCode{usedAt: time.Now()}
		case GrantRefreshToken:
			delete(idp.refreshTokens, r.value)
		case GrantDeviceCode:
			if auth := idp.deviceAuthByCode[r.value]; auth != nil {
				auth.Status = DeviceAuthConsumed
			}
		}
		idp.finishGrantLocked(r.key, r.flight)
	})
}

// Abort revokes/deletes every partial artifact and restores the grant: the
// code, refresh token or authorized device record was never mutated while the
// claim was held, so simply releasing the claim makes a legal retry possible.
func (r *Redemption) Abort(tokens PartialTokens) {
	accessJTIs := r.idp.accessJTIsOf(tokens.AccessTokens)
	r.once.Do(func() {
		idp := r.idp
		idp.mu.Lock()
		defer idp.mu.Unlock()
		if !idp.ownsGrant(r.key, r.flight) {
			return
		}
		idp.revokePartialTokensLocked(accessJTIs, tokens.RefreshTokens)
		// The grant record itself was never consumed; release restores it.
		idp.finishGrantLocked(r.key, r.flight)
	})
}

// BeginAuthorizationCodeRedemption validates every binding on the code
// (replay/expiry, client, redirect_uri, PKCE) and claims it exclusively, but
// does NOT consume it. Consumption happens only when the returned Redemption
// is Committed after the complete token response is prepared.
//
// Concurrent redemptions of the same code are serialized at the claim: a
// waiter either finds the code restored after an Abort (and may then redeem
// it) or already committed, in which case it gets the existing replay error
// and, per RFC 6749 Section 4.1.2, revokes the tokens previously issued.
func (idp *MockIdP) BeginAuthorizationCodeRedemption(code, clientID, redirectURI, codeVerifier string) (*models.AuthorizationCode, *Redemption, error) {
	code = strings.TrimSpace(code)
	flight := idp.acquireGrant(grantKey(GrantAuthorizationCode, code))

	idp.mu.Lock()
	authCode, err := idp.validateAuthorizationCodeLocked(code, clientID, redirectURI, codeVerifier)
	if err != nil {
		idp.finishGrantLocked(grantKey(GrantAuthorizationCode, code), flight)
		idp.mu.Unlock()
		return nil, nil, err
	}
	idp.mu.Unlock()
	return authCode, idp.newRedemption(GrantAuthorizationCode, code, flight), nil
}

// validateAuthorizationCodeLocked performs every pre-redemption check on an
// authorization code without consuming it. It preserves the replay side
// effects: a code in usedCodes revokes the tokens previously minted from it
// (RFC 6749 Section 4.1.2). The caller must hold idp.mu.
func (idp *MockIdP) validateAuthorizationCodeLocked(code, clientID, redirectURI, codeVerifier string) (*models.AuthorizationCode, error) {
	idp.pruneUsedCodesLocked()

	authCode, exists := idp.authCodes[code]
	if !exists {
		// RFC 6749 Section 4.1.2: an authorization code presented more than once
		// MUST be denied, and the OP SHOULD revoke the tokens it previously issued
		// from that code.
		if used, replayed := idp.usedCodes[code]; replayed {
			for _, jti := range used.accessTokenJTIs {
				idp.revokedTokens[jti] = time.Now()
			}
			for _, rt := range used.refreshTokens {
				delete(idp.refreshTokens, rt)
			}
			return nil, errors.New("authorization code already used")
		}
		return nil, errors.New("invalid authorization code")
	}

	// Reject expired codes (RFC 6749 §4.1.2; FAPI2 SP Final §5.3.2.1-11).
	if !authCode.ExpiresAt.After(time.Now()) {
		delete(idp.authCodes, code)
		return nil, errors.New("authorization code expired")
	}

	// Bind the code to the issuing client and redirect_uri before redemption.
	// A mismatch must not burn the legitimate client's code (OIDCC §3.1.3.4).
	if authCode.ClientID != clientID {
		return nil, errors.New("client ID mismatch")
	}

	if authCode.RedirectURI != redirectURI {
		return nil, errors.New("redirect URI mismatch")
	}

	// Validate PKCE if code challenge was provided (RFC 7636).
	if authCode.CodeChallenge != "" {
		if err := ValidatePKCEWithError(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			return nil, err
		}
	}

	copy := *authCode
	copy.CredentialConfigurationIDs = append([]string(nil), authCode.CredentialConfigurationIDs...)
	return &copy, nil
}

// BeginRefreshTokenRedemption validates a rotating refresh token (existence,
// expiry, client binding) and claims it exclusively without deleting it. The
// old token is only deleted when Redemption.Commit is called after the new
// response is fully prepared; Abort leaves it valid for a legal retry.
func (idp *MockIdP) BeginRefreshTokenRedemption(token, clientID string) (*models.RefreshToken, *Redemption, error) {
	token = strings.TrimSpace(token)
	flight := idp.acquireGrant(grantKey(GrantRefreshToken, token))

	idp.mu.Lock()
	rt, err := idp.validateRefreshTokenLocked(token, clientID)
	if err != nil {
		idp.finishGrantLocked(grantKey(GrantRefreshToken, token), flight)
		idp.mu.Unlock()
		return nil, nil, err
	}
	idp.mu.Unlock()
	return rt, idp.newRedemption(GrantRefreshToken, token, flight), nil
}

// validateRefreshTokenLocked validates a refresh token without rotating
// (deleting) it. The caller must hold idp.mu.
func (idp *MockIdP) validateRefreshTokenLocked(token, clientID string) (*models.RefreshToken, error) {
	rt, exists := idp.refreshTokens[token]
	if !exists {
		return nil, errors.New("invalid refresh token")
	}

	if rt.ExpiresAt.Before(time.Now()) {
		delete(idp.refreshTokens, token)
		return nil, errors.New("refresh token expired")
	}

	if rt.ClientID != clientID {
		return nil, errors.New("client ID mismatch")
	}

	copy := *rt
	return &copy, nil
}

// BeginDeviceCodeRedemption evaluates an RFC 8628 token poll. When the device
// authorization is authorized it is claimed exclusively WITHOUT being marked
// consumed: the caller prepares the token response and then Commits, or Aborts
// (leaving the authorization authorized for a legal retry). Non-terminal
// outcomes (authorization_pending, slow_down, access_denied, expired_token,
// client mismatch, unknown/consumed) claim nothing.
func (idp *MockIdP) BeginDeviceCodeRedemption(deviceCode, clientID string, now time.Time) (DevicePollOutcome, *DeviceAuthorization, *Redemption) {
	key := grantKey(GrantDeviceCode, deviceCode)
	for {
		idp.mu.Lock()
		outcome, auth := idp.evaluateDevicePollLocked(deviceCode, clientID, now)
		if outcome != DevicePollAuthorized {
			idp.mu.Unlock()
			return outcome, auth, nil
		}
		flight, holder := idp.tryAcquireGrantLocked(key)
		if holder == nil {
			idp.mu.Unlock()
			return outcome, auth, idp.newRedemption(GrantDeviceCode, deviceCode, flight)
		}
		// An exchange for this authorized device code is in flight; wait for
		// it to commit or abort, then re-evaluate without holding the lock.
		idp.mu.Unlock()
		timer := time.NewTimer(inflightWaitTTL)
		select {
		case <-holder.done:
		case <-timer.C:
		}
		timer.Stop()
	}
}
