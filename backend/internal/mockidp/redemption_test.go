package mockidp

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
)

// redemptionTestEnv bundles a fresh IdP with the constants the grant tests use.
type redemptionTestEnv struct {
	idp      *MockIdP
	clientID string
	redirect string
	scope    string
}

func newRedemptionTestEnv(t *testing.T) *redemptionTestEnv {
	t.Helper()
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	idp.SetIssuer("https://op.example.com")
	return &redemptionTestEnv{idp: idp, clientID: "public-app", redirect: "http://localhost:3000/callback", scope: "openid profile"}
}

func (e *redemptionTestEnv) createCode(t *testing.T) string {
	t.Helper()
	code, err := e.idp.CreateAuthorizationCode(e.clientID, "alice", e.redirect, e.scope, "", "", "", "", "", time.Now())
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	return code.Code
}

// mintExchangeTokens signs the same artifacts the protocol handlers mint and
// records their partial cleanup set. Safe to invoke from the test goroutine.
func (e *redemptionTestEnv) mintExchangeTokens(t *testing.T, userID string) PartialTokens {
	t.Helper()
	tokens, err := e.mintTokens(userID)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

// mintToken is the fatal-free variant used from contender goroutines.
func (e *redemptionTestEnv) mintTokens(userID string) (PartialTokens, error) {
	jwt := e.idp.JWTService()
	access, err := jwt.CreateAccessToken(userID, e.clientID, e.scope, time.Hour, nil)
	if err != nil {
		return PartialTokens{}, err
	}
	refresh, err := jwt.CreateRefreshToken(userID, e.clientID, e.scope, time.Hour)
	if err != nil {
		return PartialTokens{}, err
	}
	e.idp.TrackAccessToken(userID, access)
	e.idp.StoreRefreshToken(refresh, e.clientID, userID, e.scope, time.Now(), time.Now().Add(time.Hour))
	return PartialTokens{AccessTokens: []string{access}, RefreshTokens: []string{refresh}}, nil
}

func assertInflightEmpty(t *testing.T, idp *MockIdP) {
	t.Helper()
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	if len(idp.inflight) != 0 {
		t.Fatalf("inflight claims leaked: %d remaining", len(idp.inflight))
	}
}

func assertCodeLive(t *testing.T, idp *MockIdP, code string) {
	t.Helper()
	if _, ok := idp.GetAuthorizationCode(code); !ok {
		t.Fatal("grant must remain redeemable after abort, but it is gone")
	}
}

func assertCodeConsumed(t *testing.T, idp *MockIdP, code, accessJTI, refreshToken string) {
	t.Helper()
	if _, ok := idp.GetAuthorizationCode(code); ok {
		t.Fatal("grant must be consumed after commit")
	}
	idp.mu.RLock()
	used := idp.usedCodes[code]
	idp.mu.RUnlock()
	if used == nil {
		t.Fatal("committed code has no replay record")
	}
	if accessJTI != "" && (len(used.accessTokenJTIs) != 1 || used.accessTokenJTIs[0] != accessJTI) {
		t.Fatalf("replay record JTIs = %#v, want [%s]", used.accessTokenJTIs, accessJTI)
	}
	if refreshToken != "" && (len(used.refreshTokens) != 1 || used.refreshTokens[0] != refreshToken) {
		t.Fatalf("replay record refresh tokens = %#v, want [%s]", used.refreshTokens, refreshToken)
	}
}

// A failure before any artifact exists leaves the code directly retryable and
// records no orphaned state.
func TestAuthCodeAbortBeforeMintRestoresGrant(t *testing.T) {
	env := newRedemptionTestEnv(t)
	code := env.createCode(t)

	_, redemption, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Simulated signer failure with no tokens minted yet.
	redemption.Abort(PartialTokens{})

	assertCodeLive(t, env.idp, code)
	assertInflightEmpty(t, env.idp)
	env.idp.mu.RLock()
	used := len(env.idp.usedCodes)
	tracked := len(env.idp.revokedTokens)
	env.idp.mu.RUnlock()
	if used != 0 || tracked != 0 {
		t.Fatalf("abort before mint left state: usedCodes=%d revoked=%d", used, tracked)
	}

	// Legal retry succeeds end to end.
	authCode, redemption2, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
	if err != nil {
		t.Fatalf("retry Begin: %v", err)
	}
	tokens := env.mintExchangeTokens(t, authCode.UserID)
	if err := redemption2.Commit(tokens); err != nil {
		t.Fatalf("retry Commit: %v", err)
	}
	jti := env.idp.accessJTIsOf(tokens.AccessTokens)[0]
	assertCodeConsumed(t, env.idp, code, jti, tokens.RefreshTokens[0])
	if env.idp.IsTokenRevoked(tokens.AccessTokens[0]) {
		t.Fatal("successfully issued access token must not be revoked")
	}
	assertInflightEmpty(t, env.idp)
}

// A failure after the access token was signed and tracked revokes it, removes
// its tracking and still restores the code for a legal retry.
func TestAuthCodeAbortAfterAccessTokenRevokesPartial(t *testing.T) {
	env := newRedemptionTestEnv(t)
	code := env.createCode(t)

	authCode, redemption, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	jwt := env.idp.JWTService()
	partialAccess, err := jwt.CreateAccessToken(authCode.UserID, env.clientID, env.scope, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	env.idp.TrackAccessToken(authCode.UserID, partialAccess)
	partial := PartialTokens{AccessTokens: []string{partialAccess}}
	partialJTI := env.idp.accessJTIsOf(partial.AccessTokens)[0]

	redemption.Abort(partial)

	if !env.idp.IsTokenRevoked(partialAccess) {
		t.Fatal("partial access token must be revoked after abort")
	}
	env.idp.mu.RLock()
	for _, jtis := range env.idp.accessJTIsByUser {
		for _, jti := range jtis {
			if jti == partialJTI {
				t.Fatal("partial access token JTI must be removed from subject tracking")
			}
		}
	}
	env.idp.mu.RUnlock()
	assertCodeLive(t, env.idp, code)

	// Retry succeeds and the fresh access token is usable; the revoked one
	// stays revoked.
	_, redemption2, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
	if err != nil {
		t.Fatalf("retry Begin: %v", err)
	}
	retryTokens := env.mintExchangeTokens(t, authCode.UserID)
	if err := redemption2.Commit(retryTokens); err != nil {
		t.Fatalf("retry Commit: %v", err)
	}
	if env.idp.IsTokenRevoked(retryTokens.AccessTokens[0]) {
		t.Fatal("retry access token must not be revoked")
	}
	if !env.idp.IsTokenRevoked(partialAccess) {
		t.Fatal("failed access token must remain revoked")
	}
	if _, ok := env.idp.GetRefreshToken(retryTokens.RefreshTokens[0]); !ok {
		t.Fatal("retry refresh token must be stored")
	}
}

// A failure after the refresh token was stored deletes it as well and leaves
// the code redeemable.
func TestAuthCodeAbortAfterRefreshTokenDeletesPartial(t *testing.T) {
	env := newRedemptionTestEnv(t)
	code := env.createCode(t)

	authCode, redemption, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	tokens := env.mintExchangeTokens(t, authCode.UserID)
	redemption.Abort(tokens)

	if _, ok := env.idp.GetRefreshToken(tokens.RefreshTokens[0]); ok {
		t.Fatal("partial refresh token must be deleted after abort")
	}
	if !env.idp.IsTokenRevoked(tokens.AccessTokens[0]) {
		t.Fatal("partial access token must be revoked after abort")
	}
	assertCodeLive(t, env.idp, code)

	_, redemption2, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
	if err != nil {
		t.Fatalf("retry Begin: %v", err)
	}
	retry := env.mintExchangeTokens(t, authCode.UserID)
	if err := redemption2.Commit(retry); err != nil {
		t.Fatalf("retry Commit: %v", err)
	}
	if _, ok := env.idp.GetRefreshToken(tokens.RefreshTokens[0]); ok {
		t.Fatal("aborted refresh token must not reappear after retry")
	}
	assertCodeConsumed(t, env.idp, code, env.idp.accessJTIsOf(retry.AccessTokens)[0], retry.RefreshTokens[0])
}

// Refresh-token rotation: the old token stays valid through a failed rotation
// and is deleted only on commit; reuse afterwards follows the existing
// invalid_grant rule.
func TestRefreshTokenRotationIsTransactional(t *testing.T) {
	env := newRedemptionTestEnv(t)
	authTime := time.Now().Add(-time.Hour).Truncate(time.Second)
	old := "old-refresh-token"
	env.idp.StoreRefreshToken(old, env.clientID, "alice", env.scope, authTime, time.Now().Add(time.Hour))

	rt, redemption, err := env.idp.BeginRefreshTokenRedemption(old, env.clientID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if !rt.AuthTime.Equal(authTime) {
		t.Fatalf("auth time = %v, want %v", rt.AuthTime, authTime)
	}
	// Mid-rotation failure after the replacement refresh token was stored.
	tokens := env.mintExchangeTokens(t, rt.UserID)
	redemption.Abort(tokens)

	if _, ok := env.idp.GetRefreshToken(old); !ok {
		t.Fatal("old refresh token must remain valid after aborted rotation")
	}
	if _, ok := env.idp.GetRefreshToken(tokens.RefreshTokens[0]); ok {
		t.Fatal("partial replacement refresh token must be deleted")
	}
	if !env.idp.IsTokenRevoked(tokens.AccessTokens[0]) {
		t.Fatal("partial access token must be revoked")
	}

	// Legal retry rotates successfully.
	rt2, redemption2, err := env.idp.BeginRefreshTokenRedemption(old, env.clientID)
	if err != nil {
		t.Fatalf("retry Begin: %v", err)
	}
	retry := env.mintExchangeTokens(t, rt2.UserID)
	if err := redemption2.Commit(retry); err != nil {
		t.Fatalf("retry Commit: %v", err)
	}
	if _, ok := env.idp.GetRefreshToken(old); ok {
		t.Fatal("old refresh token must be deleted after committed rotation")
	}
	if _, ok := env.idp.GetRefreshToken(retry.RefreshTokens[0]); !ok {
		t.Fatal("rotated refresh token must be stored")
	}
	// Existing rule: reusing the rotated value is still invalid_grant.
	if _, _, err := env.idp.BeginRefreshTokenRedemption(old, env.clientID); err == nil ||
		err.Error() != "invalid refresh token" {
		t.Fatalf("reused rotated token err = %v, want invalid refresh token", err)
	}
	assertInflightEmpty(t, env.idp)
}

// Device authorization: a token failure after the access token exists revokes
// it and leaves the authorization authorized so the device can poll again;
// only commit marks it consumed.
func TestDeviceCodeFailureRestoresAuthorizedState(t *testing.T) {
	env := newRedemptionTestEnv(t)
	now := time.Now()
	auth, err := env.idp.CreateDeviceAuthorization(env.clientID, env.scope, "sess", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.idp.AuthorizeDeviceAuthorization(auth.UserCode, "alice", now); err != nil {
		t.Fatalf("AuthorizeDeviceAuthorization: %v", err)
	}

	outcome, claim, redemption := env.idp.BeginDeviceCodeRedemption(auth.DeviceCode, env.clientID, now)
	if outcome != DevicePollAuthorized || claim == nil || redemption == nil {
		t.Fatalf("first begin outcome = %v, want authorized", outcome)
	}
	tokens := env.mintExchangeTokens(t, claim.UserID)
	redemption.Abort(tokens)

	if !env.idp.IsTokenRevoked(tokens.AccessTokens[0]) {
		t.Fatal("partial device access token must be revoked")
	}
	peek := env.idp.PeekDeviceAuthorizationByUserCode(auth.UserCode)
	if peek == nil || peek.Status != DeviceAuthAuthorized {
		t.Fatalf("device authorization after abort = %#v, want authorized", peek)
	}

	outcome, claim, redemption = env.idp.BeginDeviceCodeRedemption(auth.DeviceCode, env.clientID, now)
	if outcome != DevicePollAuthorized || redemption == nil {
		t.Fatalf("retry poll outcome = %v, want authorized", outcome)
	}
	retry := env.mintExchangeTokens(t, claim.UserID)
	if err := redemption.Commit(retry); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if env.idp.IsTokenRevoked(retry.AccessTokens[0]) {
		t.Fatal("committed device access token must be usable")
	}
	outcome, _, _ = env.idp.BeginDeviceCodeRedemption(auth.DeviceCode, env.clientID, now)
	if outcome != DevicePollConsumed {
		t.Fatalf("reuse after commit outcome = %v, want consumed", outcome)
	}
	assertInflightEmpty(t, env.idp)
}

// Concurrent redemption of one code: exactly one exchange commits, every loser
// observes the existing replay rejection, and exactly one token set is ever
// recorded. The code ends consumed with the winner's tokens replay-revoked per
// RFC 6749 Section 4.1.2.
func TestConcurrentAuthCodeRedemptionCommitsExactlyOnce(t *testing.T) {
	env := newRedemptionTestEnv(t)
	code := env.createCode(t)

	const contenders = 16
	start := make(chan struct{})
	var successes, replayRejects, otherErrors int64
	var winnerMu sync.Mutex
	var winnerTokens PartialTokens
	var wg sync.WaitGroup

	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			authCode, redemption, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
			if err != nil {
				if err.Error() == "authorization code already used" {
					atomic.AddInt64(&replayRejects, 1)
				} else {
					atomic.AddInt64(&otherErrors, 1)
				}
				return
			}
			// Hold the claim briefly so all contenders race the same window.
			time.Sleep(5 * time.Millisecond)
			tokens, err := env.mintTokens(authCode.UserID)
			if err != nil {
				atomic.AddInt64(&otherErrors, 1)
				return
			}
			if err := redemption.Commit(tokens); err != nil {
				atomic.AddInt64(&otherErrors, 1)
				return
			}
			winnerMu.Lock()
			winnerTokens = tokens
			winnerMu.Unlock()
			atomic.AddInt64(&successes, 1)
		}()
	}
	close(start)
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1", successes)
	}
	if replayRejects != contenders-1 {
		t.Fatalf("replay rejections = %d, want %d", replayRejects, contenders-1)
	}
	if otherErrors != 0 {
		t.Fatalf("unexpected errors = %d", otherErrors)
	}
	assertInflightEmpty(t, env.idp)
	assertCodeConsumed(t, env.idp, code,
		env.idp.accessJTIsOf(winnerTokens.AccessTokens)[0], winnerTokens.RefreshTokens[0])
	// Losers' replay attempts revoked the winner's tokens and dropped the
	// refresh token, exactly as the pre-existing replay rule requires.
	if !env.idp.IsTokenRevoked(winnerTokens.AccessTokens[0]) {
		t.Fatal("replayed code must revoke the access token issued from it")
	}
	if _, ok := env.idp.GetRefreshToken(winnerTokens.RefreshTokens[0]); ok {
		t.Fatal("replayed code must drop the refresh token issued from it")
	}
}

// When the first holder fails and aborts, a concurrent waiter must be able to
// take over: still exactly one commit, the failed artifact revoked, the
// successful one live, and no orphaned state.
func TestConcurrentAuthCodeAbortLetsWaiterCommit(t *testing.T) {
	env := newRedemptionTestEnv(t)
	code := env.createCode(t)

	started := make(chan struct{})
	var wg sync.WaitGroup
	var secondMu sync.Mutex
	var secondTokens PartialTokens
	var errs []string
	var errsMu sync.Mutex
	addErr := func(format string, args ...interface{}) {
		errsMu.Lock()
		errs = append(errs, fmt.Sprintf(format, args...))
		errsMu.Unlock()
	}

	// First holder: begin, then abort with a partial access token.
	wg.Add(1)
	go func() {
		defer wg.Done()
		authCode, redemption, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
		if err != nil {
			addErr("first Begin: %v", err)
			close(started)
			return
		}
		close(started)
		time.Sleep(10 * time.Millisecond)
		jwt := env.idp.JWTService()
		partialAccess, err := jwt.CreateAccessToken(authCode.UserID, env.clientID, env.scope, time.Hour, nil)
		if err != nil {
			addErr("partial mint: %v", err)
			redemption.Abort(PartialTokens{})
			return
		}
		env.idp.TrackAccessToken(authCode.UserID, partialAccess)
		partialJTI := env.idp.accessJTIsOf([]string{partialAccess})[0]
		redemption.Abort(PartialTokens{AccessTokens: []string{partialAccess}})
		if !env.idp.IsTokenRevoked(partialAccess) {
			addErr("partial access token %s not revoked", partialJTI)
		}
	}()

	// Second holder: waits for the abort, then commits.
	<-started
	wg.Add(1)
	go func() {
		defer wg.Done()
		authCode, redemption, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
		if err != nil {
			addErr("second Begin: %v", err)
			return
		}
		tokens, err := env.mintTokens(authCode.UserID)
		if err != nil {
			addErr("second mint: %v", err)
			return
		}
		if err := redemption.Commit(tokens); err != nil {
			addErr("second Commit: %v", err)
			return
		}
		secondMu.Lock()
		secondTokens = tokens
		secondMu.Unlock()
	}()
	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("concurrent abort/retry errors: %v", errs)
	}
	if env.idp.IsTokenRevoked(secondTokens.AccessTokens[0]) {
		t.Fatal("waiter's committed access token must be usable")
	}
	if _, ok := env.idp.GetRefreshToken(secondTokens.RefreshTokens[0]); !ok {
		t.Fatal("waiter's refresh token must be stored")
	}
	assertCodeConsumed(t, env.idp, code,
		env.idp.accessJTIsOf(secondTokens.AccessTokens)[0], secondTokens.RefreshTokens[0])
	assertInflightEmpty(t, env.idp)
}

// A failed replay after a commit must never release the committed state: the
// code stays consumed and the replay record survives.
func TestReplayFailureDoesNotReleaseCommittedState(t *testing.T) {
	env := newRedemptionTestEnv(t)
	code := env.createCode(t)

	authCode, redemption, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	tokens := env.mintExchangeTokens(t, authCode.UserID)
	if err := redemption.Commit(tokens); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		_, _, err := env.idp.BeginAuthorizationCodeRedemption(code, env.clientID, env.redirect, "")
		if err == nil {
			t.Fatalf("replay attempt %d must be rejected", attempt+1)
		}
		if err.Error() != "authorization code already used" {
			t.Fatalf("replay attempt %d err = %q, want already used", attempt+1, err.Error())
		}
	}
	if _, ok := env.idp.GetAuthorizationCode(code); ok {
		t.Fatal("failed replay must not restore the consumed code")
	}
	assertInflightEmpty(t, env.idp)
}
