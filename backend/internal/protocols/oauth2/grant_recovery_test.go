package oauth2

import (
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
)

// failPhaseOnce installs a hook that fails the first invocation for the given
// grant kind/phase and lets every subsequent exchange through. It also delays
// the holder at that phase so concurrent contenders overlap the claim window.
func failPhaseOnce(t *testing.T, server *oauthAssertionTestServer, kind mockidp.GrantKind, phase mockidp.GrantPhase, delay time.Duration) {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	server.idp.SetFaultHook(func(k mockidp.GrantKind, p mockidp.GrantPhase) error {
		mu.Lock()
		defer mu.Unlock()
		if delay > 0 && k == kind && p == phase {
			time.Sleep(delay)
		}
		if k == kind && p == phase {
			calls++
			if calls == 1 {
				return errors.New("simulated transient failure")
			}
		}
		return nil
	})
	t.Cleanup(func() { server.idp.SetFaultHook(nil) })
}

func authCodeTokenForm(code string) url.Values {
	return url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
}

// At every failure phase, a transient error leaves the code retryable: the
// first attempt fails server-side, the legal retry succeeds, and a third use
// is rejected as a replay (invalid_grant). The refresh token returned on the
// successful retry must itself work, proving no partial artifact blocked the
// chain.
func TestAuthorizationCodeGrantRecoversAtEveryFailurePhase(t *testing.T) {
	phases := []mockidp.GrantPhase{
		mockidp.GrantPhaseBeforeMint,
		mockidp.GrantPhaseAfterAccessToken,
		mockidp.GrantPhaseAfterRefreshToken,
	}
	for _, phase := range phases {
		t.Run(string(phase), func(t *testing.T) {
			server := newOAuthAssertionTestServer(t)
			code := createDPoPTestAuthCode(t, server).Code
			failPhaseOnce(t, server, mockidp.GrantAuthorizationCode, phase, 0)

			status, body := postTokenRequest(t, server.server.URL, authCodeTokenForm(code), "")
			if status != http.StatusBadRequest || body["error"] != "server_error" {
				t.Fatalf("failed exchange = %d %#v, want 400 server_error", status, body)
			}

			status, body = postTokenRequest(t, server.server.URL, authCodeTokenForm(code), "")
			if status != http.StatusOK {
				t.Fatalf("legal retry after %s = %d %#v, want 200", phase, status, body)
			}
			refreshToken, _ := body["refresh_token"].(string)
			if refreshToken == "" {
				t.Fatalf("successful retry must include a refresh token: %#v", body)
			}

			// No orphaned partial refresh token: the returned refresh token
			// rotates cleanly.
			status, body = postTokenRequest(t, server.server.URL, url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
				"client_id":     {"public-app"},
			}, "")
			if status != http.StatusOK {
				t.Fatalf("refresh after recovery = %d %#v, want 200", status, body)
			}

			// The code was finally consumed by the successful retry.
			status, body = postTokenRequest(t, server.server.URL, authCodeTokenForm(code), "")
			if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
				t.Fatalf("replay after commit = %d %#v, want 400 invalid_grant", status, body)
			}
		})
	}
}

// A transient failure during refresh rotation keeps the old refresh token
// usable; the legal retry rotates and the old value is then rejected.
func TestRefreshTokenGrantRecoversFromMidExchangeFailure(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	key := newDPoPTestKey(t)
	refreshToken := issueDPoPBoundRefreshToken(t, server, key)
	tokenURL := server.server.URL + "/oauth2/token"
	failPhaseOnce(t, server, mockidp.GrantRefreshToken, mockidp.GrantPhaseAfterRefreshToken, 0)

	refreshForm := func(token string) (url.Values, string) {
		return url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token},
			"client_id":     {"public-app"},
		}, key.proof(t, http.MethodPost, tokenURL, nil)
	}

	form, proof := refreshForm(refreshToken)
	status, body := postTokenRequest(t, server.server.URL, form, proof)
	if status != http.StatusBadRequest || body["error"] != "server_error" {
		t.Fatalf("failed refresh = %d %#v, want 400 server_error", status, body)
	}

	// Old refresh token survives the aborted rotation.
	form, proof = refreshForm(refreshToken)
	status, body = postTokenRequest(t, server.server.URL, form, proof)
	if status != http.StatusOK {
		t.Fatalf("legal refresh retry = %d %#v, want 200", status, body)
	}
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" || rotated == refreshToken {
		t.Fatalf("retry must rotate the refresh token: old=%q new=%q", refreshToken, rotated)
	}

	// Old value is consumed by the committed rotation.
	form, proof = refreshForm(refreshToken)
	status, body = postTokenRequest(t, server.server.URL, form, proof)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("old refresh reuse = %d %#v, want 400 invalid_grant", status, body)
	}
}

// A transient failure after tokens were minted during the device grant leaves
// the authorization authorized: the failed poll is 500, the next poll gets
// tokens, and a further poll is invalid_grant (consumed).
func TestDeviceCodeGrantRecoversFromMidExchangeFailure(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	issued := postDeviceAuthorize(t, server.server.URL, url.Values{"client_id": {"public-app"}})
	deviceCode := issued["device_code"].(string)
	userCode := issued["user_code"].(string)
	alice := server.idp.GetDemoUserPresets()[0]
	approveDevice(t, server.server.URL, userCode, alice.Credentials.Email, alice.Credentials.Password, "approve")
	failPhaseOnce(t, server, mockidp.GrantDeviceCode, mockidp.GrantPhaseAfterAccessToken, 0)

	pollForm := url.Values{
		"grant_type":  {mockidp.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, pollForm, "")
	if status != http.StatusInternalServerError {
		t.Fatalf("failed device poll = %d %#v, want 500", status, body)
	}

	status, body = postTokenRequest(t, server.server.URL, pollForm, "")
	if status != http.StatusOK || body["access_token"] == "" {
		t.Fatalf("legal device retry = %d %#v, want 200 with tokens", status, body)
	}

	status, body = postTokenRequest(t, server.server.URL, pollForm, "")
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("device reuse after commit = %d %#v, want 400 invalid_grant", status, body)
	}
}

type tokenResult struct {
	status int
	body   map[string]interface{}
}

// Concurrent redemptions of one authorization code commit at most once even
// when the holder pauses mid-exchange: exactly one 200, all others 400
// invalid_grant, and no panic/deadlock under -race.
func TestConcurrentAuthorizationCodeExchangeCommitsOnce(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	code := createDPoPTestAuthCode(t, server).Code
	failPhaseOnce(t, server, mockidp.GrantAuthorizationCode, mockidp.GrantPhaseBeforeMint, 20*time.Millisecond)
	// Keep the hook delay-only for this scenario.
	server.idp.SetFaultHook(func(k mockidp.GrantKind, p mockidp.GrantPhase) error {
		if k == mockidp.GrantAuthorizationCode && p == mockidp.GrantPhaseBeforeMint {
			time.Sleep(20 * time.Millisecond)
		}
		return nil
	})

	const contenders = 12
	start := make(chan struct{})
	results := make([]tokenResult, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			status, body := postTokenRequest(t, server.server.URL, authCodeTokenForm(code), "")
			results[i] = tokenResult{status: status, body: body}
		}(i)
	}
	close(start)
	wg.Wait()

	ok, invalid := 0, 0
	for _, result := range results {
		switch {
		case result.status == http.StatusOK:
			ok++
		case result.status == http.StatusBadRequest && result.body["error"] == "invalid_grant":
			invalid++
		default:
			t.Fatalf("unexpected concurrent result: %d %#v", result.status, result.body)
		}
	}
	if ok != 1 {
		t.Fatalf("200 responses = %d, want exactly 1", ok)
	}
	if invalid != contenders-1 {
		t.Fatalf("invalid_grant responses = %d, want %d", invalid, contenders-1)
	}
}

// With a failing first holder and concurrent contenders, the failed attempt
// returns 500-style server_error and restores the code; exactly one waiter
// then succeeds and everybody else is rejected. The successful refresh token
// chain proves no double issuance.
func TestConcurrentAuthorizationCodeFailureThenSingleSuccess(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	code := createDPoPTestAuthCode(t, server).Code

	var mu sync.Mutex
	hits := 0
	server.idp.SetFaultHook(func(k mockidp.GrantKind, p mockidp.GrantPhase) error {
		if k != mockidp.GrantAuthorizationCode {
			return nil
		}
		if p == mockidp.GrantPhaseBeforeMint {
			time.Sleep(15 * time.Millisecond)
		}
		if p == mockidp.GrantPhaseAfterRefreshToken {
			mu.Lock()
			hits++
			fail := hits == 1
			mu.Unlock()
			if fail {
				return errors.New("simulated state-save failure")
			}
		}
		return nil
	})
	t.Cleanup(func() { server.idp.SetFaultHook(nil) })

	const contenders = 8
	start := make(chan struct{})
	results := make([]tokenResult, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			status, body := postTokenRequest(t, server.server.URL, authCodeTokenForm(code), "")
			results[i] = tokenResult{status: status, body: body}
		}(i)
	}
	close(start)
	wg.Wait()

	ok, failed, invalid := 0, 0, 0
	var successBody map[string]interface{}
	for _, result := range results {
		switch {
		case result.status == http.StatusOK:
			ok++
			successBody = result.body
		case result.body["error"] == "server_error":
			failed++
		case result.status == http.StatusBadRequest && result.body["error"] == "invalid_grant":
			invalid++
		default:
			t.Fatalf("unexpected result: %d %#v", result.status, result.body)
		}
	}
	if failed != 1 {
		t.Fatalf("server_error responses = %d, want exactly 1", failed)
	}
	if ok != 1 {
		t.Fatalf("200 responses = %d, want exactly 1", ok)
	}
	if invalid != contenders-2 {
		t.Fatalf("invalid_grant responses = %d, want %d", invalid, contenders-2)
	}

	// Exactly one token set was ever issued (single 200); the failed attempt
	// left none behind. The concurrent replay losers follow the existing RFC
	// 6749 Section 4.1.2 rule and revoke the tokens the sole winner minted, so
	// its refresh token is subsequently rejected like any replayed-code token.
	refreshToken, _ := successBody["refresh_token"].(string)
	status, body := postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"public-app"},
	}, "")
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("winner refresh token after concurrent replays = %d %#v, want 400 invalid_grant (RFC 6749 4.1.2 replay revocation)", status, body)
	}

	// A sequential (non-replayed) recovery keeps its token chain usable, which
	// TestAuthorizationCodeGrantRecoversAtEveryFailurePhase asserts above.
}
