package oid4vci

import (
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
)

const grantRecoveryClientID = "public-app"
const grantRecoveryRedirectURI = "http://localhost:3000/callback"

func createGrantRecoveryCode(t *testing.T, env *oid4vciTestEnvironment) string {
	t.Helper()
	authCode, err := env.IDP.CreateAuthorizationCode(
		grantRecoveryClientID, "alice", grantRecoveryRedirectURI, "vc:issue", "", "",
		"", "", "", time.Now(),
	)
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	if err := env.IDP.BindCredentialConfigurationIDs(authCode.Code, []string{defaultCredentialConfigurationID}); err != nil {
		t.Fatalf("BindCredentialConfigurationIDs: %v", err)
	}
	return authCode.Code
}

func grantRecoveryForm(code string) url.Values {
	return url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {grantRecoveryRedirectURI},
		"client_id":    {grantRecoveryClientID},
	}
}

func vciFaultOnce(p *Plugin, kind mockidp.GrantKind, phase mockidp.GrantPhase, delay time.Duration) func() {
	var mu sync.Mutex
	calls := 0
	p.mockIDP.SetFaultHook(func(k mockidp.GrantKind, ph mockidp.GrantPhase) error {
		mu.Lock()
		defer mu.Unlock()
		if delay > 0 && k == kind && ph == phase {
			time.Sleep(delay)
		}
		if k == kind && ph == phase {
			calls++
			if calls == 1 {
				return errors.New("simulated transient failure")
			}
		}
		return nil
	})
	return func() { p.mockIDP.SetFaultHook(nil) }
}

func grantContextCounts(p *Plugin) (accessGrants, refreshGrants int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.accessGrants), len(p.refreshGrants)
}

// Every phased failure in the OID4VCI code grant leaves the code retryable and
// leaves no access/refresh grant context behind; the legal retry succeeds once,
// and replay stays invalid_grant.
func TestOID4VCIAuthorizationCodeRecoversAtEveryPhase(t *testing.T) {
	phases := []mockidp.GrantPhase{
		mockidp.GrantPhaseBeforeMint,
		mockidp.GrantPhaseAfterAccessToken,
		mockidp.GrantPhaseAfterRefreshToken,
		mockidp.GrantPhaseAfterAncillary,
	}
	for _, phase := range phases {
		t.Run(string(phase), func(t *testing.T) {
			env := newTestEnvironment(t)
			code := createGrantRecoveryCode(t, env)
			stop := vciFaultOnce(env.Plugin, mockidp.GrantAuthorizationCode, phase, 0)
			defer stop()

			status, body := postTokenRequestForm(t, env.Server.URL, grantRecoveryForm(code), "")
			if status != http.StatusInternalServerError || body["error"] != "server_error" {
				t.Fatalf("failed exchange = %d %#v, want 500 server_error", status, body)
			}
			if access, refresh := grantContextCounts(env.Plugin); access != 0 || refresh != 0 {
				t.Fatalf("orphaned grant context after %s failure: accessGrants=%d refreshGrants=%d", phase, access, refresh)
			}
			if _, ok := env.IDP.GetAuthorizationCode(code); !ok {
				t.Fatal("code must remain redeemable after failed exchange")
			}

			status, body = postTokenRequestForm(t, env.Server.URL, grantRecoveryForm(code), "")
			if status != http.StatusOK {
				t.Fatalf("legal retry = %d %#v, want 200", status, body)
			}
			if body["access_token"] == "" || body["refresh_token"] == "" {
				t.Fatalf("retry response missing tokens: %#v", body)
			}
			if access, refresh := grantContextCounts(env.Plugin); access != 1 || refresh != 1 {
				t.Fatalf("grant context after success = accessGrants:%d refreshGrants:%d, want 1/1", access, refresh)
			}

			status, body = postTokenRequestForm(t, env.Server.URL, grantRecoveryForm(code), "")
			if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
				t.Fatalf("replay after commit = %d %#v, want 400 invalid_grant", status, body)
			}
			if access, refresh := grantContextCounts(env.Plugin); access != 1 || refresh != 1 {
				t.Fatalf("committed grant context must survive replay: accessGrants=%d refreshGrants=%d", access, refresh)
			}
		})
	}
}

// A failure after ancillary state is prepared rolls the issuer-initiated
// transaction back to its previous status; retry then advances it once.
func TestOID4VCIAuxiliaryStateRollbackOnAbort(t *testing.T) {
	env := newTestEnvironment(t)
	code := createGrantRecoveryCode(t, env)
	authCode, ok := env.IDP.GetAuthorizationCode(code)
	if !ok {
		t.Fatal("code missing")
	}
	issuerState := "issuer-state-rollback"
	now := time.Now().UTC()
	env.Plugin.mu.Lock()
	env.Plugin.issuerInitiatedOffers[issuerState] = &issuerInitiatedTransaction{
		StatusID:      "status-id",
		IssuerState:   issuerState,
		ClientID:      grantRecoveryClientID,
		Status:        issuerInitiatedStatusAuthorizationRequestReceived,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(issuerInitiatedTransactionTTL),
	}
	authCode.IssuerState = issuerState
	env.IDP.BindAuthorizationCodeIssuerState(code, issuerState)
	env.Plugin.mu.Unlock()

	stop := vciFaultOnce(env.Plugin, mockidp.GrantAuthorizationCode, mockidp.GrantPhaseAfterAncillary, 0)

	status, body := postTokenRequestForm(t, env.Server.URL, grantRecoveryForm(code), "")
	if status != http.StatusInternalServerError {
		t.Fatalf("failed exchange = %d %#v, want 500", status, body)
	}

	env.Plugin.mu.RLock()
	txn := env.Plugin.issuerInitiatedOffers[issuerState]
	env.Plugin.mu.RUnlock()
	if txn == nil {
		t.Fatal("issuer transaction must still exist after rollback")
	}
	if txn.Status != issuerInitiatedStatusAuthorizationRequestReceived {
		t.Fatalf("issuer transaction status = %q, want rolled-back %q", txn.Status, issuerInitiatedStatusAuthorizationRequestReceived)
	}
	if access, refresh := grantContextCounts(env.Plugin); access != 0 || refresh != 0 {
		t.Fatalf("orphaned grant context: accessGrants=%d refreshGrants=%d", access, refresh)
	}

	stop()
	status, body = postTokenRequestForm(t, env.Server.URL, grantRecoveryForm(code), "")
	if status != http.StatusOK {
		t.Fatalf("legal retry = %d %#v, want 200", status, body)
	}
	env.Plugin.mu.RLock()
	txn = env.Plugin.issuerInitiatedOffers[issuerState]
	env.Plugin.mu.RUnlock()
	if txn.Status != issuerInitiatedStatusTokenIssued {
		t.Fatalf("issuer transaction status after retry = %q, want %q", txn.Status, issuerInitiatedStatusTokenIssued)
	}
}

// Concurrent OID4VCI code exchanges commit at most once; losers get
// invalid_grant and no extra grant context is created.
func TestOID4VCIConcurrentCodeExchangeCommitsOnce(t *testing.T) {
	env := newTestEnvironment(t)
	code := createGrantRecoveryCode(t, env)
	env.Plugin.mockIDP.SetFaultHook(func(k mockidp.GrantKind, ph mockidp.GrantPhase) error {
		if k == mockidp.GrantAuthorizationCode && ph == mockidp.GrantPhaseBeforeMint {
			time.Sleep(20 * time.Millisecond)
		}
		return nil
	})
	defer env.Plugin.mockIDP.SetFaultHook(nil)

	const contenders = 10
	start := make(chan struct{})
	type result struct {
		status int
		error_ string
	}
	results := make([]result, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			status, body := postTokenRequestForm(t, env.Server.URL, grantRecoveryForm(code), "")
			errCode, _ := body["error"].(string)
			results[i] = result{status: status, error_: errCode}
		}(i)
	}
	close(start)
	wg.Wait()

	ok, invalid := 0, 0
	for _, r := range results {
		switch {
		case r.status == http.StatusOK:
			ok++
		case r.status == http.StatusBadRequest && r.error_ == "invalid_grant":
			invalid++
		default:
			t.Fatalf("unexpected result: %+v", r)
		}
	}
	if ok != 1 {
		t.Fatalf("200 responses = %d, want exactly 1", ok)
	}
	if invalid != contenders-1 {
		t.Fatalf("invalid_grant responses = %d, want %d", invalid, contenders-1)
	}
	if access, refresh := grantContextCounts(env.Plugin); access != 1 || refresh != 1 {
		t.Fatalf("grant context after concurrent storm = accessGrants:%d refreshGrants:%d, want 1/1", access, refresh)
	}
}
