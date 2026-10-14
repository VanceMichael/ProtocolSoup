package oidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
)

func oidcFaultOnce(p *Plugin, kind mockidp.GrantKind, phase mockidp.GrantPhase, delay time.Duration) func() {
	var mu sync.Mutex
	calls := 0
	p.mockIdP.SetFaultHook(func(k mockidp.GrantKind, ph mockidp.GrantPhase) error {
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
	return func() { p.mockIdP.SetFaultHook(nil) }
}

func oidcCodeTokenRequest(t *testing.T, p *Plugin, code string) *httptest.ResponseRecorder {
	t.Helper()
	client, _ := p.mockIdP.GetClient(testConfClient)
	return postTokenForm(t, p, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirectURI},
	}, testConfClient, client.Secret)
}

// At every failure phase in the OIDC code exchange, the failed attempt must not
// consume the code: first attempt 500, legal retry 200 with an ID token, third
// presentation 400 invalid_grant.
func TestOIDCAuthorizationCodeRecoversAtEveryPhase(t *testing.T) {
	phases := []mockidp.GrantPhase{
		mockidp.GrantPhaseBeforeMint,
		mockidp.GrantPhaseAfterAccessToken,
		mockidp.GrantPhaseAfterRefreshToken,
		mockidp.GrantPhaseAfterIDToken,
	}
	for _, phase := range phases {
		t.Run(string(phase), func(t *testing.T) {
			p := newTestPlugin(t)
			authCode, err := p.mockIdP.CreateAuthorizationCode(testConfClient, testUserID, testRedirectURI, "openid", "", "", "", "", "", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			stop := oidcFaultOnce(p, mockidp.GrantAuthorizationCode, phase, 0)
			defer stop()

			rr := oidcCodeTokenRequest(t, p, authCode.Code)
			if rr.Code != http.StatusInternalServerError {
				t.Fatalf("failed exchange = %d body=%s, want 500", rr.Code, rr.Body.String())
			}

			rr = oidcCodeTokenRequest(t, p, authCode.Code)
			if rr.Code != http.StatusOK {
				t.Fatalf("legal retry = %d body=%s, want 200", rr.Code, rr.Body.String())
			}
			tokens := decodeJSONObject(t, rr.Body.Bytes())
			if tokens["id_token"] == "" || tokens["access_token"] == "" || tokens["refresh_token"] == "" {
				t.Fatalf("retry response missing tokens: %#v", tokens)
			}

			rr = oidcCodeTokenRequest(t, p, authCode.Code)
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_grant") {
				t.Fatalf("replay after commit = %d body=%s, want 400 invalid_grant", rr.Code, rr.Body.String())
			}
		})
	}
}

// A transient OIDC refresh failure keeps the old refresh token valid and the
// retry still returns a rotated set including a fresh ID token.
func TestOIDCRefreshRecoversAndRotatesTransactionally(t *testing.T) {
	p := newTestPlugin(t)
	authTime := time.Now().Add(-time.Hour).Truncate(time.Second)
	old := "oidc-old-refresh-token"
	p.mockIdP.StoreRefreshToken(old, testConfClient, testUserID, "openid", authTime, time.Now().Add(time.Hour))
	stop := oidcFaultOnce(p, mockidp.GrantRefreshToken, mockidp.GrantPhaseAfterIDToken, 0)
	defer stop()

	refreshForm := func(token string) *httptest.ResponseRecorder {
		client, _ := p.mockIdP.GetClient(testConfClient)
		return postTokenForm(t, p, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token},
			"scope":         {"openid"},
		}, testConfClient, client.Secret)
	}

	rr := refreshForm(old)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("failed refresh = %d body=%s, want 500", rr.Code, rr.Body.String())
	}
	if _, ok := p.mockIdP.GetRefreshToken(old); !ok {
		t.Fatal("old refresh token must survive the aborted refresh")
	}

	rr = refreshForm(old)
	if rr.Code != http.StatusOK {
		t.Fatalf("legal retry = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	tokens := decodeJSONObject(t, rr.Body.Bytes())
	if tokens["id_token"] == "" {
		t.Fatal("refresh response must include an ID token for openid scope")
	}
	newRT, _ := tokens["refresh_token"].(string)
	if newRT == "" || newRT == old {
		t.Fatalf("expected rotated refresh token, old=%q new=%q", old, newRT)
	}

	rr = refreshForm(old)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_grant") {
		t.Fatalf("old refresh reuse = %d body=%s, want 400 invalid_grant", rr.Code, rr.Body.String())
	}
}

// Concurrent OIDC code exchanges commit at most once.
func TestOIDCConcurrentCodeExchangeCommitsOnce(t *testing.T) {
	p := newTestPlugin(t)
	authCode, err := p.mockIdP.CreateAuthorizationCode(testConfClient, testUserID, testRedirectURI, "openid", "", "", "", "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client, _ := p.mockIdP.GetClient(testConfClient)
	// Delay-only hook widens the claim window; no failure in this scenario.
	p.mockIdP.SetFaultHook(func(k mockidp.GrantKind, ph mockidp.GrantPhase) error {
		if k == mockidp.GrantAuthorizationCode && ph == mockidp.GrantPhaseBeforeMint {
			time.Sleep(20 * time.Millisecond)
		}
		return nil
	})
	defer p.mockIdP.SetFaultHook(nil)

	const contenders = 10
	start := make(chan struct{})
	codes := make([]int, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {authCode.Code},
				"redirect_uri": {testRedirectURI},
			}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(testConfClient, client.Secret)
			rr := httptest.NewRecorder()
			p.handleToken(rr, req)
			codes[i] = rr.Code
		}(i)
	}
	close(start)
	wg.Wait()

	ok, invalid := 0, 0
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusBadRequest:
			invalid++
		default:
			t.Fatalf("unexpected status %d", code)
		}
	}
	if ok != 1 {
		t.Fatalf("200 responses = %d, want exactly 1", ok)
	}
	if invalid != contenders-1 {
		t.Fatalf("400 responses = %d, want %d", invalid, contenders-1)
	}
}
