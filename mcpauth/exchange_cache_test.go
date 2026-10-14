package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/opensvc/osvc-auth-mcp/mcpauthtest"
)

// fakeClock is the clock of a cache under test.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestCache() (*exchangeCache, *fakeClock) {
	clock := &fakeClock{now: time.Now()}
	c := newExchangeCache()
	c.now = clock.Now
	return c, clock
}

// counted returns an exchange that counts its calls and returns a token
// expiring after lifetime, measured on clock.
func counted(clock *fakeClock, lifetime time.Duration) (func(context.Context) (exchanged, error), *atomic.Int32) {
	var calls atomic.Int32
	return func(context.Context) (exchanged, error) {
		n := calls.Add(1)
		return exchanged{token: "token-" + string(rune('a'+n-1)), subject: "alice", deadline: clock.Now().Add(lifetime)}, nil
	}, &calls
}

func TestExchangeCacheReusesATokenForAtMostAMinute(t *testing.T) {
	c, clock := newTestCache()
	exchange, calls := counted(clock, time.Hour)
	first, err := c.get(t.Context(), "key", exchange)
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(59 * time.Second)
	if again, _ := c.get(t.Context(), "key", exchange); again.token != first.token || calls.Load() != 1 {
		t.Fatalf("token not reused within the lifetime: %d exchanges", calls.Load())
	}
	clock.Add(2 * time.Second)
	if renewed, _ := c.get(t.Context(), "key", exchange); renewed.token == first.token || calls.Load() != 2 {
		t.Fatalf("token reused after the lifetime: %d exchanges", calls.Load())
	}
}

func TestExchangeCacheNeverReusesATokenThatExpiresSoon(t *testing.T) {
	c, clock := newTestCache()
	exchange, calls := counted(clock, 45*time.Second)
	if _, err := c.get(t.Context(), "key", exchange); err != nil {
		t.Fatal(err)
	}
	clock.Add(16 * time.Second) // 29s left: within the margin
	if _, err := c.get(t.Context(), "key", exchange); err != nil || calls.Load() != 2 {
		t.Fatalf("token reused within the expiry margin: %d exchanges", calls.Load())
	}
	short, calls := counted(clock, 20*time.Second)
	for range 2 {
		if _, err := c.get(t.Context(), "short", short); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 || len(c.entries) != 1 {
		t.Fatalf("token expiring within the margin was cached: %d exchanges, %d entries", calls.Load(), len(c.entries))
	}
}

func TestExchangeCacheSharesOneExchangeBetweenConcurrentCalls(t *testing.T) {
	c, clock := newTestCache()
	release := make(chan struct{})
	var calls atomic.Int32
	exchange := func(context.Context) (exchanged, error) {
		calls.Add(1)
		<-release
		return exchanged{token: "shared", deadline: clock.Now().Add(time.Hour)}, nil
	}
	var wg sync.WaitGroup
	tokens := make(chan string, 10)
	for range 10 {
		wg.Go(func() {
			result, err := c.get(t.Context(), "key", exchange)
			if err != nil {
				t.Error(err)
			}
			tokens <- result.token
		})
	}
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(tokens)
	for token := range tokens {
		if token != "shared" {
			t.Errorf("waiter got %q", token)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("%d exchanges for concurrent calls", calls.Load())
	}
}

func TestExchangeCacheRemembersFailuresForFiveSeconds(t *testing.T) {
	c, clock := newTestCache()
	refused := errors.New("token exchange refused by SSO (invalid_grant)")
	var calls atomic.Int32
	exchange := func(context.Context) (exchanged, error) {
		if calls.Add(1) == 1 {
			return exchanged{}, refused
		}
		return exchanged{token: "ok", deadline: clock.Now().Add(time.Hour)}, nil
	}
	for range 3 {
		if _, err := c.get(t.Context(), "key", exchange); err != refused {
			t.Fatalf("err = %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("a client looping on a refused token reached the SSO %d times", calls.Load())
	}
	clock.Add(5 * time.Second)
	if result, err := c.get(t.Context(), "key", exchange); err != nil || result.token != "ok" || calls.Load() != 2 {
		t.Fatalf("failure remembered too long: %v %d exchanges", err, calls.Load())
	}
}

func TestExchangeCacheWaitersRetryWhenTheFirstCallerGivesUp(t *testing.T) {
	c, clock := newTestCache()
	started := make(chan struct{})
	var calls atomic.Int32
	exchange := func(ctx context.Context) (exchanged, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			return exchanged{}, ctx.Err()
		}
		return exchanged{token: "second", deadline: clock.Now().Add(time.Hour)}, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	go func() { _, _ = c.get(ctx, "key", exchange) }()
	<-started
	done := make(chan exchanged)
	go func() {
		result, err := c.get(t.Context(), "key", exchange)
		if err != nil {
			t.Error(err)
		}
		done <- result
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if result := <-done; result.token != "second" || calls.Load() != 2 {
		t.Fatalf("waiter inherited the cancellation of another caller: %q, %d exchanges", result.token, calls.Load())
	}
}

func TestExchangeCacheStaysBounded(t *testing.T) {
	c, clock := newTestCache()
	c.max = 2
	exchange, calls := counted(clock, time.Hour)
	for _, key := range []string{"a", "b", "c", "c"} {
		if _, err := c.get(t.Context(), key, exchange); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.entries) != 2 || calls.Load() != 4 {
		t.Fatalf("full cache: %d entries, %d exchanges", len(c.entries), calls.Load())
	}
	clock.Add(2 * time.Minute)
	if _, err := c.get(t.Context(), "c", exchange); err != nil || len(c.entries) != 1 {
		t.Fatalf("expired entries not purged: %d entries", len(c.entries))
	}
}

func TestExchangeCacheForgetsOnlyTheRefusedToken(t *testing.T) {
	c, clock := newTestCache()
	exchange, calls := counted(clock, time.Hour)
	first, _ := c.get(t.Context(), "key", exchange)
	c.forget("key", first.token)
	second, _ := c.get(t.Context(), "key", exchange)
	if second.token == first.token || calls.Load() != 2 {
		t.Fatalf("refused token not forgotten: %d exchanges", calls.Load())
	}
	c.forget("key", first.token) // late refusal of the old token
	if again, _ := c.get(t.Context(), "key", exchange); again.token != second.token || calls.Load() != 2 {
		t.Fatal("a late refusal removed a newer token")
	}
}

// TestPrepareCachesPerMCPTokenAndTarget runs through the OAuth middleware, as
// the MCP servers do.
func TestPrepareCachesPerMCPTokenAndTarget(t *testing.T) {
	p := mcpauthtest.NewOAuthProvider(t)
	p.Metadata["token_endpoint"] = p.Server.URL + "/token"
	profiles, err := LoadExchangeProfiles(mcpauthtest.WriteExchangeProfiles(t, p, "client_secret_basic"))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	p.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		_ = r.ParseForm()
		token := p.Token(t, r.PostForm.Get("audience"), "alice", func(c jwt.MapClaims) { c["n"] = n })
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "issued_token_type": accessTokenType, "expires_in": 300})
	}
	verifier := newTestVerifier(t, p)
	call := func(subject, audience, target string, refused bool) string {
		var token string
		handler := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel, err := profiles.Prepare(r.Context(), "test-sso", audience, target)
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			_, token, _ = ExchangedFromContext(ctx)
			if refused {
				ForgetExchanged(ctx)
			}
			w.WriteHeader(204)
		}))
		if w := oauthRequest(handler, subject); w.Code != 204 {
			t.Fatalf("status %d", w.Code)
		}
		return token
	}
	alice := p.Token(t, testResource, "alice", nil)
	bob := p.Token(t, testResource, "bob", nil)
	first := call(alice, "daemon-a", "cluster-a", false)
	if call(alice, "daemon-a", "cluster-a", false) != first || calls.Load() != 1 {
		t.Fatalf("same MCP token and target exchanged again: %d exchanges", calls.Load())
	}
	call(alice, "daemon-a", "cluster-b", false)
	call(alice, "daemon-b", "cluster-a", false)
	call(bob, "daemon-a", "cluster-a", false)
	if calls.Load() != 4 {
		t.Fatalf("cache shared between targets or MCP tokens: %d exchanges", calls.Load())
	}
	call(alice, "daemon-a", "cluster-a", true)
	if call(alice, "daemon-a", "cluster-a", false) == first || calls.Load() != 5 {
		t.Fatalf("refused token reused: %d exchanges", calls.Load())
	}
}
