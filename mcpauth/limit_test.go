package mcpauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func identityContext(issuer, subject string) context.Context {
	identity := OAuthIdentity{Issuer: issuer, Subject: subject, ExpiresAt: time.Now().Add(time.Hour)}
	return context.WithValue(context.Background(), oauthContextKey{}, oauthCredential{identity: identity, token: "token"})
}

func testLimiter(maxConcurrent, perMinute int) (*CallLimiter, *fakeClock) {
	clock := &fakeClock{now: time.Now()}
	l := NewCallLimiter(maxConcurrent, perMinute)
	l.now = clock.Now
	return l, clock
}

func TestCallLimiterBoundsCallsInProgressPerIdentity(t *testing.T) {
	l, _ := testLimiter(2, 0)
	alice := identityContext("https://sso.example.test/", "alice")
	first, err := l.Acquire(alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Acquire(alice); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Acquire(alice); !errors.Is(err, ErrCallLimited) || !strings.Contains(err.Error(), "retry when one completes") {
		t.Fatalf("third concurrent call admitted: %v", err)
	}
	if _, err := l.Acquire(identityContext("https://sso.example.test/", "bob")); err != nil {
		t.Fatalf("another identity limited: %v", err)
	}
	if _, err := l.Acquire(identityContext("https://other.example.test/", "alice")); err != nil {
		t.Fatalf("the same subject of another issuer limited: %v", err)
	}
	first()
	first() // a second release is ignored
	if _, err := l.Acquire(alice); err != nil {
		t.Fatalf("call not admitted after a release: %v", err)
	}
	if _, err := l.Acquire(alice); !errors.Is(err, ErrCallLimited) {
		t.Fatal("double release freed two slots")
	}
}

func TestCallLimiterBoundsCallsPerMinuteWithABurst(t *testing.T) {
	l, clock := testLimiter(0, 120)
	alice := identityContext("https://sso.example.test/", "alice")
	for i := range 30 {
		release, err := l.Acquire(alice)
		if err != nil {
			t.Fatalf("call %d of the burst refused: %v", i+1, err)
		}
		release()
	}
	_, err := l.Acquire(alice)
	if !errors.Is(err, ErrCallLimited) || !strings.Contains(err.Error(), "retry in 1 s") {
		t.Fatalf("burst exceeded: %v", err)
	}
	clock.Add(time.Second) // 120 per minute: 2 per second
	for range 2 {
		release, err := l.Acquire(alice)
		if err != nil {
			t.Fatalf("refilled call refused: %v", err)
		}
		release()
	}
	if _, err := l.Acquire(alice); !errors.Is(err, ErrCallLimited) {
		t.Fatal("refill exceeded the rate")
	}
	clock.Add(time.Hour)
	for range 30 {
		release, err := l.Acquire(alice)
		if err != nil {
			t.Fatal("bucket not refilled up to the burst")
		}
		release()
	}
	if _, err := l.Acquire(alice); !errors.Is(err, ErrCallLimited) {
		t.Fatal("bucket refilled beyond the burst")
	}
}

func TestCallLimiterBurstNeverExceedsTheRate(t *testing.T) {
	l, _ := testLimiter(0, 5)
	alice := identityContext("https://sso.example.test/", "alice")
	for range 5 {
		if _, err := l.Acquire(alice); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.Acquire(alice); !errors.Is(err, ErrCallLimited) || !strings.Contains(err.Error(), "retry in 13 s") {
		t.Fatalf("burst above a rate of 5 per minute: %v", err)
	}
}

func TestCallLimiterDisabledOrWithoutIdentity(t *testing.T) {
	if NewCallLimiter(0, 0) != nil {
		t.Fatal("limiter without limits")
	}
	var none *CallLimiter
	release, err := none.Acquire(identityContext("https://sso.example.test/", "alice"))
	if err != nil {
		t.Fatal(err)
	}
	release()
	l, _ := testLimiter(1, 1)
	for range 3 {
		if _, err := l.Acquire(context.Background()); err != nil {
			t.Fatalf("unauthenticated context limited: %v", err)
		}
	}
}

func TestCallLimiterMemoryStaysBounded(t *testing.T) {
	l, clock := testLimiter(4, 120)
	busy := identityContext("https://sso.example.test/", "busy")
	if _, err := l.Acquire(busy); err != nil {
		t.Fatal(err)
	}
	for i := range callLimiterSweep + 10 {
		release, err := l.Acquire(identityContext("https://sso.example.test/", fmt.Sprint("user-", i)))
		if err != nil {
			t.Fatal(err)
		}
		release()
		if i == callLimiterSweep/2 {
			clock.Add(time.Minute)
		}
	}
	if len(l.identities) > callLimiterSweep {
		t.Fatalf("%d identities kept", len(l.identities))
	}
	if l.identities["https://sso.example.test/\x00busy"] == nil {
		t.Fatal("identity with a call in progress swept")
	}
}
