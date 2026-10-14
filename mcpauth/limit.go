package mcpauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultMaxConcurrentCalls and DefaultMaxCallsPerMinute are the limits of
	// one authenticated identity when the MCP server does not configure them.
	// The concurrency default covers the parallel tool calls an LLM client
	// makes in one turn; the rate limit stops the loops.
	DefaultMaxConcurrentCalls = 10
	DefaultMaxCallsPerMinute  = 120
	// maxCallBurst bounds the calls an idle identity may make at once, within
	// its rate per minute.
	maxCallBurst = 30
	// callLimiterSweep is the number of identities above which idle ones are
	// removed, so that the limiter memory stays bounded.
	callLimiterSweep = 4096
)

// ErrCallLimited is wrapped by the errors of CallLimiter.Acquire.
var ErrCallLimited = errors.New("tool call limited")

// CallLimiter bounds the tool calls of each authenticated identity (issuer and
// subject): the calls in progress, and the calls per minute with a token
// bucket. It protects the SSO and the targets from a client that loops; the
// network protection of the listener belongs to the infrastructure in front
// of it. A nil *CallLimiter limits nothing.
type CallLimiter struct {
	maxConcurrent int
	perMinute     int
	burst         float64
	now           func() time.Time

	mu         sync.Mutex
	identities map[string]*callBudget
}

type callBudget struct {
	active  int
	tokens  float64
	updated time.Time
}

// NewCallLimiter returns a limiter of maxConcurrent calls in progress and
// perMinute calls per minute for each identity; 0 disables a limit. It returns
// nil when both are disabled.
func NewCallLimiter(maxConcurrent, perMinute int) *CallLimiter {
	if maxConcurrent <= 0 && perMinute <= 0 {
		return nil
	}
	burst := min(perMinute, maxCallBurst)
	return &CallLimiter{
		maxConcurrent: max(maxConcurrent, 0), perMinute: max(perMinute, 0), burst: float64(burst),
		now: time.Now, identities: make(map[string]*callBudget),
	}
}

// Acquire admits one tool call of the OAuth identity of ctx, or refuses it
// with an error that wraps ErrCallLimited and tells the client when to retry.
// release must be called when the call ends. A request without OAuth
// identity is not limited: the listener authenticates every request first.
func (l *CallLimiter) Acquire(ctx context.Context) (release func(), err error) {
	identity, _, ok := OAuthFromContext(ctx)
	if l == nil || !ok {
		return func() {}, nil
	}
	key := identity.Issuer + "\x00" + identity.Subject
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.identities[key]
	if b == nil {
		if len(l.identities) >= callLimiterSweep {
			l.sweep(now)
		}
		b = &callBudget{tokens: l.burst, updated: now}
		l.identities[key] = b
	}
	if l.perMinute > 0 {
		b.tokens = min(l.burst, b.tokens+now.Sub(b.updated).Minutes()*float64(l.perMinute))
		b.updated = now
	}
	if l.maxConcurrent > 0 && b.active >= l.maxConcurrent {
		return nil, fmt.Errorf("%w: this identity has reached its limit of tool calls in progress (%d); retry when one completes", ErrCallLimited, l.maxConcurrent)
	}
	if l.perMinute > 0 {
		if b.tokens < 1 {
			wait := time.Duration((1 - b.tokens) / float64(l.perMinute) * float64(time.Minute))
			return nil, fmt.Errorf("%w: more than %d tool calls per minute for this identity; retry in %d s", ErrCallLimited, l.perMinute, int(wait.Seconds())+1)
		}
		b.tokens--
	}
	b.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			b.active--
		})
	}, nil
}

// sweep removes the identities with no call in progress and a full bucket:
// they would start again from the same state. Called with l.mu held.
func (l *CallLimiter) sweep(now time.Time) {
	for key, b := range l.identities {
		refilled := l.perMinute == 0 || b.tokens+now.Sub(b.updated).Minutes()*float64(l.perMinute) >= l.burst
		if b.active == 0 && refilled {
			delete(l.identities, key)
		}
	}
}
