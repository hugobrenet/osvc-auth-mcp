package mcpauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	// exchangeCacheLifetime bounds the reuse of an exchanged token, whatever
	// its expiry: a burst of tool calls reuses it, a claim change in the SSO
	// applies within a minute.
	exchangeCacheLifetime = time.Minute
	// exchangeCacheMargin keeps a token that expires soon from being reused:
	// it must outlive the tool call and the clock skew of the target.
	exchangeCacheMargin = 30 * time.Second
	// exchangeFailureMemory is how long a failed exchange is returned again
	// without contacting the SSO: a client that loops on a refused token
	// makes at most one SSO request per period.
	exchangeFailureMemory = 5 * time.Second
	// exchangeCacheEntries bounds the memory of the cache. When it is full of
	// live entries, new exchanges are not cached.
	exchangeCacheEntries = 1024
)

// exchanged is the checked result of one token exchange.
type exchanged struct {
	token    string
	subject  string
	deadline time.Time
}

// exchangeCache keeps the exchanged tokens in the memory of the process
// only, never on disk, for at most exchangeCacheLifetime. Entries are keyed
// by a hash of the MCP token and the target, never by the MCP token itself.
// Concurrent calls for the same key share one exchange, and a failed
// exchange is returned again for exchangeFailureMemory.
type exchangeCache struct {
	mu      sync.Mutex
	now     func() time.Time
	max     int
	entries map[string]*cachedExchange
}

type cachedExchange struct {
	pending bool
	done    chan struct{} // closed when the exchange ends
	result  exchanged
	err     error
	// retry tells waiters that the exchange ended with the context of the
	// caller that ran it, which says nothing about the SSO.
	retry bool
	until time.Time // reuse limit of the result or of the error
}

func newExchangeCache() *exchangeCache {
	return &exchangeCache{now: time.Now, max: exchangeCacheEntries, entries: make(map[string]*cachedExchange)}
}

// exchangeCacheKey hashes the fields, which contain no NUL byte: the MCP
// token is a compact JWT, the others are valid claim text.
func exchangeCacheKey(subject, profile, audience, target string) string {
	sum := sha256.Sum256([]byte(subject + "\x00" + profile + "\x00" + audience + "\x00" + target))
	return hex.EncodeToString(sum[:])
}

// get returns the cached exchange or failure of key while it may be reused,
// waits for the exchange of key in progress, or runs exchange.
func (c *exchangeCache) get(ctx context.Context, key string, exchange func(context.Context) (exchanged, error)) (exchanged, error) {
	for {
		c.mu.Lock()
		e := c.entries[key]
		if e != nil && !e.pending && c.now().Before(e.until) {
			c.mu.Unlock()
			if e.err != nil {
				return exchanged{}, e.err
			}
			return e.result, nil
		}
		if e != nil && e.pending {
			c.mu.Unlock()
			select {
			case <-e.done:
			case <-ctx.Done():
				return exchanged{}, errors.New("token exchange request failed or timed out")
			}
			if e.retry {
				continue
			}
			if e.err != nil {
				return exchanged{}, e.err
			}
			if !c.now().Before(e.result.deadline) {
				continue
			}
			return e.result, nil
		}
		e = &cachedExchange{pending: true, done: make(chan struct{})}
		cached := c.reserve(key, e)
		c.mu.Unlock()

		result, err := exchange(ctx)

		c.mu.Lock()
		e.pending, e.result, e.err, e.retry = false, result, err, err != nil && ctx.Err() != nil
		if err == nil {
			e.until = result.deadline.Add(-exchangeCacheMargin)
			if limit := c.now().Add(exchangeCacheLifetime); limit.Before(e.until) {
				e.until = limit
			}
		} else if !e.retry {
			e.until = c.now().Add(exchangeFailureMemory)
		}
		if cached && (e.retry || !c.now().Before(e.until)) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		close(e.done)
		return result, err
	}
}

// reserve records the pending exchange e of key, unless the cache is full of
// live entries. Called with c.mu held.
func (c *exchangeCache) reserve(key string, e *cachedExchange) bool {
	if _, replace := c.entries[key]; !replace && len(c.entries) >= c.max {
		now := c.now()
		for k, old := range c.entries {
			if !old.pending && !now.Before(old.until) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.max {
			return false
		}
	}
	c.entries[key] = e
	return true
}

// forget removes the cached exchange of key if it still holds token, so that
// a newer exchange is never removed by a late refusal of an older token.
func (c *exchangeCache) forget(key, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[key]; e != nil && !e.pending && e.result.token == token {
		delete(c.entries, key)
	}
}
