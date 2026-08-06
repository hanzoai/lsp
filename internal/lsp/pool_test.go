package lsp

// pool_test.go tests the eviction policy as the arithmetic it is — no toolchain,
// no processes, no wall clock. `now` is a field for exactly this reason.

import (
	"context"
	"testing"
	"time"
)

// warm inserts a finished root under k, last used at the given time.
func warm(p *pool, k key, used time.Time) *Root {
	r := &Root{key: k, used: used, ready: make(chan struct{}), langs: map[string]*live{}}
	close(r.ready)
	p.live[k] = r
	return r
}

func TestIdleRootsAreSwept(t *testing.T) {
	clock := time.Unix(1_000_000, 0)
	p := newPool()
	p.now = func() time.Time { return clock }

	fresh := key{"acme", "app", sha(1)}
	stale := key{"acme", "app", sha(2)}
	warm(p, fresh, clock.Add(-time.Minute))
	warm(p, stale, clock.Add(-2*warmTTL))

	p.mu.Lock()
	p.sweep()
	p.mu.Unlock()

	if _, ok := p.live[stale]; ok {
		t.Error("a root idle past the TTL was kept")
	}
	if _, ok := p.live[fresh]; !ok {
		t.Error("a root used a minute ago was swept")
	}
}

func TestEvictionTakesTheLeastRecentlyUsed(t *testing.T) {
	clock := time.Unix(1_000_000, 0)
	p := newPool()
	p.now = func() time.Time { return clock }

	// Fill to the ceiling, oldest first.
	var oldest key
	for i := 0; i < warmMost; i++ {
		k := key{"acme", "app", sha(byte(i))}
		if i == 0 {
			oldest = k
		}
		warm(p, k, clock.Add(-time.Duration(warmMost-i)*time.Minute))
	}
	// One more claim pushes past the ceiling.
	if _, mine := p.claim(key{"acme", "app", sha(90)}); !mine {
		t.Fatal("a new key must be ours to build")
	}
	if _, ok := p.live[oldest]; ok {
		t.Error("eviction did not take the least recently used root")
	}
	if len(p.live) > warmMost {
		t.Errorf("live = %d, want at most %d", len(p.live), warmMost)
	}
}

// A root still being built is never evicted: it has no server to close and a
// request is already waiting on it.
func TestPendingRootsSurviveEviction(t *testing.T) {
	clock := time.Unix(1_000_000, 0)
	p := newPool()
	p.now = func() time.Time { return clock }
	p.most = 1

	pending, mine := p.claim(key{"acme", "app", sha(1)})
	if !mine {
		t.Fatal("first claim must be ours")
	}
	if _, mine := p.claim(key{"acme", "app", sha(2)}); !mine {
		t.Fatal("second claim must be ours")
	}
	if _, ok := p.live[pending.key]; !ok {
		t.Fatal("a root being built was evicted out from under its waiter")
	}
}

// Two requests for the same key must not build competing trees into one
// directory: the second waits on the first.
func TestSecondClaimWaitsRatherThanBuilding(t *testing.T) {
	p := newPool()
	k := key{"acme", "app", sha(1)}

	first, mine := p.claim(k)
	if !mine {
		t.Fatal("first claim must be ours")
	}
	second, mine := p.claim(k)
	if mine {
		t.Fatal("second claim must NOT build — it would race the first into the same directory")
	}
	if first != second {
		t.Fatal("the second caller must wait on the SAME root")
	}
}

// A failed build is removed, so the next request retries rather than inheriting a
// permanent error.
func TestFailedBuildIsNotCached(t *testing.T) {
	p := newPool()
	k := key{"acme", "app", sha(1)}

	r, _ := p.claim(k)
	p.settle(r, nil, context.DeadlineExceeded)

	if _, ok := p.live[k]; ok {
		t.Fatal("a failed build stayed in the pool — every later request would inherit it")
	}
	if _, mine := p.claim(k); !mine {
		t.Fatal("the next caller must get to try again")
	}
}

// holds is the warm door's whole admission rule, and it is scoped by ORG: another
// tenant's live root for the same repo name must not admit yours.
func TestHoldsIsScopedByOrg(t *testing.T) {
	p := newPool()
	warm(p, key{"acme", "app", sha(1)}, time.Now())

	if !p.holds("acme", "app") {
		t.Error("holds must see the org's own live root")
	}
	if p.holds("other", "app") {
		t.Error("holds leaked across the tenant boundary")
	}
	if p.holds("acme", "other") {
		t.Error("holds matched the wrong repository")
	}
}

func TestHoldReportsAnAbsentRoot(t *testing.T) {
	p := newPool()
	_, held, err := p.hold(context.Background(), key{"acme", "app", sha(1)})
	if err != nil {
		t.Fatalf("hold: %v", err)
	}
	if held {
		t.Fatal("hold reported a root nobody built")
	}
}
