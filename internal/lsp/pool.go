package lsp

// pool.go is the bounded set of live roots: LRU by last use, with an idle TTL.
//
// There is no invalidation here, and that is the point. A root is keyed by a
// resolved commit, so it names one tree for all time — nothing can make a warm
// root wrong. A push is a different key, and the only reason anything is ever
// discarded is that memory is finite.

import (
	"context"
	"sync"
	"time"
)

// key names one root. org is FIRST and is the caller's tenant: two tenants
// naming the same repo at the same revision get two keys, two directories and
// two servers, so a warm server can never be handed across the boundary.
type key struct{ org, repo, rev string }

type pool struct {
	mu   sync.Mutex
	live map[key]*Root
	most int
	ttl  time.Duration
	// now is a field so the eviction policy can be tested as the arithmetic it
	// is, with no toolchain and no wall clock.
	now func() time.Time
}

func newPool() *pool {
	return &pool{live: map[key]*Root{}, most: warmMost, ttl: warmTTL, now: time.Now}
}

// hold returns the root for k if one is live, waiting for a build already in
// flight. It never starts one: a caller that gets false is told to send a tree.
//
// A held root is BUSY until the caller releases it, and a busy root is never
// evicted — so a query cannot have its servers killed and its tree removed while
// it is running. Every path out of here that does not return a root releases it.
func (p *pool) hold(ctx context.Context, k key) (*Root, bool, error) {
	p.mu.Lock()
	p.sweep()
	r, ok := p.live[k]
	if ok {
		r.used = p.now()
		r.busy.Add(1)
	}
	p.mu.Unlock()
	if !ok {
		return nil, false, nil
	}
	select {
	case <-r.ready:
	case <-ctx.Done():
		r.release()
		return nil, true, ctx.Err()
	}
	if r.err != nil {
		r.release()
		return nil, true, r.err
	}
	return r, true, nil
}

// claim reserves k for a build. mine reports that this caller must do it; a
// second caller for the same key gets mine=false and the pending root to wait on,
// so two requests never build competing trees into one directory.
func (p *pool) claim(k key) (r *Root, mine bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweep()
	if r, ok := p.live[k]; ok {
		r.used = p.now()
		return r, false
	}
	r = &Root{key: k, used: p.now(), ready: make(chan struct{})}
	p.live[k] = r
	p.evict()
	return r, true
}

// settle publishes a claimed build's outcome and releases everyone waiting. A
// failed build is removed, so the next request retries rather than inheriting a
// permanent error.
func (p *pool) settle(r *Root, built *Root, err error) {
	if err != nil {
		r.err = err
		close(r.ready)
		p.mu.Lock()
		if p.live[r.key] == r {
			delete(p.live, r.key)
		}
		p.mu.Unlock()
		return
	}
	r.dir, r.dirs, r.langs = built.dir, built.dirs, built.langs
	close(r.ready)
}

// holds reports whether any revision of one repo is live for one org. It is the
// whole admission rule for a warm request: pre-warming a NEW revision is free
// work, and free work is only offered where the caller has already paid for a
// cold start on the same repository.
func (p *pool) holds(org, repo string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k := range p.live {
		if k.org == org && k.repo == repo {
			return true
		}
	}
	return false
}

// sweep drops roots idle past the TTL. The caller holds mu.
func (p *pool) sweep() {
	cut := p.now().Add(-p.ttl)
	for k, r := range p.live {
		if r.settled() && r.busy.Load() == 0 && r.used.Before(cut) {
			delete(p.live, k)
			go r.close()
		}
	}
}

// evict enforces the ceiling by dropping least-recently-used roots. The caller
// holds mu.
func (p *pool) evict() {
	for len(p.live) > p.most {
		var oldest key
		var found bool
		for k, r := range p.live {
			// Neither a root being built (nothing to close, somebody waiting)
			// nor one being queried (killing it would fail that query) is a
			// candidate. A burst can therefore briefly exceed the ceiling, which
			// is the right trade against evicting what somebody is using.
			if !r.settled() || r.busy.Load() > 0 {
				continue
			}
			if !found || r.used.Before(p.live[oldest].used) {
				oldest, found = k, true
			}
		}
		if !found {
			return
		}
		r := p.live[oldest]
		delete(p.live, oldest)
		go r.close()
	}
}

func (p *pool) closeAll() {
	p.mu.Lock()
	live := p.live
	p.live = map[key]*Root{}
	p.mu.Unlock()
	for _, r := range live {
		if r.settled() {
			r.close()
		}
	}
}

func (r *Root) settled() bool {
	select {
	case <-r.ready:
		return true
	default:
		return false
	}
}
