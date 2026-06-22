package checker

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"xray-checker/models"
)

func makeTestProxies(count int) []*models.ProxyConfig {
	proxies := make([]*models.ProxyConfig, count)
	for i := range proxies {
		proxies[i] = &models.ProxyConfig{Name: fmt.Sprintf("proxy-%d", i)}
	}
	return proxies
}

func updateMax(current int64, max *int64) {
	for {
		old := atomic.LoadInt64(max)
		if current <= old || atomic.CompareAndSwapInt64(max, old, current) {
			return
		}
	}
}

func TestRunProxyChecksUnlimitedStartsAllChecks(t *testing.T) {
	proxies := makeTestProxies(5)
	entered := make(chan struct{}, len(proxies))
	release := make(chan struct{})
	done := make(chan struct{})
	var active int64
	var maxActive int64

	go func() {
		runProxyChecks(proxies, 0, func(*models.ProxyConfig) {
			current := atomic.AddInt64(&active, 1)
			updateMax(current, &maxActive)
			entered <- struct{}{}
			<-release
			atomic.AddInt64(&active, -1)
		})
		close(done)
	}()

	for range proxies {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for unlimited checks to start")
		}
	}

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for unlimited checks to finish")
	}

	if maxActive != int64(len(proxies)) {
		t.Fatalf("expected %d concurrent checks, got %d", len(proxies), maxActive)
	}
}

func TestRunProxyChecksLimitsConcurrency(t *testing.T) {
	proxies := makeTestProxies(10)
	const concurrency = 4
	entered := make(chan struct{}, len(proxies))
	release := make(chan struct{})
	done := make(chan struct{})
	var active int64
	var maxActive int64

	go func() {
		runProxyChecks(proxies, concurrency, func(*models.ProxyConfig) {
			current := atomic.AddInt64(&active, 1)
			updateMax(current, &maxActive)
			entered <- struct{}{}
			<-release
			atomic.AddInt64(&active, -1)
		})
		close(done)
	}()

	for i := 0; i < concurrency; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for limited checks to start")
		}
	}

	select {
	case <-entered:
		t.Fatal("started more checks than the configured concurrency limit")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for limited checks to finish")
	}

	if maxActive != concurrency {
		t.Fatalf("expected %d concurrent checks, got %d", concurrency, maxActive)
	}
}

func TestRunProxyChecksSequential(t *testing.T) {
	proxies := makeTestProxies(5)
	var active int64
	var maxActive int64
	var checks int64

	runProxyChecks(proxies, 1, func(*models.ProxyConfig) {
		current := atomic.AddInt64(&active, 1)
		updateMax(current, &maxActive)
		atomic.AddInt64(&checks, 1)
		time.Sleep(time.Millisecond)
		atomic.AddInt64(&active, -1)
	})

	if checks != int64(len(proxies)) {
		t.Fatalf("expected %d checks, got %d", len(proxies), checks)
	}
	if maxActive != 1 {
		t.Fatalf("expected sequential checks, got %d concurrent checks", maxActive)
	}
}
