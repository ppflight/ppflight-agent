//go:build linux

package agent

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ppflight/ppflight-agent/internal/collector"
	"github.com/ppflight/ppflight-agent/internal/config"
	"github.com/ppflight/ppflight-agent/internal/lifecycle"
	"github.com/ppflight/ppflight-agent/internal/observation"
	"github.com/ppflight/ppflight-agent/internal/pve"
	"github.com/ppflight/ppflight-agent/internal/sdnotify"
)

func TestSystemdReadyIsSentOnlyAfterHealthListenerIsReachable(t *testing.T) {
	notifyDirectory, err := os.MkdirTemp("", "ppflight-ha-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(notifyDirectory)
	notifySocket := filepath.Join(notifyDirectory, "notify.sock")
	notifications, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifySocket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer notifications.Close()
	if err := notifications.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOTIFY_SOCKET", notifySocket)
	withoutEnvironment(t, "WATCHDOG_USEC")
	withoutEnvironment(t, "WATCHDOG_PID")

	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	healthAddress := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg := parseHAConfig(t, root, healthAddress, false)
	app, err := New(cfg, config.Secrets{}, "test", discardedLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- app.Run(ctx, false) }()

	if got := readSystemdNotification(t, notifications); got != "READY=1" {
		cancel()
		t.Fatalf("first notification=%q want READY=1", got)
	}
	response, err := http.Get("http://" + healthAddress + "/healthz")
	if err != nil {
		cancel()
		t.Fatalf("health listener was not reachable after READY: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "ok\n" {
		cancel()
		t.Fatalf("health response status=%d body=%q err=%v", response.StatusCode, body, readErr)
	}

	cancel()
	if got := readSystemdNotification(t, notifications); got != "STOPPING=1" {
		t.Fatalf("shutdown notification=%q want STOPPING=1", got)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("graceful agent stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop after context cancellation")
	}
}

func TestSystemdWatchdogFailureLeavesLifecycleRunningForNextRestart(t *testing.T) {
	notifyDirectory, err := os.MkdirTemp("", "ppflight-watchdog-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(notifyDirectory)
	notifySocket := filepath.Join(notifyDirectory, "notify.sock")
	notifications, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifySocket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer notifications.Close()
	t.Setenv("NOTIFY_SOCKET", notifySocket)
	t.Setenv("WATCHDOG_USEC", "1000000")
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))

	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	healthAddress := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg := parseHAConfig(t, root, healthAddress, false)
	cfg.Collection.SampleInterval = config.Duration{Duration: time.Second}
	app, err := New(cfg, config.Secrets{}, "test", discardedLogger())
	if err != nil {
		t.Fatal(err)
	}
	stuck := &blockedCollectionSource{started: make(chan struct{})}
	app.source = stuck
	result := make(chan error, 1)
	go func() { result <- app.Run(context.Background(), false) }()
	select {
	case <-stuck.started:
	case <-time.After(3 * time.Second):
		t.Fatal("collection did not start")
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "collection loop stopped making progress") {
			t.Fatalf("watchdog result=%v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("watchdog did not terminate the stuck agent")
	}

	next, err := lifecycle.Begin(filepath.Join(RuntimeStateDirectory(filepath.Join(root, "state")), "lifecycle-state.json"), secondLifecycleBootID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	website, monitoring := next.Pending(lifecycle.DomainWebsite), next.Pending(lifecycle.DomainMonitor)
	if len(website) != 1 || len(monitoring) != 1 || website[0].EventID != monitoring[0].EventID {
		t.Fatalf("watchdog failure was not retained for both domains: website=%#v monitoring=%#v", website, monitoring)
	}
}

func TestSystemdWatchdogDeadlineResetsOnInnerCollectionProgress(t *testing.T) {
	notifyDirectory, err := os.MkdirTemp("", "ppflight-progress-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(notifyDirectory)
	notifySocket := filepath.Join(notifyDirectory, "notify.sock")
	notifications, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifySocket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer notifications.Close()
	t.Setenv("NOTIFY_SOCKET", notifySocket)
	t.Setenv("WATCHDOG_USEC", "1000000")
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))

	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	healthAddress := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg := parseHAConfig(t, root, healthAddress, false)
	cfg.Collection.SampleInterval = config.Duration{Duration: time.Second}
	app, err := New(cfg, config.Secrets{}, "test", discardedLogger())
	if err != nil {
		t.Fatal(err)
	}
	progressing := &progressingCollectionSource{started: make(chan struct{})}
	progressing.SetProgressReporter(app.markCollectionProgress)
	app.source = progressing
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- app.Run(ctx, false) }()
	select {
	case <-progressing.started:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("collection did not start")
	}
	select {
	case err := <-result:
		cancel()
		t.Fatalf("watchdog stopped a collection that was still progressing: %v", err)
	case <-time.After(1400 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("graceful stop after progress: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not stop after context cancellation")
	}
}

func TestExpiredCollectionNeverSendsAnotherWatchdogHeartbeat(t *testing.T) {
	notifyDirectory, err := os.MkdirTemp("", "ppflight-expired-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(notifyDirectory)
	notifySocket := filepath.Join(notifyDirectory, "notify.sock")
	notifications, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifySocket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer notifications.Close()
	t.Setenv("NOTIFY_SOCKET", notifySocket)
	t.Setenv("WATCHDOG_USEC", "1000000")
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	notifier, err := sdnotify.New()
	if err != nil {
		t.Fatal(err)
	}

	app := &App{
		cfg:                      config.Config{Collection: config.CollectionConfig{SampleInterval: config.Duration{Duration: time.Second}}},
		collectionProgressSignal: make(chan struct{}, 1),
	}
	app.collectionActive.Store(true)
	// Deadline and heartbeat become due at approximately the same instant.
	// Whichever select branch wins must reject the expired progress before it
	// can send WATCHDOG=1 and extend systemd's kill window.
	startedAt := time.Now().UTC()
	app.collectionProgressAt.Store(startedAt.Add(-500 * time.Millisecond).UnixNano())
	failures := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go app.watchdogLoop(ctx, notifier, startedAt, failures)
	select {
	case err := <-failures:
		if err == nil || !strings.Contains(err.Error(), "stopped making progress") {
			t.Fatalf("watchdog failure=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expired collection did not stop the watchdog loop")
	}
	if err := notifications.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if count, _, err := notifications.ReadFromUnix(buffer); err == nil {
		t.Fatalf("expired collection sent notification %q", string(buffer[:count]))
	} else if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatalf("read notification: %v", err)
	}
}

func readSystemdNotification(t *testing.T, listener *net.UnixConn) string {
	t.Helper()
	buffer := make([]byte, 64)
	count, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return string(buffer[:count])
}

func withoutEnvironment(t *testing.T, key string) {
	t.Helper()
	value, found := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if found {
			_ = os.Setenv(key, value)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

type blockedCollectionSource struct {
	started chan struct{}
}

func (s *blockedCollectionSource) Collect(ctx context.Context, _ time.Time, _ collector.Due) (observation.Snapshot, error) {
	select {
	case <-s.started:
	default:
		close(s.started)
	}
	<-ctx.Done()
	return observation.Snapshot{}, ctx.Err()
}

func (*blockedCollectionSource) PVEClient() *pve.Client { return nil }

type progressingCollectionSource struct {
	started  chan struct{}
	reporter func()
}

func (s *progressingCollectionSource) SetProgressReporter(reporter func()) { s.reporter = reporter }

func (s *progressingCollectionSource) Collect(ctx context.Context, _ time.Time, _ collector.Due) (observation.Snapshot, error) {
	select {
	case <-s.started:
	default:
		close(s.started)
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return observation.Snapshot{}, ctx.Err()
		case <-ticker.C:
			if s.reporter != nil {
				s.reporter()
			}
		}
	}
}

func (*progressingCollectionSource) PVEClient() *pve.Client { return nil }
