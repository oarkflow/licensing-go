package licensing

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type TamperDetector struct {
	mu        sync.Mutex
	enabled   bool
	checkedAt time.Time
	interval  time.Duration
	stopCh    chan struct{}
	failures  []TamperFailure
}

type TamperFailure struct {
	Type      string    `json:"type"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}

func NewTamperDetector(interval time.Duration) *TamperDetector {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &TamperDetector{
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (td *TamperDetector) Start() {
	td.mu.Lock()
	if td.enabled {
		td.mu.Unlock()
		return
	}
	td.enabled = true
	td.mu.Unlock()

	go func() {
		ticker := time.NewTicker(td.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				td.runChecks()
			case <-td.stopCh:
				return
			}
		}
	}()
}

func (td *TamperDetector) Stop() {
	td.mu.Lock()
	defer td.mu.Unlock()
	if td.enabled {
		close(td.stopCh)
		td.enabled = false
	}
}

func (td *TamperDetector) runChecks() {
	td.mu.Lock()
	td.checkedAt = time.Now()
	td.mu.Unlock()

	checkDebugger()
	checkPermissions()
	checkEnvironment()
}

func (td *TamperDetector) Failures() []TamperFailure {
	td.mu.Lock()
	defer td.mu.Unlock()
	out := make([]TamperFailure, len(td.failures))
	copy(out, td.failures)
	return out
}

func (td *TamperDetector) recordFailure(typ, details string) {
	td.mu.Lock()
	defer td.mu.Unlock()
	td.failures = append(td.failures, TamperFailure{
		Type:      typ,
		Details:   details,
		Timestamp: time.Now(),
	})
}

func checkDebugger() {
	if runtime.GOOS == "linux" {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if !isNumeric(name) {
				continue
			}
			statusPath := filepath.Join("/proc", name, "status")
			data, err := os.ReadFile(filepath.Clean(statusPath))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "TracerPid:") {
					pid := strings.TrimSpace(line[10:])
					if pid != "" && pid != "0" {
						_ = pid
					}
				}
			}
		}
	}
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func checkPermissions() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	info, err := os.Stat(exe)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0002 != 0 {
		_ = info.Mode()
	}
}

func checkEnvironment() {
	suspicious := []string{
		"LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES",
		"__GLIBC_",
	}
	for _, key := range os.Environ() {
		for _, prefix := range suspicious {
			if strings.HasPrefix(key, prefix) {
				_ = key
			}
		}
	}
}

type SecurityMetrics struct {
	mu                sync.Mutex
	totalValidations  int64
	failedValidations int64
	tamperFailures    int
	lastCheckAt       time.Time
	debuggerDetected  bool
}

func NewSecurityMetrics() *SecurityMetrics {
	return &SecurityMetrics{}
}

func (sm *SecurityMetrics) RecordValidation(success bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.totalValidations++
	if !success {
		sm.failedValidations++
	}
}

func (sm *SecurityMetrics) RecordTamperCheck(passed bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.lastCheckAt = time.Now()
	if !passed {
		sm.tamperFailures++
	}
}

func (sm *SecurityMetrics) SetDebuggerDetected() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.debuggerDetected = true
}

func (sm *SecurityMetrics) Snapshot() SecurityMetricsSnapshot {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return SecurityMetricsSnapshot{
		TotalValidations:  sm.totalValidations,
		FailedValidations: sm.failedValidations,
		TamperFailures:    sm.tamperFailures,
		LastCheckAt:       sm.lastCheckAt,
		DebuggerDetected:  sm.debuggerDetected,
	}
}

type SecurityMetricsSnapshot struct {
	TotalValidations  int64     `json:"total_validations"`
	FailedValidations int64     `json:"failed_validations"`
	TamperFailures    int       `json:"tamper_failures"`
	LastCheckAt       time.Time `json:"last_check_at"`
	DebuggerDetected  bool      `json:"debugger_detected"`
}
