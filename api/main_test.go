package main

import (
	"testing"
	"time"
)

// A skewed clock costs a user precision, never their data (#16).
//
// Every rejection recorded in eighteen days of production ingest was a
// timestamp: 896 events from three machines running 306 to 604 seconds ahead of
// the server, plus ten whole batches refused outright. None of it was bad data
// -- it was ordinary people whose Windows clock had drifted, and the client
// treats the 400 as permanent, so what was refused was never sent again.
//
// These tests pin the two decisions that came out of that: the window is wide
// enough for a real drifting clock, and a batch is never discarded for the one
// field that is a correlation key rather than a measurement.

func aBatch() AnalyticsBatch {
	return AnalyticsBatch{
		ClientID:   "efab15f0940a8359d7bc405c1280d82b987c0797f3759c05304c2c4e74d37847",
		AppVersion: "3.6.7",
		OS:         OsInfo{Family: "Windows", Version: "10.0", Arch: "x86_64"},
		Events:     []AnalyticsEvent{{Timestamp: time.Now().UnixMilli(), EventType: "session_start"}},
	}
}

func TestADriftingClockDoesNotCostTheBatch(t *testing.T) {
	now := time.Now().UnixMilli()

	// The exact shape seen in production: ~8 minutes ahead. This used to be a
	// 400, and the client does not retry a 400.
	batch := aBatch()
	batch.SessionStart = now + 481190
	if err := validateBatch(batch); err != nil {
		t.Fatalf("a batch from a clock 481s ahead was refused: %v", err)
	}

	// sessionStart is fixed for the life of the process, so a long-lived
	// install legitimately reports a very old one. Also must not be refused.
	batch.SessionStart = now - 90*24*60*60*1000
	if err := validateBatch(batch); err != nil {
		t.Fatalf("a batch from a 90-day-old session was refused: %v", err)
	}

	// Even an absurd value is only a silly join key, never a reason to throw
	// away the events that came with it.
	batch.SessionStart = now + 50*365*24*60*60*1000
	if err := validateBatch(batch); err != nil {
		t.Fatalf("an absurd sessionStart was allowed to discard real events: %v", err)
	}
}

func TestSkewIsStillVisibleEvenThoughItIsForgiven(t *testing.T) {
	now := time.Now().UnixMilli()

	if skew := sessionStartSkewMillis(now+481190, now); skew != 0 {
		t.Errorf("8 minutes is inside the window now, so it should not be reported as skew: got %d", skew)
	}
	// Beyond the window it is reported, so a fleet of broken clocks does not
	// become invisible just because it stopped being fatal.
	if skew := sessionStartSkewMillis(now+3*60*60*1000, now); skew <= 0 {
		t.Errorf("3 hours ahead should be reported as skew, got %d", skew)
	}
}

func TestTheBatchIsStillRefusedForThingsThatAreActuallyWrong(t *testing.T) {
	// Widening one window must not have opened the others.
	for _, c := range []struct {
		name  string
		spoil func(*AnalyticsBatch)
	}{
		{"no events", func(b *AnalyticsBatch) { b.Events = nil }},
		{"client id", func(b *AnalyticsBatch) { b.ClientID = "nope" }},
		{"app version", func(b *AnalyticsBatch) { b.AppVersion = "development" }},
		{"os family", func(b *AnalyticsBatch) { b.OS.Family = "Amiga" }},
		{"os arch", func(b *AnalyticsBatch) { b.OS.Arch = "m68k" }},
	} {
		batch := aBatch()
		c.spoil(&batch)
		if err := validateBatch(batch); err == nil {
			t.Errorf("a batch with a bad %s was accepted", c.name)
		}
	}
}

func TestAnEventIsJudgedOnItsOwnTimestamp(t *testing.T) {
	// Seeded because the allowlist is loaded from features.json at boot, and a
	// nil map makes every name unknown -- which would mask what this is testing.
	knownFeatures = map[string]bool{"file_new": true}
	defer func() { knownFeatures = nil }()

	now := time.Now().UnixMilli()
	ok := AnalyticsEvent{EventType: "feature_used", FeatureName: "file_new"}

	for _, c := range []struct {
		name     string
		offset   int64
		storable bool
	}{
		{"now", 0, true},
		{"ten minutes ahead, which production actually sends", 10 * 60 * 1000, true},
		{"fifty-nine minutes ahead, just inside", 59 * 60 * 1000, true},
		{"three hours ahead, a clock that is wrong not drifting", 3 * 60 * 60 * 1000, false},
		{"six days old, a batch that waited", -6 * 24 * 60 * 60 * 1000, true},
		{"eight days old, past the age bound", -8 * 24 * 60 * 60 * 1000, false},
	} {
		event := ok
		event.Timestamp = now + c.offset
		reason := analyticsEventRejectReason(event, now)
		if c.storable && reason != "" {
			t.Errorf("%s should be stored, rejected as %q", c.name, reason)
		}
		if !c.storable && reason == "" {
			t.Errorf("%s should be rejected, was accepted", c.name)
		}
	}
}

func TestAnUnknownFeatureNameIsStillRefusedPerEvent(t *testing.T) {
	// The allowlist is the one thing that must stay fail-closed: it is what
	// keeps free text out of the dataset. Loaded from features.json at boot, so
	// seeded directly here.
	knownFeatures = map[string]bool{"file_new": true}
	defer func() { knownFeatures = nil }()

	now := time.Now().UnixMilli()

	if reason := analyticsEventRejectReason(
		AnalyticsEvent{Timestamp: now, EventType: "feature_used", FeatureName: "file_new"}, now); reason != "" {
		t.Errorf("an allow-listed feature was refused: %s", reason)
	}
	if reason := analyticsEventRejectReason(
		AnalyticsEvent{Timestamp: now, EventType: "feature_used", FeatureName: "whatever_i_like"}, now); reason == "" {
		t.Error("an unknown feature name was accepted")
	}
	if reason := analyticsEventRejectReason(
		AnalyticsEvent{Timestamp: now, EventType: "feature_used"}, now); reason == "" {
		t.Error("a feature_used event with no feature name was accepted")
	}
	if reason := analyticsEventRejectReason(
		AnalyticsEvent{Timestamp: now, EventType: "whatever"}, now); reason == "" {
		t.Error("an unknown event type was accepted")
	}
}
